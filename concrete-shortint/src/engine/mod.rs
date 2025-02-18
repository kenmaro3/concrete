use crate::ServerKey;
use concrete_core::backends::fftw::private::crypto::bootstrap::FourierBuffers;
use concrete_core::prelude::*;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Debug;

mod client_side;
mod server_side;
mod treepbs;
mod wopbs;

thread_local! {
    static LOCAL_ENGINE: RefCell<ShortintEngine> = RefCell::new(ShortintEngine::new());
}

fn new_seeder() -> Box<dyn Seeder> {
    let seeder;
    #[cfg(target_arch = "x86")]
    {
        if RdseedSeeder::is_available() {
            seeder = Box::new(RdseedSeeder);
        } else {
            assert!(false);
            seeder = Box::new(UnixSeeder::new(0));
        }
    }
    #[cfg(not(target_arch = "x86"))]
    {
        seeder = Box::new(UnixSeeder::new(0));
    }

    seeder
}

/// Stores buffers associated to a ServerKey
struct Buffers {
    pub(crate) accumulator: GlweCiphertext64,
    pub(crate) buffer_lwe_after_ks: LweCiphertext64,
    pub(crate) fourier: FourierBuffers<u64>,
}

/// This allows to store and retrieve the `Buffers`
/// corresponding to a `ServerKey` in a `BTreeMap`
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq)]
struct KeyId {
    accumulator_dim: GlweSize,
    lwe_dim_after_pbs: usize,
    glwe_size: GlweSize,
    poly_size: PolynomialSize,
}

impl ServerKey {
    #[inline]
    fn key_id(&self) -> KeyId {
        KeyId {
            accumulator_dim: self.bootstrapping_key.glwe_dimension().to_glwe_size(),
            lwe_dim_after_pbs: self.bootstrapping_key.output_lwe_dimension().0,
            glwe_size: self.bootstrapping_key.glwe_dimension().to_glwe_size(),
            poly_size: self.bootstrapping_key.polynomial_size(),
        }
    }
}

/// Simple wrapper around `std::error::Error` to be able to
/// forward all the possible `EngineError` type from `concrete-core`
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct EngineError {
    error: Box<dyn std::error::Error>,
}

impl<T> From<T> for EngineError
where
    T: std::error::Error + 'static,
{
    fn from(error: T) -> Self {
        Self {
            error: Box::new(error),
        }
    }
}

pub(crate) type EngineResult<T> = Result<T, EngineError>;

/// ShortintEngine
///
/// This 'engine' holds the necessary engines from `concrete-core`
/// as well as the buffers that we want to keep around to save processing time.
///
/// This structs actually implements the logics into its methods.
pub(crate) struct ShortintEngine {
    pub(crate) engine: DefaultEngine,
    pub(crate) fftw_engine: FftwEngine,
    pub(crate) par_engine: DefaultParallelEngine,
    buffers: BTreeMap<KeyId, Buffers>,
}

impl ShortintEngine {
    /// Safely gives access to the `thead_local` shortint engine
    /// to call one (or many) of its method.
    #[inline]
    pub(crate) fn with_thread_local_mut<F, R>(func: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        LOCAL_ENGINE.with(|engine_cell| func(&mut engine_cell.borrow_mut()))
    }

    /// Creates a new shortint engine
    ///
    /// Creating a `ShortintEngine` should not be needed, as each
    /// rust thread gets its own `thread_local` engine created automatically,
    /// see [ShortintEngine::with_thread_local_mut]
    ///
    ///
    /// # Panics
    ///
    /// This will panic if the `CoreEngine` failed to create.
    fn new() -> Self {
        let engine = DefaultEngine::new(new_seeder()).expect("Failed to create a DefaultEngine");
        let par_engine = DefaultParallelEngine::new(new_seeder())
            .expect("Failed to create a DefaultParallelEngine");
        let fftw_engine = FftwEngine::new(()).unwrap();
        Self {
            engine,
            fftw_engine,
            par_engine,
            buffers: Default::default(),
        }
    }

    fn generate_accumulator_with_engine<F>(
        engine: &mut DefaultEngine,
        server_key: &ServerKey,
        f: F,
    ) -> EngineResult<GlweCiphertext64>
    where
        F: Fn(u64) -> u64,
    {
        // Modulus of the msg contained in the msg bits and operations buffer
        let modulus_sup = server_key.message_modulus.0 * server_key.carry_modulus.0;

        // N/(p/2) = size of each block
        let box_size = server_key.bootstrapping_key.polynomial_size().0 / modulus_sup;

        // Value of the shift we multiply our messages by
        let delta =
            (1_u64 << 63) / (server_key.message_modulus.0 * server_key.carry_modulus.0) as u64;

        // Create the accumulator
        let mut accumulator_u64 = vec![0_u64; server_key.bootstrapping_key.polynomial_size().0];

        // This accumulator extracts the carry bits
        for i in 0..modulus_sup {
            let index = i as usize * box_size;
            accumulator_u64[index..index + box_size]
                .iter_mut()
                .for_each(|a| *a = f(i as u64) * delta);
        }

        let half_box_size = box_size / 2;

        // Negate the first half_box_size coefficients
        for a_i in accumulator_u64[0..half_box_size].iter_mut() {
            *a_i = (*a_i).wrapping_neg();
        }

        // Rotate the accumulator
        accumulator_u64.rotate_left(half_box_size);

        // Everywhere
        let accumulator_plaintext = engine.create_plaintext_vector_from(&accumulator_u64)?;

        let accumulator = engine.trivially_encrypt_glwe_ciphertext(
            server_key.bootstrapping_key.glwe_dimension().to_glwe_size(),
            &accumulator_plaintext,
        )?;

        Ok(accumulator)
    }

    /// Returns the `Buffers` for the given `ServerKey`
    ///
    /// Takes care creating the buffers if they do not exists for the given key
    ///
    /// This also `&mut CoreEngine` to simply borrow checking for the caller
    /// (since returned buffers are borrowed from `self`, using the `self.engine`
    /// wouldn't be possible after calling `buffers_for_key`)
    fn buffers_for_key(
        &mut self,
        server_key: &ServerKey,
    ) -> (&mut Buffers, &mut DefaultEngine, &mut FftwEngine) {
        let key = server_key.key_id();
        // To make borrow checker happy
        let engine = &mut self.engine;
        let buffers_map = &mut self.buffers;
        let buffers = buffers_map.entry(key).or_insert_with(|| {
            let accumulator = Self::generate_accumulator_with_engine(engine, server_key, |n| {
                n % server_key.message_modulus.0 as u64
            })
            .unwrap();

            // Allocate the buffer for the output of the PBS
            let zero_plaintext = engine.create_plaintext_from(&0_u64).unwrap();
            let buffer_lwe_after_pbs = engine
                .trivially_encrypt_lwe_ciphertext(
                    server_key
                        .key_switching_key
                        .output_lwe_dimension()
                        .to_lwe_size(),
                    &zero_plaintext,
                )
                .unwrap();

            let buffer_fourier: FourierBuffers<u64> = FourierBuffers::new(
                server_key.bootstrapping_key.polynomial_size(),
                server_key.bootstrapping_key.glwe_dimension().to_glwe_size(),
            );

            Buffers {
                accumulator,
                buffer_lwe_after_ks: buffer_lwe_after_pbs,
                fourier: buffer_fourier,
            }
        });

        (buffers, engine, &mut self.fftw_engine)
    }
}
