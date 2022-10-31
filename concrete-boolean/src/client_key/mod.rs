//! The secret key of the client.
//!
//! This module implements the generation of the client' secret keys, together with the
//! encryption and decryption methods.

use crate::ciphertext::Ciphertext;
use crate::parameters::BooleanParameters;
use crate::{PLAINTEXT_FALSE, PLAINTEXT_TRUE};
use concrete_commons::key_kinds::BinaryKeyKind;
use concrete_core::crypto::encoding::Plaintext;
use concrete_core::crypto::lwe::LweCiphertext;
use concrete_core::crypto::secret::generators::{EncryptionRandomGenerator, SecretRandomGenerator};
use concrete_core::crypto::secret::{GlweSecretKey, LweSecretKey};
use serde::{Deserialize, Serialize};
use crate::parameters::DEBUG_PARAMETERS;

/// A structure containing the client key, which must be kept secret.
///
/// In more details, it contains:
/// * `lwe_secret_key` - an LWE secret key, used to encrypt the inputs and decrypt the outputs.
/// This secret key is also used in the generation of bootstrapping and key switching keys.
/// * `glwe_secret_key` - a GLWE secret key, used to generate the bootstrapping keys and key
/// switching keys.
/// * `parameters` - the cryptographic parameter set.
#[derive(Serialize, Clone, Deserialize, PartialEq, Debug)]
pub struct ClientKey {
    pub(crate) lwe_secret_key: LweSecretKey<BinaryKeyKind, Vec<u32>>,
    pub(crate) glwe_secret_key: GlweSecretKey<BinaryKeyKind, Vec<u32>>,
    pub parameters: BooleanParameters,
}

impl ClientKey {
    /// Encrypts a Boolean message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_boolean::gen_keys;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys();
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(true);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(true, dec);
    /// ```
    pub fn encrypt(&self, message: bool) -> Ciphertext {
        // encode the boolean message
        let plain: Plaintext<u32> = if message {
            Plaintext(PLAINTEXT_TRUE)
        } else {
            Plaintext(PLAINTEXT_FALSE)
        };

        // instantiate an encryption random generator
        let mut encryption_generator = EncryptionRandomGenerator::new(None);

        // allocate the ciphertext
        let mut ct = LweCiphertext::allocate(0_u32, self.parameters.lwe_dimension.to_lwe_size());

        // encrypt the encoded boolean
        self.lwe_secret_key.encrypt_lwe(
            &mut ct,
            &plain,
            self.parameters.lwe_modular_std_dev,
            &mut encryption_generator,
        );

        Ciphertext(ct)
    }

    /// Decrypts a ciphertext encrypting a Boolean message using the client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_boolean::gen_keys;
    ///
    /// // Generate the client key and the server key:
    /// let (cks, sks) = gen_keys();
    ///
    /// // Encryption of one message:
    /// let ct = cks.encrypt(true);
    ///
    /// // Decryption:
    /// let dec = cks.decrypt(&ct);
    /// assert_eq!(true, dec);
    /// ```
    pub fn decrypt(&self, ct: &Ciphertext) -> bool {
        // allocation for the decryption
        let mut decrypted = Plaintext(0_u32);

        // decryption
        self.lwe_secret_key.decrypt_lwe(&mut decrypted, &ct.0);

        // return
        decrypted.0 < (1 << 31)
    }

    /// Allocates and generates a client key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use concrete_boolean::client_key::ClientKey;
    /// use concrete_boolean::parameters::DEFAULT_PARAMETERS;
    ///
    /// // Generate the client key:
    /// let cks = ClientKey::new(&DEFAULT_PARAMETERS);
    /// ```
    pub fn new(parameter_set: &BooleanParameters) -> ClientKey {
        // instantiate a secret random generator
        let mut secret_generator = SecretRandomGenerator::new(None);

        // generate the lwe secret key
        let lwe_secret_key: LweSecretKey<BinaryKeyKind, Vec<u32>> =
            LweSecretKey::generate_binary(parameter_set.lwe_dimension, &mut secret_generator);

        // generate the rlwe secret key
        let glwe_secret_key: GlweSecretKey<BinaryKeyKind, Vec<u32>> =
            GlweSecretKey::generate_binary(
                parameter_set.glwe_dimension,
                parameter_set.polynomial_size,
                &mut secret_generator,
            );

        // pack the keys in the client key set
        let cks: ClientKey = ClientKey {
            lwe_secret_key,
            glwe_secret_key,
            parameters: (*parameter_set).clone(),
        };
        cks
    }


    pub fn decrypt_8bit(&self, x: [Ciphertext; 8]) -> [bool; 8]{
        let mut res = [false; 8];
        for i in 0..8{
            res[i] = self.decrypt(&x[i]);
        };
        res
    }

    pub fn decode(&self, x: [bool; 8]) -> u8{
        let mut res: u8 = 0;
        for i in 0..8{
            if x[i]{
                res += 1 << i;
            }
            else{
            }
        };
        res

    }

    pub fn decrypt_and_decode_8bit(&self, x: &[Ciphertext; 8]) -> u8{
        let mut res = [false; 8];
        for i in 0..8{
            res[i] = self.decrypt(&x[i]);
        };
        return self.decode(res);
    }

    pub fn generate_public_key(&self) -> PublicKey{
        //let tmp0 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        // let tmp1 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        // let tmp2 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        // let tmp3 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        // let tmp4 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        // let tmp5 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        // let tmp6 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        // let tmp7 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        // let mut res: [Ciphertext; 8] = [tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7];

        let tmp0 = self.zero_encrypt();


        let pub_key = PublicKey{
            key: tmp0,
            parameters: self.parameters
        };

        pub_key
    }


    pub fn zero_encrypt(&self) -> Ciphertext {

        let plain = Plaintext(0);
        // instantiate an encryption random generator
        let mut encryption_generator = EncryptionRandomGenerator::new(None);

        // allocate the ciphertext
        let mut ct = LweCiphertext::allocate(0_u32, self.parameters.lwe_dimension.to_lwe_size());

        // encrypt the encoded boolean
        self.lwe_secret_key.encrypt_lwe(
            &mut ct,
            &plain,
            self.parameters.lwe_modular_std_dev,
            &mut encryption_generator,
        );

        Ciphertext(ct)
    }

}


#[derive(Serialize, Clone, Deserialize)]
pub struct PublicKey{
    pub key: Ciphertext,
    pub parameters: BooleanParameters,
}

impl PublicKey{
    pub fn encrypt(&self, message: bool) -> Ciphertext{
        // encode the boolean message
        let plain: Plaintext<u32> = if message {
            Plaintext(PLAINTEXT_TRUE)
        } else {
            Plaintext(PLAINTEXT_FALSE)
        };

        let tmp = &mut self.key.clone();

        let (body, mask)= tmp.0.get_mut_body_and_mask();

        body.0 = body.0.wrapping_add(plain.0);

        tmp.to_owned()

    }

    pub fn encode(&self, x: u8) -> [bool; 8]{
        let mut res = [false; 8];
        let mut cnt = 0;
        let mut tmp = x;
        if x == 0{
            let res = [false; 8];
            return res;
        }
        else{
            while tmp > 0{
                if tmp % 2 == 0{
                    res[cnt] = false;
                }
                else{
                    res[cnt] = true;
                }
                tmp /= 2;
                cnt += 1;
            }
            res
        }
    }

    fn get_8_ciphers(&self) -> [Ciphertext; 8]{
        let tmp0 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        let tmp1 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        let tmp2 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        let tmp3 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        let tmp4 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        let tmp5 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        let tmp6 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        let tmp7 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
        let res: [Ciphertext; 8] = [tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7];
        res
    }

    pub fn encrypt_8bit(&self, x: [bool; 8]) -> [Ciphertext; 8]{
        let mut res = self.get_8_ciphers();
        for i in 0..8{
            res[i] = self.encrypt(x[i]);
        };
        res
    }

    pub fn encode_and_encrypt_8bit(&self, x: u8) -> [Ciphertext; 8]{
        let tmp = self.encode(x);
        let mut res = self.get_8_ciphers();
        for i in 0..8{
            res[i] = self.encrypt(tmp[i]);
        };
        res
    }

}