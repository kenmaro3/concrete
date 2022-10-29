//! Welcome the the `concrete-boolean` documentation!
//!
//! # Description
//! This library makes it possible to execute boolean gates over encrypted bits.
//! It allows to execute a boolean circuit on an untrusted server because both circuit inputs and
//! outputs are kept private.
//! Data are indeed encrypted on the client side, before being sent to the server.
//! On the server side every computation is performed on ciphertexts.
//! The server however has to know the boolean circuit to be evaluated.
//! At the end of the computation, the server returns the encryption of the result to the user.
//!
//!
//!
//! # Quick Example
//!
//! The following piece of code shows how to generate keys and run a small Boolean circuit
//! homomorphically.
//!
//! ```rust
//! extern crate concrete_boolean;
//! use concrete_boolean::gen_keys;
//!
//! // We generate a set of client/server keys, using the default parameters:
//! let (client_key, server_key) = gen_keys();
//!
//! // We use the client secret key to encrypt two messages:
//! let ct_1 = client_key.encrypt(true);
//! let ct_2 = client_key.encrypt(false);
//!
//! // We use the server public key to execute a boolean circuit:
//! // if ((NOT ct_2) NAND (ct_1 AND ct_2)) then (NOT ct_2) else (ct_1 AND ct_2)
//! let ct_3 = server_key.not(&ct_2);
//! let ct_4 = server_key.and(&ct_1, &ct_2);
//! let ct_5 = server_key.nand(&ct_3, &ct_4);
//! let ct_6 = server_key.mux(&ct_5, &ct_3, &ct_4);
//!
//! // We use the client key to decrypt the output of the circuit:
//! let output = client_key.decrypt(&ct_6);
//! assert_eq!(output, true);
//! ```

use crate::client_key::ClientKey;
use crate::ciphertext::Ciphertext;
use crate::parameters::DEFAULT_PARAMETERS;
use crate::parameters::DEBUG_PARAMETERS;
use crate::server_key::ServerKey;

use concrete_core::crypto::lwe::LweCiphertext;
use concrete_core::crypto::lwe::LweKeyswitchKey;
use concrete_commons::parameters::LweDimension;
use concrete_core::crypto::secret::generators::EncryptionRandomGenerator;



pub mod ciphertext;
pub mod client_key;
pub mod parameters;
pub mod server_key;

/// The scaling factor used for the plaintext
pub(crate) const PLAINTEXT_LOG_SCALING_FACTOR: usize = 3;

/// The plaintext associated with true: 1/8
pub(crate) const PLAINTEXT_TRUE: u32 = 1 << (32 - PLAINTEXT_LOG_SCALING_FACTOR);

/// The plaintext associated with false: -1/8
pub(crate) const PLAINTEXT_FALSE: u32 = 7 << (32 - PLAINTEXT_LOG_SCALING_FACTOR);

/// tool to generate random booleans
#[cfg(test)]
pub(crate) fn random_boolean() -> bool {
    // create a random generator
    let mut generator = concrete_core::math::random::RandomGenerator::new(None);

    // generate a bit
    let n: u32 = generator.random_uniform_binary();

    // convert it to boolean and return
    n != 0
}

/// tool to generate random integers
#[cfg(test)]
pub(crate) fn random_integer() -> u32 {
    // create a random generator
    let mut generator = concrete_core::math::random::RandomGenerator::new(None);

    // generate a bit
    generator.random_uniform()
}

/// Generate a couple of client and server keys with the default cryptographic parameters:
/// `DEFAULT_PARAMETERS`.
/// The client is the one generating both keys.
/// * the client key is used to encrypt and decrypt and has to be kept secret;
/// * the server key is used to perform homomorphic operations on the server side and it is
/// meant to be published (the client sends it to the server).
///
/// ```rust
/// use concrete_boolean::gen_keys;
/// // generate the client key and the server key:
/// let (cks, sks) = gen_keys();
/// ```
pub fn gen_keys() -> (ClientKey, ServerKey) {
    // generate the client key
    let cks = ClientKey::new(&DEFAULT_PARAMETERS);

    // generate the server key
    let sks = ServerKey::new(&cks);

    // return
    (cks, sks)
}


pub struct CipherSumAndCarry{
    s: Ciphertext,
    c: Ciphertext
}

pub struct PlainSumAndCarry{
    s: bool,
    c: bool
}

pub struct CipherSubtractAndDecrease{
    s: Ciphertext,
    d: Ciphertext
}

pub struct PlainSubtractAndDecrease{
    s: bool,
    d: bool
}


fn cipher_half_adder(x1: &Ciphertext, x2: &Ciphertext, calculation_key: &ServerKey) -> CipherSumAndCarry{
    let res_carry= calculation_key.and(x1, x2);
    let res_sum= calculation_key.xor(x1, x2);
    let res = CipherSumAndCarry{
        s: res_sum,
        c: res_carry
    };
    res
}

fn cipher_half_subtractor(x1: &Ciphertext, x2: &Ciphertext, calculation_key: &ServerKey) -> CipherSubtractAndDecrease{
    let sutbtact = calculation_key.xor(x1, x2);
    let decrease = calculation_key.and(&calculation_key.not(x1), x2);

    let res = CipherSubtractAndDecrease{
        s: sutbtact,
        d: decrease
    };
    res
}

fn plain_half_adder(x1: bool, x2: bool) -> PlainSumAndCarry{
    let carry = x1 & x2;
    let sum = x1 ^ x2;
    
    let res = PlainSumAndCarry{
        s: sum,
        c: carry
    };
    res
}

fn plain_half_subtractor(x1: bool, x2: bool) -> PlainSubtractAndDecrease{
    let subtract = x1 ^ x2;
    let decrease = !x1 & x2;

    let res = PlainSubtractAndDecrease{
        s: subtract,
        d: decrease
    };

    return res
}


pub fn cipher_full_adder(x1: &Ciphertext, x2: &Ciphertext, c:&Ciphertext, calculation_key: &ServerKey) -> CipherSumAndCarry{
    let half1 = cipher_half_adder(x1, x2, calculation_key);
    let half2 = cipher_half_adder(&half1.s, c, calculation_key);

    let res_or = calculation_key.or(&half1.c, &half2.c);

    let res = CipherSumAndCarry{
        c: res_or,
        s: half2.s
    };

    res
}


pub fn plain_full_adder(x1: bool, x2: bool, c: bool) -> PlainSumAndCarry{
    let half1= plain_half_adder(x1, x2);
    let half2= plain_half_adder(half1.s, c);

    let res_or = half1.c | half2.c;
    
    let res = PlainSumAndCarry{
        c: res_or,
        s: half2.s
    };
    res
}


pub fn cipher_full_subtractor(x1: &Ciphertext, x2: &Ciphertext, d: &Ciphertext, calculation_key: &ServerKey) -> CipherSubtractAndDecrease{
    let tmp1 = cipher_half_subtractor(x1, x2, calculation_key);
    let tmp2 = cipher_half_subtractor(&tmp1.s, d, calculation_key);
    let tmp3 = calculation_key.or(&tmp2.d, &tmp1.d);

    let res = CipherSubtractAndDecrease{
        s: tmp2.s,
        d: tmp3
    };
    res
}

pub fn plain_full_subtractor(x1: bool, x2: bool, d: bool) -> PlainSubtractAndDecrease{
    let tmp1 = plain_half_subtractor(x1, x2);
    let tmp2 = plain_half_subtractor(tmp1.s, d);
    let tmp3 = tmp2.d | tmp1.d;

    let res = PlainSubtractAndDecrease{
        s: tmp2.s,
        d: tmp3
    };
    res
}


fn get_8_ciphers() -> [Ciphertext; 8]{

    let mut tmp0 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
    let mut tmp1 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
    let mut tmp2 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
    let mut tmp3 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
    let mut tmp4 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
    let mut tmp5 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
    let mut tmp6 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
    let mut tmp7 = Ciphertext(LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size()));
    let mut res: [Ciphertext; 8] = [tmp0, tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7];
    res
}

pub fn cipher_8bit_adder(x1: &[Ciphertext; 8], x2: &[Ciphertext; 8], c_zero: &Ciphertext, calculation_key: &ServerKey) -> [Ciphertext; 8]{

    let mut res = get_8_ciphers();

    let mut res_full_adder = cipher_full_adder(&x1[0], &x2[0], c_zero, calculation_key);
    res[0] = res_full_adder.s;

    for i in 1..8{
        res_full_adder = cipher_full_adder(&x1[i], &x2[i], &res_full_adder.c, calculation_key);
        res[i] = res_full_adder.s;
    };
    res
}

pub fn cipher_8bit_subtractor(x1: &[Ciphertext; 8], x2: &[Ciphertext; 8], c_zero: &Ciphertext, calculation_key: &ServerKey) -> [Ciphertext; 8]{

    let mut res = get_8_ciphers();

    let mut res_full_subtractor= cipher_full_subtractor(&x1[0], &x2[0], c_zero, calculation_key);
    res[0] = res_full_subtractor.s;

    for i in 1..8{
        res_full_subtractor = cipher_full_subtractor(&x1[i], &x2[i], &res_full_subtractor.d, calculation_key);
        res[i] = res_full_subtractor.s;
    };
    res
}


pub fn plain_8bit_adder(x1: [bool; 8], x2: [bool; 8]) -> [bool; 8]{
    let mut res = [false; 8];
    let mut res_full_adder = plain_full_adder(x1[0], x2[0], false);
    res[0] = res_full_adder.s;


    for i in 1..8{
        res_full_adder = plain_full_adder(x1[i], x2[i], res_full_adder.c);
        res[i] = res_full_adder.s;
    };
    res
}

pub fn plain_8bit_subtractor(x1: [bool; 8], x2: [bool; 8]) -> [bool; 8]{
    let mut res = [false; 8];
    let mut res_full_subtractor = plain_full_subtractor(x1[0], x2[0], false);
    res[0] = res_full_subtractor.s;


    for i in 1..8{
        res_full_subtractor = plain_full_subtractor(x1[i], x2[i], res_full_subtractor.d);
        res[i] = res_full_subtractor.s;
    };
    res
}

pub fn decrypt_sum_and_carry(x: &CipherSumAndCarry, key: ClientKey) -> PlainSumAndCarry{
    let dec_sum= key.decrypt(&x.s);
    let dec_carry= key.decrypt(&x.c);
    let res = PlainSumAndCarry{
        s: dec_sum,
        c: dec_carry
    };
    return res
}


pub fn encode(x: u8) -> [bool; 8]{
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


pub fn decode(x: [bool; 8]) -> u8{
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

pub fn encrypt_8bit(x: [bool; 8], client_key: &ClientKey) -> [Ciphertext; 8]{
    let mut res = get_8_ciphers();
    for i in 0..8{
        res[i] = client_key.encrypt(x[i]);
    };
    res
}

pub fn decrypt_8bit(x: [Ciphertext; 8], client_key: &ClientKey) -> [bool; 8]{
    let mut res = [false; 8];
    for i in 0..8{
        res[i] = client_key.decrypt(&x[i]);
    };
    res
}

pub fn plain_8bits_a_smaller_than_b(a: [bool; 8], b: [bool; 8]) -> bool{
    let mut i = 0;
    let mut res = false;
    let mut break_flag = false;
    let mut found_t_flag = false;
    while !break_flag{
        let index = 7-i;
        res = plain_a_smaller_than_b(a[index], b[index]);
        if (i == 0 && res){
            res = true;
            break
        }
        else if(i != 0 && res){
            found_t_flag = true;
        }

        if (found_t_flag && !res){
            res = true;
            break
        }

        i += 1;
        if i == 8{
            break
        }
    }
    res

}

pub fn cipher_8bits_a_smaller_than_b(a: &[Ciphertext; 8], b: &[Ciphertext; 8], calculation_key: &ServerKey, client_key: &ClientKey) -> bool{
    let mut i = 0;
    let mut res = false;
    while !res{
        let tmp = cipher_a_smaller_than_b(&a[i], &b[i], calculation_key);
        res = client_key.decrypt(&tmp);

        i += 1;
        if i == 8{
            break
        }
    }
    res
}

pub fn cipher_8bits_a_smaller_than_b_whole(a: &[Ciphertext; 8], b: &[Ciphertext; 8], calculation_key: &ServerKey) -> [Ciphertext; 8]{
    let mut res = get_8_ciphers();
    for i in 0..8{
        res[i] = cipher_a_smaller_than_b(&a[i], &b[i], &calculation_key);
    };
    res
}

pub fn postprocess_8bits_comparison_result(x: [bool; 8]) -> bool{
    let mut res = false;
    let mut sum = 0;
    for i in 0..8{
        sum += x[i] as i32;
    };

    if sum > 0{
        true
    }
    else{
        false
    }

}


fn plain_8bits_a_smaller_than_b_whole(a: [bool; 8], b: [bool; 8]) -> [bool; 8]{
    let mut res = [false; 8];
    for i in 0..8{
        res[i] = plain_a_smaller_than_b(a[i], b[i]);
    };
    res

}

pub fn plain_a_smaller_than_b(a: bool, b: bool) -> bool{
    !a & b
}

pub fn cipher_a_smaller_than_b(a: &Ciphertext, b: &Ciphertext, calculation_key: &ServerKey) -> Ciphertext{
    let tmp = calculation_key.not(a);
    let res = calculation_key.and(&tmp, b);
    res
}


pub fn generate_ksk(server_sk: &ClientKey, user_sk: &ClientKey) -> LweKeyswitchKey<Vec<u32>>{

    // Allocate the key switching key:
    let mut ksk: LweKeyswitchKey<Vec<u32>> = LweKeyswitchKey::allocate(
        0_u32,
        user_sk.parameters.ks_level,
        user_sk.parameters.ks_base_log,
        //LweDimension(user_sk.parameters.glwe_dimension.0 * user_sk.parameters.polynomial_size.0),
        LweDimension(user_sk.parameters.lwe_dimension.0),
        user_sk.parameters.lwe_dimension,
    );

    // Convert the GLWE secret key into an LWE secret key:
    //let big_lwe_secret_key = user_sk.glwe_secret_key.clone().into_lwe_secret_key();

    let mut encryption_generator = EncryptionRandomGenerator::new(None);
    // Fill the key switching key:
    ksk.fill_with_keyswitch_key(
        &server_sk.lwe_secret_key,
        &user_sk.lwe_secret_key,
        user_sk.parameters.lwe_modular_std_dev,
        &mut encryption_generator,
    );

    ksk


}

pub fn apply_keyswitch(ct: &Ciphertext, ksk: &LweKeyswitchKey<Vec<u32>>) -> Ciphertext{
    let mut ct_after_ks=
    LweCiphertext::allocate(0_u32, DEBUG_PARAMETERS.lwe_dimension.to_lwe_size());

    ksk.keyswitch_ciphertext(&mut ct_after_ks, &ct.0);

    Ciphertext(ct_after_ks)
}

pub fn apply_keyswitch_8bits(ct: &[Ciphertext; 8], ksk: &LweKeyswitchKey<Vec<u32>>) -> [Ciphertext; 8]{
    let mut res = get_8_ciphers();
    for i in 0..8{
        res[i] = apply_keyswitch(&ct[i], ksk);
    };
    res
}