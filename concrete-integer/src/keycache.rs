use concrete_shortint::Parameters;
use lazy_static::lazy_static;

use crate::client_key::VecLength;

use crate::{ClientKey, ServerKey};

#[derive(Default)]
pub struct IntegerKeyCache;

impl IntegerKeyCache {
    pub fn get_from_params(
        &self,
        params: Parameters,
        vec_length: VecLength,
    ) -> (ClientKey, ServerKey) {
        let keys = concrete_shortint::keycache::KEY_CACHE.get_from_param(params);
        let (client_key, server_key) = (keys.client_key(), keys.server_key());

        let client_key = ClientKey::from_shortint(client_key.clone(), vec_length);
        let server_key = ServerKey::from_shortint(&client_key, server_key.clone());

        (client_key, server_key)
    }

    pub fn get_shortint_from_params(
        &self,
        params: Parameters,
    ) -> (concrete_shortint::ClientKey, concrete_shortint::ServerKey) {
        let keys = concrete_shortint::keycache::KEY_CACHE.get_from_param(params);
        (keys.client_key().clone(), keys.server_key().clone())
    }
}

lazy_static! {
    pub static ref KEY_CACHE: IntegerKeyCache = IntegerKeyCache::default();
}