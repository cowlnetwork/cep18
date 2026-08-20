use alloc::{string::String, vec::Vec};
use casper_contract::{
    contract_api::{cryptography, runtime, storage},
    unwrap_or_revert::UnwrapOrRevert,
};
use casper_eip_712::{
    encode_address, encode_bytes32, encode_uint256, encode_uint64, keccak256, Address,
    DomainBuilder, DomainFieldValue,
};
use casper_types::{
    bytesrepr::{Bytes, FromBytes, ToBytes},
    Key, PublicKey, Signature, URef, U256,
};

use crate::{
    constants::{
        ARG_NAME, ARG_PACKAGE_HASH, DICT_PERMIT_NONCES, DICT_USED_AUTHORIZATION_NONCES,
        KEY_GASLESS_CHAIN_NAME,
    },
    error::Cep18Error,
    utils::{base64_encode, get_stored_value},
};

const DOMAIN_VERSION: &str = "1";
pub const TRANSFER_WITH_AUTHORIZATION_TYPEHASH: [u8; 32] = [
    0x7c, 0x7c, 0x6c, 0xdb, 0x67, 0xa1, 0x87, 0x43, 0xf4, 0x9e, 0xc6, 0xfa, 0x9b, 0x35, 0xf5, 0x0d,
    0x52, 0xed, 0x05, 0xcb, 0xed, 0x4c, 0xc5, 0x92, 0xe1, 0x3b, 0x44, 0x50, 0x1c, 0x1a, 0x22, 0x67,
];
pub const RECEIVE_WITH_AUTHORIZATION_TYPEHASH: [u8; 32] = [
    0xd0, 0x99, 0xcc, 0x98, 0xef, 0x71, 0x10, 0x7a, 0x61, 0x6c, 0x4f, 0x0f, 0x94, 0x1f, 0x04, 0xc3,
    0x22, 0xd8, 0xe2, 0x54, 0xfe, 0x26, 0xb3, 0xc6, 0x66, 0x8d, 0xb8, 0x7a, 0xae, 0x41, 0x3d, 0xe8,
];
const PERMIT_TYPEHASH: [u8; 32] = [
    0x6e, 0x71, 0xed, 0xae, 0x12, 0xb1, 0xb9, 0x7f, 0x4d, 0x1f, 0x60, 0x37, 0x0f, 0xef, 0x10, 0x10,
    0x5f, 0xa2, 0xfa, 0xae, 0x01, 0x26, 0x11, 0x4a, 0x16, 0x9c, 0x64, 0x84, 0x5d, 0x61, 0x26, 0xc9,
];

pub fn init(chain_name: String) {
    storage::new_dictionary(DICT_USED_AUTHORIZATION_NONCES).unwrap_or_revert();
    storage::new_dictionary(DICT_PERMIT_NONCES).unwrap_or_revert();
    runtime::put_key(KEY_GASLESS_CHAIN_NAME, storage::new_uref(chain_name).into());
}

pub fn authorization_state(authorizer: Key, nonce: Bytes) -> bool {
    let used_nonces = dictionary_uref(DICT_USED_AUTHORIZATION_NONCES);
    storage::dictionary_get(used_nonces, &authorization_key(authorizer, &nonce))
        .unwrap_or_revert()
        .unwrap_or_default()
}

pub fn consume_authorization(
    typehash: [u8; 32],
    from: Key,
    to: Key,
    amount: U256,
    valid_after: u64,
    valid_before: u64,
    nonce: Bytes,
    public_key: PublicKey,
    signature: Bytes,
) {
    let nonce_bytes: [u8; 32] = match nonce.as_slice().try_into() {
        Ok(value) => value,
        Err(_) => runtime::revert(Cep18Error::InvalidAuthorizationNonce),
    };
    if authorization_state(from, nonce.clone()) {
        runtime::revert(Cep18Error::AuthorizationAlreadyUsed);
    }

    let now = runtime::get_blocktime().value() / 1_000;
    if now <= valid_after {
        runtime::revert(Cep18Error::AuthorizationNotYetValid);
    }
    if now >= valid_before {
        runtime::revert(Cep18Error::AuthorizationExpired);
    }
    if Key::from(public_key.clone().to_account_hash()) != from {
        runtime::revert(Cep18Error::InvalidAuthorizationPublicKey);
    }

    let message = authorization_message(
        typehash,
        from,
        to,
        amount,
        valid_after,
        valid_before,
        nonce_bytes,
    );
    verify(
        message,
        public_key,
        signature,
        Cep18Error::InvalidAuthorizationSignature,
    );

    let used_nonces = dictionary_uref(DICT_USED_AUTHORIZATION_NONCES);
    storage::dictionary_put(used_nonces, &authorization_key(from, &nonce), true);
}

pub fn permit_message(owner: Key, spender: Key, value: U256, deadline: u64) -> [u8; 32] {
    let nonce = permit_nonce(owner);
    let mut encoded = Vec::with_capacity(32 * 5);
    encoded.extend_from_slice(&encode_key(owner));
    encoded.extend_from_slice(&encode_key(spender));
    encoded.extend_from_slice(&encode_u256(value));
    encoded.extend_from_slice(&encode_u256(nonce));
    encoded.extend_from_slice(&encode_uint64(deadline));
    typed_data_hash(PERMIT_TYPEHASH, encoded)
}

pub fn verify_permit(
    owner: Key,
    spender: Key,
    value: U256,
    deadline: u64,
    public_key: PublicKey,
    signature: Bytes,
) {
    let now = runtime::get_blocktime().value() / 1_000;
    if deadline != u64::MAX && now > deadline {
        runtime::revert(Cep18Error::PermitExpired);
    }
    if Key::from(public_key.clone().to_account_hash()) != owner {
        runtime::revert(Cep18Error::InvalidPermitPublicKey);
    }
    verify(
        permit_message(owner, spender, value, deadline),
        public_key,
        signature,
        Cep18Error::InvalidPermitSignature,
    );
    let nonce = permit_nonce(owner);
    let next_nonce = nonce
        .checked_add(U256::from(1))
        .unwrap_or_revert_with(Cep18Error::PermitNonceOverflow);
    storage::dictionary_put(dictionary_uref(DICT_PERMIT_NONCES), &key(owner), next_nonce);
}

fn authorization_message(
    typehash: [u8; 32],
    from: Key,
    to: Key,
    amount: U256,
    valid_after: u64,
    valid_before: u64,
    nonce: [u8; 32],
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(32 * 6);
    encoded.extend_from_slice(&encode_key(from));
    encoded.extend_from_slice(&encode_key(to));
    encoded.extend_from_slice(&encode_u256(amount));
    encoded.extend_from_slice(&encode_uint64(valid_after));
    encoded.extend_from_slice(&encode_uint64(valid_before));
    encoded.extend_from_slice(&encode_bytes32(nonce));
    typed_data_hash(typehash, encoded)
}

fn typed_data_hash(typehash: [u8; 32], encoded: Vec<u8>) -> [u8; 32] {
    let mut struct_data = Vec::with_capacity(32 + encoded.len());
    struct_data.extend_from_slice(&typehash);
    struct_data.extend_from_slice(&encoded);

    let mut data = [0u8; 66];
    data[..2].copy_from_slice(&[0x19, 0x01]);
    data[2..34].copy_from_slice(&domain_separator().separator_hash());
    data[34..].copy_from_slice(&keccak256(&struct_data));
    keccak256(&data)
}

fn domain_separator() -> casper_eip_712::DomainSeparator {
    let package_hash = runtime::get_key(ARG_PACKAGE_HASH)
        .unwrap_or_revert()
        .into_hash_addr()
        .unwrap_or_revert_with(Cep18Error::UnexpectedKeyVariant);
    DomainBuilder::new()
        .name(&get_stored_value::<String>(ARG_NAME))
        .version(DOMAIN_VERSION)
        .custom_field(
            "chain_name",
            DomainFieldValue::String(get_stored_value(KEY_GASLESS_CHAIN_NAME)),
        )
        .custom_field(
            "contract_package_hash",
            DomainFieldValue::Bytes32(package_hash),
        )
        .build()
}

fn verify(message: [u8; 32], public_key: PublicKey, signature: Bytes, error: Cep18Error) {
    let (signature, remainder) =
        Signature::from_bytes(signature.as_slice()).unwrap_or_revert_with(error);
    if !remainder.is_empty()
        || cryptography::verify_signature(message, &signature, &public_key).is_err()
    {
        runtime::revert(error);
    }
}

fn permit_nonce(owner: Key) -> U256 {
    storage::dictionary_get(dictionary_uref(DICT_PERMIT_NONCES), &key(owner))
        .unwrap_or_revert()
        .unwrap_or_default()
}

fn dictionary_uref(name: &str) -> URef {
    runtime::get_key(name)
        .unwrap_or_revert()
        .into_uref()
        .unwrap_or_revert()
}

fn authorization_key(authorizer: Key, nonce: &Bytes) -> String {
    let mut value = authorizer.to_bytes().unwrap_or_revert();
    value.extend_from_slice(nonce.as_slice());
    base64_encode(value)
}

fn key(owner: Key) -> String {
    base64_encode(owner.to_bytes().unwrap_or_revert())
}

fn encode_key(value: Key) -> [u8; 32] {
    let key: [u8; 33] = match value.to_bytes().unwrap_or_revert().try_into() {
        Ok(value) => value,
        Err(_) => runtime::revert(Cep18Error::UnexpectedKeyVariant),
    };
    encode_address(Address::Casper(key))
}

fn encode_u256(value: U256) -> [u8; 32] {
    let mut encoded = [0u8; 32];
    value.to_big_endian(&mut encoded);
    encode_uint256(encoded)
}
