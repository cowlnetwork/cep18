use casper_eip_712::{
    encode_address, encode_bytes32, encode_uint256, encode_uint64, keccak256, Address,
    DomainBuilder, DomainFieldValue,
};
use casper_engine_test_support::{ExecuteRequestBuilder, DEFAULT_ACCOUNT_ADDR};
use casper_execution_engine::{engine_state::Error as CoreError, execution::ExecError};
use casper_types::{
    bytesrepr::{Bytes, ToBytes},
    crypto::sign,
    runtime_args, ApiError, Key, PublicKey, SecretKey, U256,
};
use cowl_cep18::{
    constants::{
        ARG_AMOUNT, ARG_DEADLINE, ARG_FROM, ARG_NONCE, ARG_OWNER, ARG_PUBLIC_KEY, ARG_SIGNATURE,
        ARG_SPENDER, ARG_TO, ARG_VALID_AFTER, ARG_VALID_BEFORE, ARG_VALUE, ENTRY_POINT_PERMIT,
        ENTRY_POINT_RECEIVE_WITH_AUTHORIZATION, ENTRY_POINT_TRANSFER_WITH_AUTHORIZATION,
    },
    error::Cep18Error,
};
use std::convert::TryInto;

use crate::utility::{
    constants::{ACCOUNT_USER_1, ACCOUNT_USER_2, TOKEN_NAME},
    installer_request_builders::{
        cep18_check_allowance_of, cep18_check_authorization_state, cep18_check_balance_of, setup,
        TestContext,
    },
    support::create_dummy_key_pair,
};

const DOMAIN_VERSION: &str = "1";
const CHAIN_NAME: &str = "casper:casper";
const TRANSFER_WITH_AUTHORIZATION_TYPE: &str = "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";
const RECEIVE_WITH_AUTHORIZATION_TYPE: &str = "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";
const PERMIT_TYPE: &str =
    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";

#[test]
fn should_transfer_with_authorization_and_record_its_state() {
    let (
        mut builder,
        TestContext {
            cep18_token,
            cep18_token_package,
            ref test_accounts,
            ..
        },
    ) = setup();
    let owner = Key::Account(*DEFAULT_ACCOUNT_ADDR);
    let recipient = Key::Account(*test_accounts.get(&ACCOUNT_USER_1).unwrap());
    let relayer = *test_accounts.get(&ACCOUNT_USER_2).unwrap();
    let (owner_secret_key, owner_public_key) = default_account_keys();
    let amount = U256::from(100u64);
    let nonce = Bytes::from(vec![1u8; 32]);
    let signature = sign_authorization(
        &owner_secret_key,
        &owner_public_key,
        cep18_token_package.value(),
        TRANSFER_WITH_AUTHORIZATION_TYPE,
        owner,
        recipient,
        amount,
        0,
        u64::MAX,
        nonce.clone(),
    );

    let request = authorization_request(
        relayer,
        cep18_token,
        ENTRY_POINT_TRANSFER_WITH_AUTHORIZATION,
        owner,
        recipient,
        amount,
        nonce.clone(),
        owner_public_key.clone(),
        signature.clone(),
    );
    builder.exec(request).expect_success().commit();

    assert_eq!(
        cep18_check_balance_of(&mut builder, &cep18_token, recipient),
        amount
    );
    assert!(cep18_check_authorization_state(
        &mut builder,
        owner,
        nonce.clone()
    ));

    let replay = authorization_request(
        relayer,
        cep18_token,
        ENTRY_POINT_TRANSFER_WITH_AUTHORIZATION,
        owner,
        recipient,
        amount,
        nonce,
        owner_public_key,
        signature,
    );
    builder.exec(replay).commit();
    assert!(matches!(
        builder.get_error(),
        Some(CoreError::Exec(ExecError::Revert(ApiError::User(code))))
            if code == Cep18Error::AuthorizationAlreadyUsed as u16
    ));
}

#[test]
fn should_receive_with_authorization_only_as_recipient() {
    let (
        mut builder,
        TestContext {
            cep18_token,
            cep18_token_package,
            ref test_accounts,
            ..
        },
    ) = setup();
    let owner = Key::Account(*DEFAULT_ACCOUNT_ADDR);
    let recipient_account = *test_accounts.get(&ACCOUNT_USER_1).unwrap();
    let recipient = Key::Account(recipient_account);
    let (owner_secret_key, owner_public_key) = default_account_keys();
    let amount = U256::from(200u64);
    let nonce = Bytes::from(vec![2u8; 32]);
    let signature = sign_authorization(
        &owner_secret_key,
        &owner_public_key,
        cep18_token_package.value(),
        RECEIVE_WITH_AUTHORIZATION_TYPE,
        owner,
        recipient,
        amount,
        0,
        u64::MAX,
        nonce.clone(),
    );

    let request = authorization_request(
        recipient_account,
        cep18_token,
        ENTRY_POINT_RECEIVE_WITH_AUTHORIZATION,
        owner,
        recipient,
        amount,
        nonce,
        owner_public_key,
        signature,
    );
    builder.exec(request).expect_success().commit();

    assert_eq!(
        cep18_check_balance_of(&mut builder, &cep18_token, recipient),
        amount
    );
}

#[test]
fn should_permit_with_a_signed_allowance() {
    let (
        mut builder,
        TestContext {
            cep18_token,
            cep18_token_package,
            ref test_accounts,
            ..
        },
    ) = setup();
    let owner = Key::Account(*DEFAULT_ACCOUNT_ADDR);
    let spender = Key::Account(*test_accounts.get(&ACCOUNT_USER_1).unwrap());
    let relayer = *test_accounts.get(&ACCOUNT_USER_2).unwrap();
    let (owner_secret_key, owner_public_key) = default_account_keys();
    let value = U256::from(300u64);
    let signature = sign_permit(
        &owner_secret_key,
        &owner_public_key,
        cep18_token_package.value(),
        owner,
        spender,
        value,
        U256::zero(),
        u64::MAX,
    );

    let request = ExecuteRequestBuilder::contract_call_by_hash(
        relayer,
        cep18_token.into(),
        ENTRY_POINT_PERMIT,
        runtime_args! {
            ARG_OWNER => owner,
            ARG_SPENDER => spender,
            ARG_VALUE => value,
            ARG_DEADLINE => u64::MAX,
            ARG_PUBLIC_KEY => owner_public_key.clone(),
            ARG_SIGNATURE => signature.clone(),
        },
    )
    .with_block_time(1_000)
    .build();
    builder.exec(request).expect_success().commit();

    assert_eq!(
        cep18_check_allowance_of(&mut builder, owner, spender),
        value
    );

    let replay = ExecuteRequestBuilder::contract_call_by_hash(
        relayer,
        cep18_token.into(),
        ENTRY_POINT_PERMIT,
        runtime_args! {
            ARG_OWNER => owner,
            ARG_SPENDER => spender,
            ARG_VALUE => value,
            ARG_DEADLINE => u64::MAX,
            ARG_PUBLIC_KEY => owner_public_key,
            ARG_SIGNATURE => signature,
        },
    )
    .with_block_time(1_000)
    .build();
    builder.exec(replay).commit();
    assert!(matches!(
        builder.get_error(),
        Some(CoreError::Exec(ExecError::Revert(ApiError::User(code))))
            if code == Cep18Error::InvalidPermitSignature as u16
    ));
}

fn authorization_request(
    sender: casper_types::account::AccountHash,
    contract: casper_types::contracts::ContractHash,
    entry_point: &str,
    from: Key,
    to: Key,
    amount: U256,
    nonce: Bytes,
    public_key: PublicKey,
    signature: Bytes,
) -> casper_engine_test_support::ExecuteRequest {
    ExecuteRequestBuilder::contract_call_by_hash(
        sender,
        contract.into(),
        entry_point,
        runtime_args! {
            ARG_FROM => from,
            ARG_TO => to,
            ARG_AMOUNT => amount,
            ARG_VALID_AFTER => 0u64,
            ARG_VALID_BEFORE => u64::MAX,
            ARG_NONCE => nonce,
            ARG_PUBLIC_KEY => public_key,
            ARG_SIGNATURE => signature,
        },
    )
    .with_block_time(1_000)
    .build()
}

fn sign_authorization(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    package_hash: [u8; 32],
    type_name: &str,
    from: Key,
    to: Key,
    amount: U256,
    valid_after: u64,
    valid_before: u64,
    nonce: Bytes,
) -> Bytes {
    let mut encoded = Vec::with_capacity(32 * 6);
    encoded.extend_from_slice(&encode_key(from));
    encoded.extend_from_slice(&encode_key(to));
    encoded.extend_from_slice(&encode_u256(amount));
    encoded.extend_from_slice(&encode_uint64(valid_after));
    encoded.extend_from_slice(&encode_uint64(valid_before));
    encoded.extend_from_slice(&encode_bytes32(nonce.as_slice().try_into().unwrap()));

    sign_typed_data(secret_key, public_key, package_hash, type_name, encoded)
}

fn sign_permit(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    package_hash: [u8; 32],
    owner: Key,
    spender: Key,
    value: U256,
    nonce: U256,
    deadline: u64,
) -> Bytes {
    let mut encoded = Vec::with_capacity(32 * 5);
    encoded.extend_from_slice(&encode_key(owner));
    encoded.extend_from_slice(&encode_key(spender));
    encoded.extend_from_slice(&encode_u256(value));
    encoded.extend_from_slice(&encode_u256(nonce));
    encoded.extend_from_slice(&encode_uint64(deadline));

    sign_typed_data(secret_key, public_key, package_hash, PERMIT_TYPE, encoded)
}

fn sign_typed_data(
    secret_key: &SecretKey,
    public_key: &PublicKey,
    package_hash: [u8; 32],
    type_name: &str,
    encoded: Vec<u8>,
) -> Bytes {
    let mut struct_data = keccak256(type_name.as_bytes()).to_vec();
    struct_data.extend_from_slice(&encoded);

    let domain = DomainBuilder::new()
        .name(TOKEN_NAME)
        .version(DOMAIN_VERSION)
        .custom_field("chain_name", DomainFieldValue::String(CHAIN_NAME.into()))
        .custom_field(
            "contract_package_hash",
            DomainFieldValue::Bytes32(package_hash),
        )
        .build();
    let mut message = [0u8; 66];
    message[..2].copy_from_slice(&[0x19, 0x01]);
    message[2..34].copy_from_slice(&domain.separator_hash());
    message[34..].copy_from_slice(&keccak256(&struct_data));

    Bytes::from(
        sign(keccak256(&message), secret_key, public_key)
            .to_bytes()
            .unwrap(),
    )
}

fn encode_key(key: Key) -> [u8; 32] {
    let bytes: [u8; 33] = key.to_bytes().unwrap().try_into().unwrap();
    encode_address(Address::Casper(bytes))
}

fn encode_u256(value: U256) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);
    encode_uint256(bytes)
}

fn default_account_keys() -> (SecretKey, PublicKey) {
    create_dummy_key_pair([199u8; SecretKey::ED25519_LENGTH])
}
