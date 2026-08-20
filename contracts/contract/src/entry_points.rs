use alloc::{boxed::Box, string::String, vec, vec::Vec};
use casper_types::{
    addressable_entity::{
        EntityEntryPoint, EntryPointAccess, EntryPointPayment, EntryPointType, EntryPoints,
        Parameter,
    },
    bytesrepr::Bytes,
    CLType, CLTyped, Key, PublicKey, U256,
};

use crate::constants::{
    ARG_ADDRESS, ARG_AMOUNT, ARG_AUTHORIZER, ARG_DEADLINE, ARG_FROM, ARG_NONCE, ARG_OWNER,
    ARG_PUBLIC_KEY, ARG_RECIPIENT, ARG_SIGNATURE, ARG_SPENDER, ARG_TO,
    ARG_TRANSFER_FILTER_CONTRACT_PACKAGE, ARG_TRANSFER_FILTER_METHOD, ARG_VALID_AFTER,
    ARG_VALID_BEFORE, ARG_VALUE, ENTRY_POINT_ALLOWANCE, ENTRY_POINT_APPROVE,
    ENTRY_POINT_AUTHORIZATION_STATE, ENTRY_POINT_BALANCE_OF, ENTRY_POINT_BURN,
    ENTRY_POINT_CHANGE_SECURITY, ENTRY_POINT_DECIMALS, ENTRY_POINT_DECREASE_ALLOWANCE,
    ENTRY_POINT_INCREASE_ALLOWANCE, ENTRY_POINT_INIT, ENTRY_POINT_MINT, ENTRY_POINT_NAME,
    ENTRY_POINT_PERMIT, ENTRY_POINT_RECEIVE_WITH_AUTHORIZATION, ENTRY_POINT_SET_TRANSFER_FILTER,
    ENTRY_POINT_SYMBOL, ENTRY_POINT_TOTAL_SUPPLY, ENTRY_POINT_TRANSFER, ENTRY_POINT_TRANSFER_FROM,
    ENTRY_POINT_TRANSFER_WITH_AUTHORIZATION, ENTRY_POINT_UPGRADE,
};

/// Returns the `name` entry point.
pub fn name() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_NAME),
        Vec::new(),
        String::cl_type(),
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `symbol` entry point.
pub fn symbol() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_SYMBOL),
        Vec::new(),
        String::cl_type(),
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `transfer_from` entry point.
pub fn transfer_from() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_TRANSFER_FROM),
        vec![
            Parameter::new(ARG_OWNER, Key::cl_type()),
            Parameter::new(ARG_RECIPIENT, Key::cl_type()),
            Parameter::new(ARG_AMOUNT, U256::cl_type()),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `allowance` entry point.
pub fn allowance() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_ALLOWANCE),
        vec![
            Parameter::new(ARG_OWNER, Key::cl_type()),
            Parameter::new(ARG_SPENDER, Key::cl_type()),
        ],
        U256::cl_type(),
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `approve` entry point.
pub fn approve() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_APPROVE),
        vec![
            Parameter::new(ARG_SPENDER, Key::cl_type()),
            Parameter::new(ARG_AMOUNT, U256::cl_type()),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `increase_allowance` entry point.
pub fn increase_allowance() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_INCREASE_ALLOWANCE),
        vec![
            Parameter::new(ARG_SPENDER, Key::cl_type()),
            Parameter::new(ARG_AMOUNT, U256::cl_type()),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `decrease_allowance` entry point.
pub fn decrease_allowance() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_DECREASE_ALLOWANCE),
        vec![
            Parameter::new(ARG_SPENDER, Key::cl_type()),
            Parameter::new(ARG_AMOUNT, U256::cl_type()),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `transfer` entry point.
pub fn transfer() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_TRANSFER),
        vec![
            Parameter::new(ARG_RECIPIENT, Key::cl_type()),
            Parameter::new(ARG_AMOUNT, U256::cl_type()),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `balance_of` entry point.
pub fn balance_of() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_BALANCE_OF),
        vec![Parameter::new(ARG_ADDRESS, Key::cl_type())],
        U256::cl_type(),
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `total_supply` entry point.
pub fn total_supply() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_TOTAL_SUPPLY),
        Vec::new(),
        U256::cl_type(),
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `decimals` entry point.
pub fn decimals() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_DECIMALS),
        Vec::new(),
        u8::cl_type(),
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `burn` entry point.
pub fn burn() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_BURN),
        vec![
            Parameter::new(ARG_OWNER, Key::cl_type()),
            Parameter::new(ARG_AMOUNT, U256::cl_type()),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `mint` entry point.
pub fn mint() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_MINT),
        vec![
            Parameter::new(ARG_OWNER, Key::cl_type()),
            Parameter::new(ARG_AMOUNT, U256::cl_type()),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `change_security` entry point.
pub fn change_security() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_CHANGE_SECURITY),
        vec![
            // Optional Arguments (can be added or omitted when calling):
            /*
            - "admin_list" : Vec<Key>
            - "minter_list" : Vec<Key>
            - "none_list" : Vec<Key>
            */
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/// Returns the `init` entry point.
pub fn init() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_INIT),
        Vec::new(),
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

pub fn authorization_state() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_AUTHORIZATION_STATE),
        vec![
            Parameter::new(ARG_AUTHORIZER, Key::cl_type()),
            Parameter::new(ARG_NONCE, Bytes::cl_type()),
        ],
        bool::cl_type(),
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

fn authorization_parameters() -> Vec<Parameter> {
    vec![
        Parameter::new(ARG_FROM, Key::cl_type()),
        Parameter::new(ARG_TO, Key::cl_type()),
        Parameter::new(ARG_AMOUNT, U256::cl_type()),
        Parameter::new(ARG_VALID_AFTER, u64::cl_type()),
        Parameter::new(ARG_VALID_BEFORE, u64::cl_type()),
        Parameter::new(ARG_NONCE, Bytes::cl_type()),
        Parameter::new(ARG_PUBLIC_KEY, PublicKey::cl_type()),
        Parameter::new(ARG_SIGNATURE, Bytes::cl_type()),
    ]
}

pub fn transfer_with_authorization() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_TRANSFER_WITH_AUTHORIZATION),
        authorization_parameters(),
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

pub fn receive_with_authorization() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_RECEIVE_WITH_AUTHORIZATION),
        authorization_parameters(),
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

pub fn permit() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_PERMIT),
        vec![
            Parameter::new(ARG_OWNER, Key::cl_type()),
            Parameter::new(ARG_SPENDER, Key::cl_type()),
            Parameter::new(ARG_VALUE, U256::cl_type()),
            Parameter::new(ARG_DEADLINE, u64::cl_type()),
            Parameter::new(ARG_PUBLIC_KEY, PublicKey::cl_type()),
            Parameter::new(ARG_SIGNATURE, Bytes::cl_type()),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

/* COWL */
pub fn set_transfer_filter() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_SET_TRANSFER_FILTER),
        vec![
            Parameter::new(
                ARG_TRANSFER_FILTER_CONTRACT_PACKAGE,
                CLType::Option(Box::new(CLType::Key)),
            ),
            Parameter::new(
                ARG_TRANSFER_FILTER_METHOD,
                CLType::Option(Box::new(CLType::String)),
            ),
        ],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}

pub fn upgrade() -> EntityEntryPoint {
    EntityEntryPoint::new(
        String::from(ENTRY_POINT_UPGRADE),
        vec![],
        CLType::Unit,
        EntryPointAccess::Public,
        EntryPointType::Called,
        EntryPointPayment::Caller,
    )
}
/*  */

/// Returns the default set of CEP-18 token entry points.
pub fn generate_entry_points() -> EntryPoints {
    let mut entry_points = EntryPoints::new();
    entry_points.add_entry_point(init());
    entry_points.add_entry_point(name());
    entry_points.add_entry_point(symbol());
    entry_points.add_entry_point(decimals());
    entry_points.add_entry_point(total_supply());
    entry_points.add_entry_point(balance_of());
    entry_points.add_entry_point(transfer());
    entry_points.add_entry_point(approve());
    entry_points.add_entry_point(allowance());
    entry_points.add_entry_point(decrease_allowance());
    entry_points.add_entry_point(increase_allowance());
    entry_points.add_entry_point(transfer_from());
    entry_points.add_entry_point(change_security());
    entry_points.add_entry_point(burn());
    entry_points.add_entry_point(mint());
    entry_points.add_entry_point(authorization_state());
    entry_points.add_entry_point(transfer_with_authorization());
    entry_points.add_entry_point(receive_with_authorization());
    entry_points.add_entry_point(permit());
    /* COWL */
    entry_points.add_entry_point(set_transfer_filter());
    entry_points.add_entry_point(upgrade());
    /*  */
    entry_points
}
