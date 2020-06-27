/*******************************************************************************
*  (c) 2020 Zondax GmbH
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#pragma once

#include <coin.h>
#include <zxtypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

typedef struct {
    const uint8_t *ptr;
    uint8_t len;
} compactInt_t;

typedef uint8_t pd_bool_t;

typedef struct {
    uint64_t _len;
    const uint8_t *_ptr;
} pd_Bytes_t;

// Basic Types
typedef uint64_t cro_nonce_t;
typedef uint64_t cro_coin_t;
typedef uint64_t cro_timespec_t;
typedef uint64_t cro_app_version_t;

#define CRO_REDEEM_ADDRESS_BYTES 20
#define CRO_ED25519_PUBKEY_SIZE  32

typedef struct {
    // CRO_REDEEM_ADDRESS_BYTES
    const uint8_t *_ptr;
} cro_redeem_address_t;

typedef struct {
    // CRO_ED25519_PUBKEY_SIZE
    const uint8_t *_ptr;
} cro_edd25519_pubkey_t;

typedef cro_redeem_address_t cro_staked_state_address_t;

typedef struct {
    uint8_t dummy_zero;
    uint8_t chain_hex_id;
    cro_app_version_t app_version;
} cro_staked_state_op_attributes_t;

typedef pd_Bytes_t cro_validator_name_t;

typedef struct  {
    uint8_t hasValue;
    pd_Bytes_t security_contact;
} cro_option_validator_security_contact_t;

#define CRO_TENDERMINT_VALIDATOR_PUBKEY_ED25519 0

typedef struct {
    uint8_t keytype;
    union {
        cro_edd25519_pubkey_t edd25519_pubkey;
    };
} cro_tendermint_validator_pubkey_t;

typedef pd_Bytes_t cro_confidential_init_t;

typedef struct {
    uint8_t dummy_zero;
    cro_validator_name_t name;
    cro_option_validator_security_contact_t security_contact;
    cro_tendermint_validator_pubkey_t consensus_pubkey;
    cro_confidential_init_t confidential_init;
} cro_council_node_t;

typedef pd_Bytes_t cro_tx_access_t;

typedef struct {
    cro_tendermint_validator_pubkey_t key;
    cro_tx_access_t access;
} cro_access_policy_t;

typedef struct {
    uint8_t chain_id;
    cro_access_policy_t allowed_view[10];
    uint64_t app_version;
} cro_tx_attributes_t;

typedef struct{
    uint64_t _len;
    const uint8_t *_ptr;
    uint64_t _lenBuffer;
} cro_vector_tx_out_t;

typedef struct {
    cro_redeem_address_t address;
    cro_coin_t  value;
    cro_timespec_t valid_from;
} cro_tx_out_t;

////////////////////////////////////////
// Transactions

// TxPublicAux - UnboundStakeTx (UnboundTx)
typedef struct {
    cro_staked_state_address_t from_staked_account;
    cro_nonce_t nonce;
    cro_coin_t value;
    cro_staked_state_op_attributes_t attributes;
} cro_unbond_tx_t;

// TxPublicAux - UnjailTx (UnjailTx)
typedef struct {
    cro_nonce_t nonce;
    cro_staked_state_address_t address;
    cro_staked_state_op_attributes_t attributes;
} cro_unjail_tx_t;

// TxPublicAux - NodeJoinTx (NodeJoinRequestTx)
typedef struct {
    cro_nonce_t nonce;
    cro_staked_state_address_t address;
    cro_staked_state_op_attributes_t attributes;
    cro_council_node_t node_meta;
} cro_node_join_request_tx_t;

// PlainTxAux - WithdrawUnboundedStakeTx (WithdrawUnboundedTx)
typedef struct {
    cro_nonce_t nonce;
    cro_vector_tx_out_t address;
    cro_tx_attributes_t attributes;
} cro_withdraw_unbonded_tx_t;

/////////////////////
/////////////////////
/////////////////////

#define CRO_TX_AUX_ENUM_ENCLAVE_TX              0
#define CRO_TX_AUX_ENUM_PUBLIC_TX               1

#define CRO_TX_PUBLIC_AUX_UNBOND_STAKE          0
#define CRO_TX_PUBLIC_AUX_UNJAIL                1
#define CRO_TX_PUBLIC_AUX_NODE_JOIN             2

#define CRO_TX_PLAIN_TX_TRANSFER                0
#define CRO_TX_DEPOSIT_STAKE                    1
#define CRO_TX_WITHDRAW_UNBOUNDED_STAKE         2


typedef struct {
    // 0 - Enclave Tx
    // 1 - TxPlug
    uint8_t txAuxEnumType;

    uint8_t txType;
    union {
        // Tx Public Aux
        cro_unbond_tx_t cro_unbound_stake_tx;
        cro_unjail_tx_t cro_unjail_tx;
        cro_node_join_request_tx_t cro_node_join_request_tx;

        // PlainTxAux
        cro_withdraw_unbonded_tx_t cro_withdraw_unbounded_tx;
    };

} parser_tx_t;

#ifdef __cplusplus
}
#endif
