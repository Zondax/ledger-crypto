/*******************************************************************************
*   (c) 2019 Zondax GmbH
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

#include <stdio.h>
#include <zxmacros.h>
#include "parser_impl.h"
#include "parser.h"
#include "coin.h"
#include "zbuffer.h"

#if defined(TARGET_NANOX)
// For some reason NanoX requires this function
void __assert_fail(const char * assertion, const char * file, unsigned int line, const char * function){
    while(1) {};
}
#endif

parser_error_t parser_parse(parser_context_t *ctx, const uint8_t *data, size_t dataLen, parser_tx_t *tx_obj) {
    CHECK_PARSER_ERR(parser_init(ctx, data, dataLen))
    ctx->tx_obj = tx_obj;
    parser_error_t err = _read(ctx, ctx->tx_obj);
    zb_check_canary();
    return err;
}

parser_error_t parser_validate(parser_context_t *ctx) {
    CHECK_PARSER_ERR(_validateTx(ctx, ctx->tx_obj))

    uint8_t numItems = 0;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))

    char tmpKey[40];
    char tmpVal[40];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_PARSER_ERR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }

    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    *num_items = _getNumItems(ctx, ctx->tx_obj);
    return parser_ok;
}

////////////////////////////////////
// TX ITEMS

__Z_INLINE parser_error_t parser_print_nonce(const cro_nonce_t *v,
                                             char *outVal, uint16_t outValLen,
                                             uint8_t pageIdx, uint8_t *pageCount) {
    char bufferUI[100];
    uint64_to_str(bufferUI, sizeof(bufferUI), *v);
    pageString(outVal, outValLen, bufferUI, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_print_coin(const cro_coin_t *v,
                                            char *outVal, uint16_t outValLen,
                                            uint8_t pageIdx, uint8_t *pageCount) {
    // FIXME: how to format coins
    char bufferUI[100];
    uint64_to_str(bufferUI, sizeof(bufferUI), *v);
    pageString(outVal, outValLen, bufferUI, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_print_appVersion(const cro_app_version_t *v,
                                                  char *outVal, uint16_t outValLen,
                                                  uint8_t pageIdx, uint8_t *pageCount) {
    // FIXME: how to format coins
    char bufferUI[100];
    uint64_to_str(bufferUI, sizeof(bufferUI), *v);
    pageString(outVal, outValLen, bufferUI, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_print_staked_state_address(const cro_staked_state_address_t *v,
                                                            char *outVal, uint16_t outValLen,
                                                            uint8_t pageIdx, uint8_t *pageCount) {
    char buffer[50];
    MEMZERO(buffer, sizeof(buffer));

    if (array_to_hexstr(buffer, sizeof(buffer), v->_ptr, 20) != 40)
        return parser_invalid_address;

    pageStringExt(outVal, outValLen, buffer, 40, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_print_council_node_validator_name(const cro_validator_name_t *v,
                                                                   char *outVal, uint16_t outValLen,
                                                                   uint8_t pageIdx, uint8_t *pageCount) {
    pageStringExt(outVal, outValLen, (char *) v->_ptr, v->_len, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_print_council_node_security_contact(const cro_option_validator_security_contact_t *v,
                                                                     char *outVal, uint16_t outValLen,
                                                                     uint8_t pageIdx, uint8_t *pageCount) {
    if (!v->hasValue) {
        snprintf(outVal, outValLen, "<EMPTY>");
        return parser_ok;
    }

    pageStringExt(outVal, outValLen, (char *) v->security_contact._ptr, v->security_contact._len, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t
parser_print_council_node_tendermint_validator_pubkey(const cro_tendermint_validator_pubkey_t *v,
                                                      char *outVal, uint16_t outValLen,
                                                      uint8_t pageIdx, uint8_t *pageCount) {

    if (pageIdx == 0) {
        switch (v->keytype) {
            case CRO_TENDERMINT_VALIDATOR_PUBKEY_ED25519:
                snprintf(outVal, outValLen, "Ed25519");
                *pageCount = 1 + (CRO_ED25519_PUBKEY_SIZE * 2) / outValLen;
                if (outValLen % (CRO_ED25519_PUBKEY_SIZE * 2) != 0) {
                    (*pageCount)++;
                }
                return parser_ok;
            default:
                return parser_unexpected_value;
        }
    }

    char buffer[70];
    MEMZERO(buffer, sizeof(buffer));

    if (array_to_hexstr(buffer, sizeof(buffer), v->edd25519_pubkey._ptr, CRO_ED25519_PUBKEY_SIZE) !=
        CRO_ED25519_PUBKEY_SIZE * 2)
        return parser_invalid_address;

    pageIdx--;
    pageStringExt(outVal, outValLen, buffer, CRO_ED25519_PUBKEY_SIZE * 2, pageIdx, pageCount);
    (*pageCount)++;

    return parser_ok;
}

__Z_INLINE parser_error_t parser_print_council_node_confidential_init(const cro_confidential_init_t *v,
                                                                      char *outVal, uint16_t outValLen,
                                                                      uint8_t pageIdx, uint8_t *pageCount) {
    char bufferUI[100];
    MEMZERO(bufferUI, sizeof(bufferUI));
    strcpy(bufferUI, "bytes: ");

    uint64_to_str(bufferUI + 7, sizeof(bufferUI) - 7, v->_len);
    pageString(outVal, outValLen, bufferUI, pageIdx, pageCount);
    return parser_ok;
}

__Z_INLINE parser_error_t parser_print_vector_tx_out(const cro_vector_tx_out_t *v,
                                                     char *outVal, uint16_t outValLen,
                                                     uint8_t pageIdx, uint8_t *pageCount) {
    return parser_ok;
}

__Z_INLINE parser_error_t parser_print_tx_attributes(const cro_tx_attributes_t *v,
                                                     char *outVal, uint16_t outValLen,
                                                     uint8_t pageIdx, uint8_t *pageCount) {
    return parser_ok;
}

////////////////////////////////////
// TX COMPLETE

__Z_INLINE parser_error_t parser_getItem_unbound_stake(const cro_unbond_tx_t *v,
                                                       uint16_t displayIdx,
                                                       char *outKey, uint16_t outKeyLen,
                                                       char *outVal, uint16_t outValLen,
                                                       uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            *pageCount = 1;
            if (pageIdx != 0) return parser_no_data;
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Unbound Stake");
            return parser_ok;
        case 1:
            snprintf(outKey, outKeyLen, "From");
            return parser_print_staked_state_address(&v->from_staked_account, outVal, outValLen, pageIdx, pageCount);
        case 2:
            snprintf(outKey, outKeyLen, "Nonce");
            return parser_print_nonce(&v->nonce, outVal, outValLen, pageIdx, pageCount);
        case 3:
            snprintf(outKey, outKeyLen, "Value");
            return parser_print_coin(&v->value, outVal, outValLen, pageIdx, pageCount);
        case 4:
            snprintf(outKey, outKeyLen, "ChainID");
            snprintf(outVal, outValLen, "%02x", v->attributes.chain_hex_id);
            return parser_ok;
        case 5:
            snprintf(outKey, outKeyLen, "AppVersion");
            return parser_print_appVersion(&v->attributes.app_version, outVal, outValLen, pageIdx, pageCount);
        default:
            return parser_no_data;
    }
}

__Z_INLINE parser_error_t parser_getItem_unjail(const cro_unjail_tx_t *v,
                                                uint16_t displayIdx,
                                                char *outKey, uint16_t outKeyLen,
                                                char *outVal, uint16_t outValLen,
                                                uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            *pageCount = 1;
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Unjail");
            return parser_ok;
        case 1:
            snprintf(outKey, outKeyLen, "Nonce");
            return parser_print_nonce(&v->nonce, outVal, outValLen, pageIdx, pageCount);
        case 2:
            snprintf(outKey, outKeyLen, "Address");
            return parser_print_staked_state_address(&v->address, outVal, outValLen, pageIdx, pageCount);
        case 3:
            snprintf(outKey, outKeyLen, "ChainID");
            snprintf(outVal, outValLen, "%02x", v->attributes.chain_hex_id);
            return parser_ok;
        case 4:
            snprintf(outKey, outKeyLen, "AppVersion");
            return parser_print_appVersion(&v->attributes.app_version, outVal, outValLen, pageIdx, pageCount);
        default:
            return parser_no_data;
    }
}

__Z_INLINE parser_error_t parser_getItem_node_join_request(const cro_node_join_request_tx_t *v,
                                                           uint16_t displayIdx,
                                                           char *outKey, uint16_t outKeyLen,
                                                           char *outVal, uint16_t outValLen,
                                                           uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            *pageCount = 1;
            if (pageIdx != 0) return parser_no_data;
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Node Join Req.");
            return parser_ok;
        case 1:
            snprintf(outKey, outKeyLen, "Nonce");
            return parser_print_nonce(&v->nonce, outVal, outValLen, pageIdx, pageCount);
        case 2:
            snprintf(outKey, outKeyLen, "Address");
            return parser_print_staked_state_address(&v->address, outVal, outValLen, pageIdx, pageCount);
        case 3:
            snprintf(outKey, outKeyLen, "ChainID");
            snprintf(outVal, outValLen, "%02x", v->attributes.chain_hex_id);
            return parser_ok;
        case 4:
            snprintf(outKey, outKeyLen, "AppVersion");
            return parser_print_appVersion(&v->attributes.app_version, outVal, outValLen, pageIdx, pageCount);
        case 5:
            snprintf(outKey, outKeyLen, "Name");
            return parser_print_council_node_validator_name(&v->node_meta.name,
                                                            outVal, outValLen, pageIdx, pageCount);
        case 6:
            snprintf(outKey, outKeyLen, "Sec Contact");
            return parser_print_council_node_security_contact(&v->node_meta.security_contact,
                                                              outVal, outValLen, pageIdx, pageCount);
        case 7:
            snprintf(outKey, outKeyLen, "Val Pubkey");
            return parser_print_council_node_tendermint_validator_pubkey(&v->node_meta.consensus_pubkey,
                                                                         outVal, outValLen, pageIdx, pageCount);
        case 8:
            snprintf(outKey, outKeyLen, "Conf Init");
            return parser_print_council_node_confidential_init(&v->node_meta.confidential_init,
                                                               outVal, outValLen, pageIdx, pageCount);
        default:
            return parser_no_data;
    }
}

__Z_INLINE parser_error_t parser_getItem_withdraw_unbounded(const cro_withdraw_unbonded_tx_t *v,
                                                            uint16_t displayIdx,
                                                            char *outKey, uint16_t outKeyLen,
                                                            char *outVal, uint16_t outValLen,
                                                            uint8_t pageIdx, uint8_t *pageCount) {
    switch (displayIdx) {
        case 0:
            *pageCount = 1;
            snprintf(outKey, outKeyLen, "Type");
            snprintf(outVal, outValLen, "Withdraw unbounded");
            return parser_ok;
        case 1:
            snprintf(outKey, outKeyLen, "Nonce");
            return parser_print_nonce(&v->nonce, outVal, outValLen, pageIdx, pageCount);
        case 2:
            snprintf(outKey, outKeyLen, "Address");
            return parser_print_vector_tx_out(&v->address, outVal, outValLen, pageIdx, pageCount);
        case 3:
            snprintf(outKey, outKeyLen, "Attributes");
            return parser_print_tx_attributes(&v->attributes, outVal, outValLen, pageIdx, pageCount);
        default:
            return parser_no_data;
    }
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint16_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, "?");
    *pageCount = 0;

    uint8_t numItems;
    CHECK_PARSER_ERR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    if (displayIdx < 0 || displayIdx >= numItems) {
        return parser_no_data;
    }

    switch (ctx->tx_obj->txAuxEnumType) {
        case CRO_TX_AUX_ENUM_ENCLAVE_TX:
            return parser_no_data;
        case CRO_TX_AUX_ENUM_PUBLIC_TX: {
            switch (ctx->tx_obj->txType) {
                case CRO_TX_PUBLIC_AUX_UNBOND_STAKE: CHECK_PARSER_ERR(
                        parser_getItem_unbound_stake(&ctx->tx_obj->cro_unbound_stake_tx,
                                                     displayIdx,
                                                     outKey, outKeyLen,
                                                     outVal, outValLen,
                                                     pageIdx, pageCount))
                    break;
                case CRO_TX_PUBLIC_AUX_UNJAIL: CHECK_PARSER_ERR(
                        parser_getItem_unjail(&ctx->tx_obj->cro_unjail_tx,
                                              displayIdx,
                                              outKey, outKeyLen,
                                              outVal, outValLen,
                                              pageIdx, pageCount))
                    break;
                case CRO_TX_PUBLIC_AUX_NODE_JOIN: CHECK_PARSER_ERR(
                        parser_getItem_node_join_request(&ctx->tx_obj->cro_node_join_request_tx,
                                                         displayIdx,
                                                         outKey, outKeyLen,
                                                         outVal, outValLen,
                                                         pageIdx, pageCount))
                    break;
            }
        }
    }

    if (*pageCount > 1) {
        uint8_t keyLen = strlen(outKey);
        if (keyLen < outKeyLen) {
            snprintf(outKey + keyLen, outKeyLen - keyLen, " [%d/%d]", pageIdx + 1, *pageCount);
        }
    }

    return parser_ok;
}
