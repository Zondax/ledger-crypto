/*******************************************************************************
*  (c) 2019 Zondax GmbH
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

#include "parser_impl.h"
#include "parser_txdef.h"

parser_error_t parser_init_context(parser_context_t *ctx,
                                   const uint8_t *buffer,
                                   uint16_t bufferSize) {
    ctx->offset = 0;

    if (bufferSize == 0 || buffer == NULL) {
        // Not available, use defaults
        ctx->buffer = NULL;
        ctx->bufferLen = 0;
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;

    return parser_ok;
}

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize) {
    CHECK_PARSER_ERR(parser_init_context(ctx, buffer, bufferSize))
    return parser_ok;
}

const char *parser_getErrorDescription(parser_error_t err) {
    switch (err) {
        // General errors
        case parser_ok:
            return "No error";
        case parser_no_data:
            return "No more data";
        case parser_init_context_empty:
            return "Initialized empty context";
        case parser_display_idx_out_of_range:
            return "display_idx_out_of_range";
        case parser_display_page_out_of_range:
            return "display_page_out_of_range";
        case parser_unexepected_error:
            return "Unexepected internal error";
            /////////// Context specific
        case parser_context_mismatch:
            return "context prefix is invalid";
        case parser_context_unexpected_size:
            return "context unexpected size";
        case parser_context_invalid_chars:
            return "context invalid chars";
            // Required fields error
        case parser_required_nonce:
            return "Required field nonce";
        case parser_required_method:
            return "Required field method";
            // Coin specific
        case parser_unexpected_type:
            return "Unexpected data type";
        case parser_unexpected_method:
            return "Unexpected method";
        case parser_unexpected_buffer_end:
            return "Unexpected buffer end";
        case parser_unexpected_value:
            return "Unexpected value";
        case parser_unexpected_number_items:
            return "Unexpected number of items";
        case parser_unexpected_characters:
            return "Unexpected characters";
        case parser_unexpected_field:
            return "Unexpected field";
        case parser_value_out_of_range:
            return "Value out of range";
        case parser_invalid_address:
            return "Invalid address format";
        default:
            return "Unrecognized error code";
    }
}

GEN_DEF_READFIX_UNSIGNED(8)

GEN_DEF_READFIX_UNSIGNED(16)

GEN_DEF_READFIX_UNSIGNED(32)

GEN_DEF_READFIX_UNSIGNED(64)

parser_error_t _readBool(parser_context_t *c, pd_bool_t *v) {
    CHECK_INPUT();

    const uint8_t p = *(c->buffer + c->offset);
    CTX_CHECK_AND_ADVANCE(c, 1)

    switch (p) {
        case 0x00:
            *v = bool_false;
            break;
        case 0x01:
            *v = bool_true;
            break;
        default:
            return parser_unexpected_value;
    }
    return parser_ok;
}

parser_error_t _getValue(const compactInt_t *c, uint64_t *v) {
    *v = 0;

    switch (c->len) {
        case 1:
            *v = (*c->ptr) >> 2u;
            break;
        case 2:
            *v = (*c->ptr) >> 2u;
            *v += *(c->ptr + 1) << 6u;
            if (*v < 64) {
                return parser_value_out_of_range;
            }
            break;
        case 4:
            *v = (*c->ptr) >> 2u;
            *v += *(c->ptr + 1) << 6u;
            *v += *(c->ptr + 2) << (8u + 6u);
            *v += *(c->ptr + 3) << (16u + 6u);
            if (*v < 16383) {
                return parser_value_out_of_range;
            }
            break;
        default:
            return parser_value_out_of_range;
    }

    return parser_ok;
}

parser_error_t _readCompactInt(parser_context_t *c, compactInt_t *v) {
    CHECK_INPUT();

    v->ptr = c->buffer + c->offset;
    const uint8_t mode = *v->ptr & 0x03u;      // get mode from two least significant bits

    uint64_t tmp;
    switch (mode) {
        case 0:         // single byte
            v->len = 1;
            CTX_CHECK_AND_ADVANCE(c, v->len)
            break;
        case 1:         // 2-byte
            v->len = 2;
            CTX_CHECK_AND_ADVANCE(c, v->len)
            _getValue(v, &tmp);
            break;
        case 2:         // 4-byte
            v->len = 4;
            CTX_CHECK_AND_ADVANCE(c, v->len)
            _getValue(v, &tmp);
            break;
        case 3:         // bitint
            v->len = (*v->ptr >> 2u) + 4 + 1;
            CTX_CHECK_AND_ADVANCE(c, v->len)
            break;
        default:
            // this is actually impossible
            // this is actually impossible
            return parser_unexpected_value;
    }

    return parser_ok;
}

parser_error_t _readBytes(parser_context_t *c, pd_Bytes_t *v) {
    CHECK_INPUT()

    compactInt_t clen;
    CHECK_PARSER_ERR(_readCompactInt(c, &clen))
    CHECK_PARSER_ERR(_getValue(&clen, &v->_len))

    v->_ptr = c->buffer + c->offset;
    CTX_CHECK_AND_ADVANCE(c, v->_len);
    return parser_ok;
}

////////////

parser_error_t _read_cro_cro_redeem_address(parser_context_t *c, cro_redeem_address_t *v) {
    CHECK_INPUT()
    uint8_t address_type;
    CHECK_PARSER_ERR(_readUInt8(c, &address_type))
    if (address_type != 0) {
        return parser_invalid_address;
    }
    GEN_DEF_READARRAY(CRO_REDEEM_ADDRESS_BYTES)
}

parser_error_t _read_staked_state_address(parser_context_t *c, cro_staked_state_address_t *v) {
    return _read_cro_cro_redeem_address(c, v);
}

parser_error_t _read_cro_nonce(parser_context_t *c, cro_nonce_t *v) {
    return _readUInt64(c, v);
}

parser_error_t _read_cro_coin(parser_context_t *c, cro_coin_t *v) {
    return _readUInt64(c, v);
}

parser_error_t _read_cro_staked_state_op_attributes(parser_context_t *c, cro_staked_state_op_attributes_t *v) {
    CHECK_INPUT()
    CHECK_PARSER_ERR(_readUInt8(c, &v->dummy_zero))
    if (v->dummy_zero != 0) {
        return parser_unexpected_value;
    }
    CHECK_PARSER_ERR(_readUInt8(c, &v->chain_hex_id))
    CHECK_PARSER_ERR(_readUInt64(c, &v->app_version))
    return parser_ok;
}

parser_error_t _read_cro_staked_state_address(parser_context_t *c, cro_staked_state_address_t *v) {
    return _read_staked_state_address(c, v);
}

parser_error_t _read_cro_validator_name(parser_context_t *c, cro_validator_name_t *v) {
    return _readBytes(c, v);
}

parser_error_t _read_cro_validator_security_contact(parser_context_t *c, cro_option_validator_security_contact_t *v) {
    CHECK_PARSER_ERR(_readUInt8(c, &v->hasValue))
    if (v->hasValue) {
        return _readBytes(c, &v->security_contact);
    }
    return parser_ok;
}

parser_error_t _read_cro_edd25519_pubkey(parser_context_t *c, cro_edd25519_pubkey_t *v) {
    GEN_DEF_READARRAY(32)
}

parser_error_t _read_cro_tendermint_validator_pubkey(parser_context_t *c, cro_tendermint_validator_pubkey_t *v) {
    CHECK_INPUT()
    CHECK_PARSER_ERR(_readUInt8(c, &v->keytype))
    if (v->keytype != 0) {
        return parser_unexpected_value;
    }
    return _read_cro_edd25519_pubkey(c, &v->edd25519_pubkey);
}

parser_error_t _read_cro_confidential_init(parser_context_t *c, cro_confidential_init_t *v) {
    return _readBytes(c, v);
}

parser_error_t _read_cro_council_node(parser_context_t *c, cro_council_node_t *v) {
    CHECK_INPUT()
    CHECK_PARSER_ERR(_readUInt8(c, &v->dummy_zero))
    if (v->dummy_zero != 0) {
        return parser_unexpected_value;
    }
    CHECK_PARSER_ERR(_read_cro_validator_name(c, &v->name));
    CHECK_PARSER_ERR(_read_cro_validator_security_contact(c, &v->security_contact));
    CHECK_PARSER_ERR(_read_cro_tendermint_validator_pubkey(c, &v->consensus_pubkey));
    CHECK_PARSER_ERR(_read_cro_confidential_init(c, &v->confidential_init));
    return parser_ok;
}

parser_error_t _read_cro_tx_out(parser_context_t *c, cro_tx_out_t *v) {
    CHECK_INPUT()
    CHECK_PARSER_ERR(_read_cro_cro_redeem_address(c, &v->address));
    CHECK_PARSER_ERR(_read_cro_coin(c, &v->value));
    CHECK_PARSER_ERR(_readUInt64(c, &v->valid_from));
    return parser_ok;
}

parser_error_t _read_cro_vector_tx_out(parser_context_t *c, cro_vector_tx_out_t *v) {
    GEN_DEF_READVECTOR(tx_out)
}

parser_error_t _read_cro_access_policy(parser_context_t *c, cro_access_policy_t *v) {
    CHECK_INPUT()
    CHECK_PARSER_ERR(_read_cro_tendermint_validator_pubkey(c, &v->key))
    CHECK_PARSER_ERR(_readBytes(c, &v->access));
    return parser_ok;
}

parser_error_t _read_cro_tx_attributes(parser_context_t *c, cro_tx_attributes_t *v) {
    CHECK_INPUT()
    CHECK_PARSER_ERR(_readUInt8(c, &v->chain_id));

    // FIXME: this is a fixed or variable length array?
    for (int i = 0; i < 10; i++) {
        CHECK_PARSER_ERR(_read_cro_access_policy(c, &v->allowed_view[i]));
    }

    CHECK_PARSER_ERR(_readUInt64(c, &v->app_version));
    return parser_ok;
}

////////////////////////////////////////

parser_error_t _read_unbond_stake_tx(parser_context_t *c, cro_unbond_tx_t *v) {
    CHECK_INPUT()
    CHECK_PARSER_ERR(_read_staked_state_address(c, &v->from_staked_account));
    CHECK_PARSER_ERR(_read_cro_nonce(c, &v->nonce));
    CHECK_PARSER_ERR(_read_cro_coin(c, &v->value));
    CHECK_PARSER_ERR(_read_cro_staked_state_op_attributes(c, &v->attributes));
    return parser_ok;
}

parser_error_t _read_unjail_tx(parser_context_t *c, cro_unjail_tx_t *v) {
    CHECK_INPUT()
    CHECK_PARSER_ERR(_read_cro_nonce(c, &v->nonce));
    CHECK_PARSER_ERR(_read_cro_staked_state_address(c, &v->address));
    CHECK_PARSER_ERR(_read_cro_staked_state_op_attributes(c, &v->attributes));
    return parser_ok;
}

parser_error_t _read_node_join_request_tx(parser_context_t *c, cro_node_join_request_tx_t *v) {
    CHECK_INPUT()
    CHECK_PARSER_ERR(_read_cro_nonce(c, &v->nonce));
    CHECK_PARSER_ERR(_read_cro_staked_state_address(c, &v->address));
    CHECK_PARSER_ERR(_read_cro_staked_state_op_attributes(c, &v->attributes));
    CHECK_PARSER_ERR(_read_cro_council_node(c, &v->node_meta));
    return parser_ok;
}

parser_error_t _read_withdraw_unbounded_tx(parser_context_t *c, cro_withdraw_unbonded_tx_t *v) {
    CHECK_INPUT()
    CHECK_PARSER_ERR(_read_cro_nonce(c, &v->nonce));
    CHECK_PARSER_ERR(_read_cro_vector_tx_out(c, &v->address));
    CHECK_PARSER_ERR(_read_cro_tx_attributes(c, &v->attributes));
    return parser_ok;
}

parser_error_t _read(parser_context_t *c, parser_tx_t *v) {
    CHECK_INPUT()

    zemu_log_stack("_read");

    // TODO: Add checks to always keep outset with bounds offset is valid
    CHECK_PARSER_ERR(_readUInt8(c, &v->txAuxEnumType))

    if (v->txAuxEnumType != CRO_TX_AUX_ENUM_PUBLIC_TX) {
        return parser_unexpected_type;
    }

    CHECK_PARSER_ERR(_readUInt8(c, &v->txType))

    switch (v->txType) {
        case CRO_TX_PUBLIC_AUX_UNBOND_STAKE: {
            CHECK_PARSER_ERR(_read_unbond_stake_tx(c, &v->cro_unbound_stake_tx))
            // FIXME: What do we do with the witness? It should not be there..
            return parser_ok;
        }
        case CRO_TX_PUBLIC_AUX_UNJAIL: {
            CHECK_PARSER_ERR(_read_unjail_tx(c, &v->cro_unjail_tx))
            return parser_ok;
        }
        case CRO_TX_PUBLIC_AUX_NODE_JOIN: {
            CHECK_PARSER_ERR(_read_node_join_request_tx(c, &v->cro_node_join_request_tx))
            return parser_ok;
        }
    }

    return parser_unexpected_type;
}

parser_error_t _validateTx(parser_context_t *c, const parser_tx_t *v) {
    // TODO: Complete this

    return parser_ok;
}

uint8_t _getNumItems(const parser_context_t *c, const parser_tx_t *v) {
    switch (v->txAuxEnumType) {
        case CRO_TX_AUX_ENUM_ENCLAVE_TX:
            return 0;
        case CRO_TX_AUX_ENUM_PUBLIC_TX: {
            switch (v->txType) {
                case CRO_TX_PUBLIC_AUX_UNBOND_STAKE:
                    return 6;
                case CRO_TX_PUBLIC_AUX_UNJAIL:
                    return 5;
                case CRO_TX_PUBLIC_AUX_NODE_JOIN:
                    return 9;
            }
        }
    }
    return 0;
}
