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
#pragma once

#include "parser_common.h"
#include "parser_txdef.h"
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

parser_error_t _readCompactInt(parser_context_t *c, compactInt_t *v);
parser_error_t _read_cro_tx_out(parser_context_t *c, cro_tx_out_t *v);
parser_error_t _read_cro_access_policy(parser_context_t *c, cro_access_policy_t *v);

// Checks that there are at least SIZE bytes available in the buffer
#define CTX_CHECK_AVAIL(CTX, SIZE) \
    if ( (CTX) == NULL || ((CTX)->offset + SIZE) > (CTX)->bufferLen) { return parser_unexpected_buffer_end; }

#define CTX_CHECK_AND_ADVANCE(CTX, SIZE) \
    CTX_CHECK_AVAIL((CTX), (SIZE))   \
    (CTX)->offset += (SIZE);

#define CHECK_INPUT() \
    if (v == NULL) { return parser_no_data; } \
    if (c == NULL || c->offset > c->bufferLen) { return parser_unexpected_buffer_end; }

#define GEN_DEF_READARRAY(SIZE) \
    v->_ptr = c->buffer + c->offset; \
    CTX_CHECK_AND_ADVANCE(c, SIZE) \
    return parser_ok;

#define GEN_DEC_READFIX_UNSIGNED(BITS) parser_error_t _readUInt ## BITS(parser_context_t *ctx, uint ## BITS ##_t *value)
#define GEN_DEF_READFIX_UNSIGNED(BITS) parser_error_t _readUInt ## BITS(parser_context_t *ctx, uint ## BITS ##_t *value) \
{                                                                                           \
    if (value == NULL)  return parser_no_data;                                              \
    *value = 0u;                                                                            \
    for(uint8_t i=0u; i < (BITS##u>>3u); i++, ctx->offset++) {                              \
        if (ctx->offset >= ctx->bufferLen) return parser_unexpected_buffer_end;             \
        *value += *(ctx->buffer + ctx->offset) << (8u*i);                                   \
    }                                                                                       \
    return parser_ok;                                                                       \
}

#define GEN_DEF_READVECTOR(TYPE)                                    \
    cro_##TYPE##_t dummy;                                           \
    compactInt_t clen;                                              \
    CHECK_PARSER_ERR(_readCompactInt(c, &clen));                    \
    CHECK_PARSER_ERR(_getValue(&clen, &v->_len));                   \
    v->_ptr = c->buffer + c->offset;                                \
    v->_lenBuffer = c->offset;                                      \
    for (uint64_t i = 0; i < v->_len; i++ ) CHECK_PARSER_ERR(_read_cro_##TYPE(c, &dummy));  \
    v->_lenBuffer = c->offset - v->_lenBuffer;                      \
    return parser_ok;

#define GEN_DEF_READVECTOR_ITEM(VEC, TYPE, INDEX, VALUE)            \
    parser_context_t ctx;                                           \
    parser_init(&ctx, VEC._ptr, VEC._lenBuffer);                    \
    compactInt_t clen;                                              \
    CHECK_PARSER_ERR(_readCompactInt(&ctx, &clen));                 \
    if ((INDEX) >= VEC._len) return parser_no_data;                 \
    for (uint64_t i = 0; i < VEC._len; i++ ) CHECK_PARSER_ERR(_read_cro_##TYPE(&ctx, &VALUE));  \
    return parser_ok;

#define GEN_DEF_TOSTRING_VECTOR(TYPE) \
    CLEAN_AND_CHECK()      \
    /* count number of pages, then output specific */       \
    *pageCount = 0;                                         \
    pd_##TYPE##_t tmp;                                      \
    parser_context_t ctx;                                   \
    uint8_t chunkPageCount;                                 \
    uint16_t currentPage, currentTotalPage = 0;             \
    /* We need to do it twice because there is no memory to keep intermediate results*/ \
    /* First count*/ \
    parser_init(&ctx, v->_ptr, v->_lenBuffer);\
    for (uint16_t i = 0; i < v->_len; i++) {\
        CHECK_ERROR(_read##TYPE(&ctx, &tmp));\
        CHECK_ERROR(_toString##TYPE(&tmp, outValue, outValueLen, 0, &chunkPageCount));\
        (*pageCount)+=chunkPageCount;\
    }\
    /* Then iterate until we can print the corresponding chunk*/ \
    parser_init(&ctx, v->_ptr, v->_lenBuffer);\
    for (uint16_t i = 0; i < v->_len; i++) {\
        CHECK_ERROR(_read##TYPE(&ctx, &tmp));\
        chunkPageCount = 1;\
        currentPage = 0;\
        while (currentPage < chunkPageCount) {\
            CHECK_ERROR(_toString##TYPE(&tmp, outValue, outValueLen, currentPage, &chunkPageCount));\
            if (currentTotalPage == pageIdx) { return parser_ok; } \
            currentPage++;\
            currentTotalPage++;\
        }\
    };\
    return parser_print_not_supported;

parser_error_t parser_init(parser_context_t *ctx, const uint8_t *buffer, uint16_t bufferSize);

parser_error_t _read(parser_context_t *c, parser_tx_t *v);

parser_error_t _validateTx(parser_context_t *c, const parser_tx_t *v);

uint8_t _getNumItems(const parser_context_t *c, const parser_tx_t *v);

#ifdef __cplusplus
}
#endif
