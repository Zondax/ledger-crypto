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

#pragma once

#include <zxerror.h>
#include "zxmacros.h"
#include <bech32.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <zxmacros.h>
#include "coin.h"
#include <stdbool.h>
#include <sigutils.h>
#include "blake3.h"
#include "blake3_impl.h"
#include "zbuffer.h"

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];

extern address_kind_e addressKind;

typedef struct {
    uint32_t value[HDPATH_LEN_DEFAULT];
} hdpath_t;

typedef struct {
    uint8_t publicKey[PK_LEN_SECP256K1_UNCOMPRESSED];
    char address[80];
    char SAFETY_GAP[15];
} __attribute__((packed)) crypto_addr_answer_t;

typedef struct {
    union {
        uint8_t hash_pk[32];
        struct {
            uint8_t address_padding[12];
            uint8_t address_pk[20];
        };
    };
    uint8_t merkle_tmp[1];
} __attribute__((packed)) crypto_addr_answer_tmp_t;

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];

__Z_INLINE bool isTestnet() {
    return hdPath[0] == HDPATH_0_TESTNET &&
           hdPath[1] == HDPATH_1_TESTNET;
}

__Z_INLINE uint8_t crypto_formatTransferAddress(const uint8_t *pk_X, char *out_address, uint8_t out_addrMaxLen) {
    crypto_addr_answer_tmp_t crypto_addr_answer_tmp;
    MEMZERO(&crypto_addr_answer_tmp, sizeof(crypto_addr_answer_tmp_t));

    MEMCPY(crypto_addr_answer_tmp.hash_pk, pk_X, 32);

    // Now hash public key with blake3
    blake3_hasher ctx;
    blake3_hasher_init(&ctx);
    // Merkle prefix
    blake3_hasher_update(&ctx, crypto_addr_answer_tmp.merkle_tmp, 1);
    zb_check_canary();
    // only X from secp256k1 1[X][Y]
    blake3_hasher_update(&ctx, pk_X, 32);
    zb_check_canary();
    blake3_hasher_finalize_seek(&ctx, crypto_addr_answer_tmp.hash_pk);
    zb_check_canary();

    const char *hrp = COIN_MAINNET_BECH32_HRP;
    if (isTestnet()) {
        hrp = COIN_TESTNET_BECH32_HRP;
    }

    // Encode last 20 bytes from the blake3 hash
    const zxerr_t err = bech32EncodeFromBytes(
            out_address, out_addrMaxLen,
            hrp,
            crypto_addr_answer_tmp.hash_pk, sizeof_field(crypto_addr_answer_tmp_t, hash_pk), 1
    );

    if (err != zxerr_ok) {
        return 0;
    }

    zb_check_canary();
    return strlen(out_address);
}

uint8_t crypto_fillAddress_secp256k1_transfer();
uint8_t crypto_fillAddress_secp256k1_staking();
void crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen);
uint16_t crypto_sign(uint8_t *signature, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen);

#ifdef __cplusplus
}
#endif
