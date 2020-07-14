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

extern address_kind_e addressKind;

typedef struct {
    uint32_t value[HDPATH_LEN_DEFAULT];
} hdpath_t;

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)
extern hdpath_t NV_CONST N_hdpath_impl __attribute__ ((aligned(64)));
#define N_hdpath (*(NV_VOLATILE hdpath_t *)PIC(&N_hdpath_impl))
#endif

bool isTestnet();

void crypto_extractPublicKey(const hdpath_t *path, uint8_t *pubKey, uint16_t pubKeyLen);

__Z_INLINE void hash_blake3(uint8_t *message_digest, const uint8_t *message, uint16_t messageLen) {
    blake3_hasher ctx;
    blake3_hasher_init(&ctx);
    CHECK_APP_CANARY()
    blake3_hasher_update(&ctx, message, messageLen);
    CHECK_APP_CANARY()
    blake3_hasher_finalize_seek(&ctx, message_digest);
    CHECK_APP_CANARY()
}

uint16_t crypto_fillAddress_secp256k1_transfer();
uint16_t crypto_fillAddress_secp256k1_staking();

uint16_t crypto_sign(uint8_t *signature, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen);

#ifdef __cplusplus
}
#endif
