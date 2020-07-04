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

extern uint32_t hdPath[HDPATH_LEN_DEFAULT];

extern address_kind_e addressKind;

bool isTestnet();

void crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen);

__Z_INLINE void hash_blake3(uint8_t *message_digest, const uint8_t *message, uint16_t messageLen) {
    // Generate TX digest before signing
    zb_allocate(sizeof(blake3_hasher));
    blake3_hasher *ctx;
    zb_get((uint8_t **)&ctx);

    blake3_hasher_init(ctx);
    zb_check_canary();
    blake3_hasher_update(ctx, message, messageLen);
    zb_check_canary();
    blake3_hasher_finalize_seek(ctx, message_digest);
    zb_check_canary();

    zb_deallocate();
    zb_check_canary();
}

uint16_t crypto_fillAddress_secp256k1_transfer();
uint16_t crypto_fillAddress_secp256k1_staking();

uint16_t crypto_sign(uint8_t *signature,
                     uint16_t signatureMaxlen,
                     const uint8_t *message,
                     uint16_t messageLen);

#ifdef __cplusplus
}
#endif
