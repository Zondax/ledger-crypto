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

#include "crypto.h"
#include "coin.h"
#include "zxmacros.h"
#include "rslib.h"
#include "bech32.h"
#include "blake3.h"

uint32_t hdPath[HDPATH_LEN_DEFAULT];

bool isTestnet() {
    return hdPath[0] == HDPATH_0_TESTNET &&
           hdPath[1] == HDPATH_1_TESTNET;
}

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)
#include "cx.h"

typedef struct {
    uint8_t publicKey[PK_LEN_SECP256K1_UNCOMPRESSED];
    char address[80];
} __attribute__((packed)) answer_t;

typedef struct {
    union{
        uint8_t hash_pk[32];
        struct {
            uint8_t address_padding[12];
            uint8_t address_pk[20];
        };
    };
} __attribute__((packed)) address_temp_t;

void keccak(uint8_t *out, size_t out_len, uint8_t *in, size_t in_len){
    cx_sha3_t sha3;
    cx_keccak_init(&sha3, 256);
    cx_hash((cx_hash_t*)&sha3, CX_LAST, in, in_len, out, out_len);
}

uint16_t crypto_fillAddress_secp256k1(uint8_t *buffer, uint16_t buffer_len) {
    MEMZERO(buffer, buffer_len);

    // We are very much stack limited, we let's use the output buffer 
    // to store temporary non-confidential data

    if (buffer_len < sizeof(answer_t) + sizeof(address_temp_t) + 4 + 4 /* separation */ ) {
        return 0;
    }

    // normally the output buffer is the G_io_apdu_buffer that is at least 250 bytes
    // [        .... output buffer....       ]
    // [answer_t][....][address_temp_t][..4..]

    answer_t *const answer = (answer_t *) buffer;
    address_temp_t *tmp = (address_temp_t *) (buffer + (buffer_len-sizeof(address_temp_t)-4));

    crypto_extractPublicKey(hdPath, answer->publicKey, sizeof_field(answer_t, publicKey));

    // Encode address depending on derivation path
    switch(hdPath[2]) {
        case HDPATH_2_ADDRESS_TRANSFER: {
            blake3_hasher ctx;
            blake3_hasher_init(&ctx);
            blake3_hasher_update(&ctx, buffer + 1, 32);
            blake3_hasher_finalize(&ctx, tmp->hash_pk, sizeof_field(address_temp_t, hash_pk));

            CHECK_APP_CANARY();

            const char *hrp = COIN_MAINNET_BECH32_HRP;
            if (isTestnet()) {
                hrp = COIN_TESTNET_BECH32_HRP;
            }

            const zxerr_t err = bech32EncodeFromBytes(
                answer->address, sizeof_field(answer_t, address),
                hrp,
                tmp->hash_pk, sizeof_field(address_temp_t, hash_pk)
            );

            if (err != zxerr_ok) {
                return 0;
            }

            CHECK_APP_CANARY();
            return PK_LEN_SECP256K1_UNCOMPRESSED + strlen(answer->address);
        }

        case HDPATH_2_ADDRESS_STAKING: {
            // https://github.com/crypto-com/chain/blob/65931c8fa67c30a90213d754c8903055a3d00013/chain-core/src/init/address.rs#L6-L11
            //! ### Generating Address
            //! There are three main steps to obtain chain address from public keys
            //! - Start with the public key. (64 bytes)
            //! - Take a Keccak-256 hash of public key. (Note: Keccak-256 is different from SHA3-256. [Difference between Keccak256 and SHA3-256](https://ethereum.stackexchange.com/questions/30369/difference-between-keccak256-and-sha3) ) (32 bytes)
            //! - Take the last 20 bytes of this Keccak-256 hash. Or, in other words, drop the first 12 bytes.
            //!   These 20 bytes are the address.
            keccak(tmp->hash_pk, 32, buffer + 1, PK_LEN_SECP256K1_UNCOMPRESSED-1);
            array_to_hexstr(answer->address, sizeof_field(answer_t, address), tmp->hash_pk, 20);

            CHECK_APP_CANARY();
            return PK_LEN_SECP256K1_UNCOMPRESSED + 40;
        }
            break;
        default:
            return 0;
    }
}

void crypto_extractPublicKey(const uint32_t path[HDPATH_LEN_DEFAULT], uint8_t *pubKey, uint16_t pubKeyLen) {
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];

    if (pubKeyLen < PK_LEN_SECP256K1_UNCOMPRESSED) {
        return;
    }

    BEGIN_TRY
    {
        TRY {
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       path,
                                       HDPATH_LEN_DEFAULT,
                                       privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);
            cx_ecfp_init_public_key(CX_CURVE_256K1, NULL, 0, &cx_publicKey);
            cx_ecfp_generate_pair(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1);
        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    // Format pubkey
    for (int i = 0; i < 32; i++) {
        pubKey[i] = cx_publicKey.W[64 - i];
    }
    cx_publicKey.W[0] = cx_publicKey.W[64] & 1 ? 0x03 : 0x02; // "Compress" public key in place
    if ((cx_publicKey.W[32] & 1) != 0) {
        pubKey[31] |= 0x80;
    }

    memcpy(pubKey, cx_publicKey.W, PK_LEN_SECP256K1_UNCOMPRESSED);
}

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) signature_t;

uint16_t crypto_sign(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen) {
    uint8_t tmp[CX_SHA256_SIZE];
    uint8_t message_digest[CX_SHA256_SIZE];

    cx_hash_sha256(message, messageLen, tmp, CX_SHA256_SIZE);
    cx_hash_sha256(tmp, CX_SHA256_SIZE, message_digest, CX_SHA256_SIZE);

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[32];
    int signatureLength;
    unsigned int info = 0;

    signature_t *const signature = (signature_t *) buffer;

    BEGIN_TRY
    {
        TRY
        {
            // Generate keys
            os_perso_derive_node_bip32(CX_CURVE_256K1,
                                       hdPath,
                                       HDPATH_LEN_DEFAULT,
                                       privateKeyData, NULL);

            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);

            // Sign
            signatureLength = cx_ecdsa_sign(&cx_privateKey,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            message_digest,
                                            CX_SHA256_SIZE,
                                            signature->der_signature,
                                            sizeof_field(signature_t, der_signature),
                                            &info);

        }
        FINALLY {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    err_convert_e err = convertDERtoRSV(signature->der_signature, info,  signature->r, signature->s, &signature->v);
    if (err != no_error) {
        // Error while converting so return length 0
        return 0;
    }

    // return actual size using value from signatureLength
    return sizeof_field(signature_t, r) + sizeof_field(signature_t, s) + sizeof_field(signature_t, v) + signatureLength;
}

#endif

