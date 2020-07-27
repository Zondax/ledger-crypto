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
#include "rslib.h"

uint32_t hdPath[HDPATH_LEN_DEFAULT];

#if defined(TARGET_NANOS) || defined(TARGET_NANOX)
#include "cx.h"
#endif

void keccak(uint8_t *out, size_t out_len, uint8_t *in, size_t in_len) {
    cx_sha3_t sha3;
    cx_keccak_init(&sha3, 256);
    cx_hash((cx_hash_t * ) & sha3, CX_LAST, in, in_len, out, out_len);
}

#define ADDRESS_BUFFER G_io_apdu_buffer
#define ADDRESS_BUFFER_LEN (IO_APDU_BUFFER_SIZE - 2)

uint8_t crypto_fillAddress_secp256k1_transfer() {
    MEMZERO(ADDRESS_BUFFER, ADDRESS_BUFFER_LEN);
    if (ADDRESS_BUFFER_LEN < sizeof(crypto_addr_answer_t) + sizeof(crypto_addr_answer_tmp_t)) {
        return 0;
    }

    crypto_addr_answer_t *const answer = (crypto_addr_answer_t *) ADDRESS_BUFFER;
    crypto_extractPublicKey(hdPath, answer->publicKey, sizeof_field(crypto_addr_answer_t, publicKey));

    const uint8_t *const pk_X = answer->publicKey + 1;

    const uint16_t address_len = crypto_formatTransferAddress(pk_X,
                                                              answer->address,
                                                              sizeof_field(crypto_addr_answer_t, address));
    if (address_len == 0) {
        return 0;
    }

    return PK_LEN_SECP256K1_UNCOMPRESSED + address_len;
}

uint8_t crypto_fillAddress_secp256k1_staking() {
    MEMZERO(ADDRESS_BUFFER, ADDRESS_BUFFER_LEN);

    // We are very much stack limited, we let's use the output buffer
    // to store temporary non-confidential data
    // normally the output buffer is the G_io_apdu_buffer that is at least 250 bytes
    // [   .... output buffer  |   260 bytes.... ]
    // [crypto_addr_answer_t 125][..15..][address_temp_t 32][  ]

    if (ADDRESS_BUFFER_LEN < sizeof(crypto_addr_answer_t) + sizeof(crypto_addr_answer_tmp_t)) {
        return 0;
    }

    crypto_addr_answer_t *const answer = (crypto_addr_answer_t *) ADDRESS_BUFFER;
    crypto_addr_answer_tmp_t *const tmp = (crypto_addr_answer_tmp_t *) (ADDRESS_BUFFER + sizeof(crypto_addr_answer_t));

    crypto_extractPublicKey(hdPath, answer->publicKey, sizeof_field(crypto_addr_answer_t, publicKey));

    // https://github.com/crypto-com/chain/blob/65931c8fa67c30a90213d754c8903055a3d00013/chain-core/src/init/address.rs#L6-L11
    //! ### Generating Address
    //! There are three main steps to obtain chain address from public keys
    //! - Start with the public key. (64 bytes)
    //! - Take a Keccak-256 hash of public key. (Note: Keccak-256 is different from SHA3-256. [Difference between Keccak256 and SHA3-256](https://ethereum.stackexchange.com/questions/30369/difference-between-keccak256-and-sha3) ) (32 bytes)
    //! - Take the last 20 bytes of this Keccak-256 hash. Or, in other words, drop the first 12 bytes.
    //!   These 20 bytes are the address.
    keccak(tmp->hash_pk, 32, answer->publicKey + 1, PK_LEN_SECP256K1_UNCOMPRESSED - 1);
    array_to_hexstr(answer->address, sizeof_field(crypto_addr_answer_t, address), tmp->address_pk, 20);
    CHECK_APP_CANARY();
    return PK_LEN_SECP256K1_UNCOMPRESSED + 40;
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
        TRY
        {
            os_perso_derive_node_bip32(CX_CURVE_256K1, hdPath, HDPATH_LEN_DEFAULT, privateKeyData, NULL);
            cx_ecfp_init_private_key(CX_CURVE_256K1, privateKeyData, 32, &cx_privateKey);
            cx_ecfp_init_public_key(CX_CURVE_256K1, NULL, 0, &cx_publicKey);
            cx_ecfp_generate_pair(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1);
        }
        FINALLY
        {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    memcpy(pubKey, cx_publicKey.W, PK_LEN_SECP256K1_UNCOMPRESSED);
}

typedef struct {
    uint8_t v;
    uint8_t r[32];
    uint8_t s[32];

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) signature_t;

uint16_t crypto_sign(uint8_t *buffer, uint16_t signatureMaxlen, const uint8_t *message, uint16_t messageLen) {
    zemu_log_stack("crypto_sign");

    // The digest has been precalculated in the output buffer
    uint8_t *message_digest = G_io_apdu_buffer;

    /// Now sign
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
                                            32,
                                            signature->der_signature,
                                            sizeof_field(signature_t, der_signature),
                                            &info);

        }
        FINALLY
        {
            MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
            MEMZERO(privateKeyData, 32);
        }
    }
    END_TRY;

    err_convert_e err = convertDERtoRSV(signature->der_signature, info, signature->r, signature->s, &signature->v);
    if (err != no_error) {
        // Error while converting so return length 0
        return 0;
    }

    // return actual size using value from signatureLength
    return sizeof_field(signature_t, r) + sizeof_field(signature_t, s) + sizeof_field(signature_t, v) + signatureLength;
}
