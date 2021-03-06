/*******************************************************************************
*   (c) 2018, 2019 Zondax GmbH
*   (c) 2016 Ledger
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

#include "app_main.h"

#include <string.h>
#include <os_io_seproxyhal.h>
#include <os.h>

#include "view.h"
#include "actions.h"
#include "tx.h"
#include "crypto.h"
#include "coin.h"
#include "zxmacros.h"

__Z_INLINE void handleGetAddrSecp256K1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    extractHDPath(rx, OFFSET_DATA);

    uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    if (requireConfirmation) {
        app_fill_address(addr_secp256k1);
        view_address_show();
        *flags |= IO_ASYNCH_REPLY;
        return;
    }

    *tx = app_fill_address(addr_secp256k1);
    THROW(APDU_CODE_OK);
}

void calculateDigest() {
    // we need to precalculate otherwise we won't have memory later on
    MEMZERO(G_io_apdu_buffer, sizeof(G_io_apdu_buffer));
    zb_check_canary();

    zemu_log_stack("calculateDigest");
    if (tx_get_buffer_length() > CRO_HEADER_SIZE) {
        // [ two bytes header ] [ tx payload ]
        // -----------------------------------
        //  2 bytes [....]
        // precalculate blake3 hash

        zemu_log_stack("hash_blake3");
        blake3_hasher ctx;
        blake3_hasher_init(&ctx);
        zb_check_canary();

        // We need to split in chunks
        const size_t total = tx_get_buffer_length() - CRO_HEADER_SIZE;
        size_t remain = total;

        while (remain > 0) {
            if (remain < BLAKE3_CHUNK_LEN) {
                zemu_log_stack("loop remainder");
                blake3_hasher_update(&ctx, tx_get_buffer() + CRO_HEADER_SIZE + (total - remain), remain);
                remain = 0;
            } else {
                zemu_log_stack("loop block");
                blake3_hasher_update(&ctx, tx_get_buffer() + CRO_HEADER_SIZE + (total - remain), BLAKE3_CHUNK_LEN);
                remain -= BLAKE3_CHUNK_LEN;
            }
        }

        zb_check_canary();
        blake3_hasher_finalize_seek(&ctx, G_io_apdu_buffer);
        zb_check_canary();
    }
}

__Z_INLINE void handleSignSecp256K1(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    zb_check_canary();
    calculateDigest();
    zb_check_canary();

    tx_parse_reset();
    const char *error_msg = tx_parse();

    if (error_msg != NULL) {
        tx_parse_reset();
        int error_msg_length = strlen(error_msg);
        MEMCPY(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    view_sign_show();
    *flags |= IO_ASYNCH_REPLY;
}

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    uint16_t sw = 0;

    BEGIN_TRY
    {
        TRY
        {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_VERSION: {
                    handle_getversion(flags, tx, rx);
                    break;
                }

                case INS_GET_ADDR_SECP256K1: {
                    handleGetAddrSecp256K1(flags, tx, rx);
                    break;
                }

                case INS_SIGN_SECP256K1: {
                    handleSignSecp256K1(flags, tx, rx);
                    break;
                }

                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET)
        {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e)
        {
            switch (e & 0xF000) {
                case 0x6000:
                case APDU_CODE_OK:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw;
            *tx += 2;
        }
        FINALLY
        {
        }
    }
    END_TRY;
}
