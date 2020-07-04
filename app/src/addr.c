/*******************************************************************************
*   (c) 2020 Zondax GmbH
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
#include "coin.h"
#include "zxerror.h"
#include "zxmacros.h"

zxerr_t addr_getNumItems(uint8_t *num_items) {
    *num_items = 2;
    zemu_log_stack("addr_getNumItems");
    return zxerr_ok;
}

zxerr_t addr_getItem(int8_t displayIdx,
                     char *outKey, uint16_t outKeyLen,
                     char *outVal, uint16_t outValLen,
                     uint8_t pageIdx, uint8_t *pageCount) {
    zemu_log_stack("addr_getItem");
    switch(displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "KEY %d %d %d", displayIdx, pageIdx, *pageCount);
            pageString(outVal, outValLen, "111111111111111111111111112222222222222222222223333333333333333333333333444444444444444444444444555555555555555555555", pageIdx, pageCount);
            return zxerr_ok;
        case 1:
            snprintf(outKey, outKeyLen, "KEY %d %d %d", displayIdx, pageIdx, *pageCount);
            pageString(outVal, outValLen, "1111111111111111111111111122222222", pageIdx, pageCount);
            return zxerr_ok;
        default:
            return zxerr_no_data;
    }
}
