#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-err58-cpp"
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

#include <gmock/gmock.h>
#include <iostream>
#include <zxmacros.h>
#include <zxformat.h>
#include "blake3.h"

using ::testing::TestWithParam;
using ::testing::Values;

TEST(Blake3, minimal) {
    blake3_hasher ctx;
    char in[] = "zondax";
    uint8_t out[32];

    blake3_hasher_init(&ctx);
    blake3_hasher_update(&ctx, in, sizeof(in)-1);
    blake3_hasher_finalize_seek(&ctx, out);

    char out_hex[100];
    memset(out_hex, 0, sizeof(out_hex));

    array_to_hexstr(out_hex, sizeof(out_hex), out, sizeof(out));
    printf("%s\n", out_hex);
    EXPECT_STREQ(out_hex, "965ede7a053c1defa6786af08e0c9c20d41fe94433fa5d249de0d214e23909f8");
}

#pragma clang diagnostic pop
