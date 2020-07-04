/*******************************************************************************
*  (c) 2020 Zondax GmbH
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

#define CRO_HEADER_SIZE 2
#define CRO_WITNESS_SIZE 66
#define CRO_TX_AUX_ENUM_ENCLAVE_TX                       0
#define CRO_TX_AUX_ENUM_PUBLIC_TX                        1

#if defined(APP_VARIANT_CRO)
#include "coin_cro.h"
#elif defined(APP_VARIANT_DCRO)
#include "coin_dcro.h"
#else
#error "APP MODE IS NOT SUPPORTED"
#endif
