// ----------------------------------------------------------------------------
// Copyright 2020 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------
#ifndef _SUIT_PLATFORM_H_
#define _SUIT_PLATFORM_H_

#include "suit_parser.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
int suit_platform_do_run(const uint8_t *component_id);
int suit_platform_do_fetch(
    suit_reference_t *component_id,
    int digest_type,
    const uint8_t *digest_bytes,
    size_t digest_len,
    size_t image_size,
    const uint8_t* uri,
    size_t uri_len
);
int suit_platform_verify_image(
    suit_reference_t *component_id,
    int digest_type,
    const uint8_t* expected_digest,
    size_t image_size
);
int suit_platform_get_image_ref(
    suit_reference_t *component_id,
    const uint8_t **image
);
int suit_platform_verify_digest(
    const uint8_t *data, size_t data_len,
    const uint8_t *exp, size_t exp_len,
    int alg);


#ifdef __cplusplus
}
#endif

#endif // _SUIT_PLATFORM_H_