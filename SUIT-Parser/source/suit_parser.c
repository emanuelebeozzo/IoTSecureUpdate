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
#include "suit_platform.h"
#include "suit_parser.h"
#include "pull_cbor.h"
#include "bm_cbor.h"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

// int key_to_var_index(int key) {
//     int rc;
//     if (key > 32 || key < 1 ) {
//         SET_ERROR(rc, CBOR_ERR_UNIMPLEMENTED, NULL);
//         return -rc;
//     }
//     key = key-1;
//     key = 1 << key;
//     if (!(key & SUIT_SUPPORTED_VARS)) {
//         SET_ERROR(rc, CBOR_ERR_UNIMPLEMENTED, NULL);
//         return -rc;
//     }
//     size_t supported = SUIT_SUPPORTED_VARS & ( key-1 );
//     size_t idx = 0;
//     for (idx = 0; supported; supported >>= 1) {
//         idx += supported & 1;
//     }
//     return idx;
// }

static int cbor_ref_to_val_check_type(suit_reference_t *ref, bm_cbor_value_t *val, uint8_t cbor_type)
{
    const uint8_t *p = ref->ptr;
    uint8_t cbor_b1 = *p;
    if ((cbor_b1 & CBOR_TYPE_MASK) != cbor_type) {
        // BM_CBOR_ERR_PRINT("Expected: %u Actual %u\n", (unsigned) cbor_type>>5, (unsigned)(**p & CBOR_TYPE_MASK)>>5);
        RETURN_ERROR(CBOR_ERR_TYPE_MISMATCH, p);
    }
    return bm_cbor_extractors[(cbor_b1 & CBOR_TYPE_MASK)>>5](&p, ref->end, val);
}


int key_to_reference(int key, suit_reference_t **ref, suit_parse_context_t* ctx) {
    //TODO: Check ACL
    if (key > 32 || key < 1 ) {
        RETURN_ERROR(CBOR_ERR_UNIMPLEMENTED, NULL);
    }
    key = key-1;
    key = 1 << key;
    if (!(key & SUIT_SUPPORTED_VARS)) {
        RETURN_ERROR(CBOR_ERR_UNIMPLEMENTED, NULL);
    }

    size_t supported = SUIT_SUPPORTED_VARS & ( key-1 );
    size_t idx = 0;
    for (idx = 0; supported; supported >>= 1) {
        idx += supported & 1;
    }
    *ref = &ctx->vars[0][idx];
    return CBOR_ERR_NONE;
}


int key_to_cbor_val_check_type(int key, bm_cbor_value_t *val, suit_parse_context_t* ctx, uint8_t cbor_type) {
    //TODO: Check ACL
    suit_reference_t *ref;
    int rc = key_to_reference(key, &ref, ctx);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    return cbor_ref_to_val_check_type(ref, val, cbor_type);
}

int suit_get_parameters(
    bm_cbor_value_t **values,
    const int* parameters,
    const uint8_t* cbor_types,
    suit_parse_context_t* ctx)
{
    size_t i;
    int rc = CBOR_ERR_NONE;
    for (i = 0; values[i] != NULL && rc == CBOR_ERR_NONE; i++) {
        rc = key_to_cbor_val_check_type(parameters[i], values[i], ctx, cbor_types[i]);
    }
    return rc;
}

static bm_cbor_value_t component_list;
CBOR_KPARSE_ELEMENT_LIST(common_elements_component_list,
    CBOR_KPARSE_ELEMENT(SUIT_COMMON_DEPENDENCIES, CBOR_TYPE_LIST, NULL, "Dependencies"),
    CBOR_KPARSE_ELEMENT_EX(SUIT_COMMON_COMPONENTS, CBOR_TYPE_LIST, &component_list, "Components"),
    CBOR_KPARSE_ELEMENT_C_BWRAP_KV(SUIT_COMMON_SEQUENCE, CBOR_TYPE_LIST, NULL, "common-sequence"),

);
CBOR_KPARSE_ELEMENT_LIST(common_entry_elements_component_list,
    CBOR_KPARSE_ELEMENT_C_BWRAP(0, CBOR_TYPE_MAP, &common_elements_component_list, "Common Block ex")
);

int suit_get_component_id(suit_reference_t *id, suit_parse_context_t *ctx, bm_cbor_uint_t idx) {
    if (idx == (uint16_t)-1) {
        RETURN_ERROR(SUIT_MFST_ERR_MANIFEST_ENCODING, NULL);
    }
    const uint8_t *p = ctx->common.ptr;
    const uint8_t *end = ctx->common.end;
    int rc = pull_cbor_handle_keyed_element(&p, end, ctx, &common_entry_elements_component_list.elements, 0);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    // Now get the indexed component ID
    p = component_list.ref.ptr;
    for (int i = 0; i < component_list.ref.uival && i < idx; i++) {
        rc = bm_cbor_skip(&p, end);
        if (rc != CBOR_ERR_NONE) {
            return rc;
        }
    }
    bm_cbor_value_t val;
    rc = bm_cbor_check_type_extract_ref(&p, end, &val, CBOR_TYPE_LIST);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    id->ptr = val.cbor_start;
    id->end = end;
    return rc;
}
int suit_get_current_component_id(suit_reference_t *id, suit_parse_context_t *ctx)
{
    return suit_get_component_id(id, ctx, ctx->cidx);
}

int Signature1_val_cat(suit_parse_context_t* ctx, bm_cbor_value_t *val) {
    size_t clen = val->ref.uival + val->ref.ptr - val->cbor_start;
    if (ctx->Sign1.offset + clen > sizeof(ctx->Sign1.Signature1)) {
        RETURN_ERROR(SUIT_ERR_SIG, val->cbor_start);
    }
    memcpy(ctx->Sign1.Signature1 + ctx->Sign1.offset, val->cbor_start, clen);
    ctx->Sign1.offset += clen;
    return CBOR_ERR_NONE;
}
int Signature1_ref_cat(suit_parse_context_t* ctx, suit_reference_t *ref) {
    const uint8_t *p = ref->ptr;
    int rc = bm_cbor_skip(&p, ref->end);    
    size_t clen = (p - ref->ptr);
    if (ctx->Sign1.offset + clen > sizeof(ctx->Sign1.Signature1)) {
        RETURN_ERROR(SUIT_ERR_SIG, ref->ptr);
    }
    memcpy(ctx->Sign1.Signature1 + ctx->Sign1.offset, ref->ptr, clen);
    ctx->Sign1.offset += clen;
    return CBOR_ERR_NONE;
}
void suit_set_reference(suit_reference_t *ref, const uint8_t* end, bm_cbor_value_t *val) {
    ref->ptr = val->cbor_start;
    ref->end = end;
}

PARSE_HANDLER(cose_sign1_alg_handler) {
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    sctx->Sign1.alg = val->i;
    return 0;
}
PARSE_HANDLER(cose_sign1_kid_handler) {
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    suit_set_reference(&sctx->Sign1.kid, end, val);
    return 0;
}
PARSE_HANDLER(cose_sign1_payload_handler) {
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    // HACK: Add an empty bytestring for External AAD
    uint8_t emptybstr[]="\x40";
    suit_reference_t empty = {.ptr = emptybstr, .end=emptybstr+sizeof(emptybstr)};
    int rc = Signature1_ref_cat(sctx, &empty);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    return Signature1_ref_cat(sctx, &sctx->manifest_digest);
}
PARSE_HANDLER(cose_sign1_signature_handler) {
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    //TODO: Check for overflow.
    int rc = COSEAuthVerify(
        sctx->Sign1.Signature1, sctx->Sign1.offset,
        val->ref.ptr, val->ref.uival,
        sctx->Sign1.kid.ptr, sctx->Sign1.kid.end - sctx->Sign1.kid.ptr,
        sctx->Sign1.alg);
    if (rc != CBOR_ERR_NONE) {
        bm_cbor_get_err_info()->ptr = *p;
    }
    return rc;
}

CBOR_KPARSE_ELEMENT_LIST(cose_sign1_protected_elements,
    CBOR_KPARSE_ELEMENT_H(COSE_HDR_ALG, CBOR_TYPE_NINT, cose_sign1_alg_handler, "COSE Sign1 alg"),
);

CBOR_KPARSE_ELEMENT_LIST(cose_sign1_unprotected_elements,
    CBOR_KPARSE_ELEMENT_H(COSE_HDR_KID, CBOR_TYPE_NINT, cose_sign1_kid_handler, "COSE Sign1 kid"),
);

CBOR_KPARSE_ELEMENT_LIST(cose_sign1_protected,
    CBOR_KPARSE_ELEMENT_C(0, CBOR_TYPE_MAP, &cose_sign1_protected_elements, "COSE Sign1 protected"),
);

PARSE_HANDLER(cose_sign1_protected_handler) {
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    int rc = Signature1_val_cat(ctx, val);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    // sctx->Sign1.offset += val->ref.uival;
    end = val->ref.ptr + val->ref.uival;
    return pull_cbor_handle_keyed_element(p, end, ctx, &cose_sign1_protected.elements, 0);
}

CBOR_KPARSE_ELEMENT_LIST(cose_sign1_elements,
    CBOR_KPARSE_ELEMENT_H(0, CBOR_TYPE_BSTR, &cose_sign1_protected_handler, "COSE Sign1 Protected"),
    CBOR_KPARSE_ELEMENT_C(1, CBOR_TYPE_MAP, &cose_sign1_unprotected_elements, "COSE Sign1 Unprotected"),
    CBOR_KPARSE_ELEMENT_H(2, CBOR_TYPE_SIMPLE, &cose_sign1_payload_handler, "COSE Sign1 Payload"),
    CBOR_KPARSE_ELEMENT_H(3, CBOR_TYPE_BSTR, &cose_sign1_signature_handler, "COSE Sign1 Signature"),
);

PARSE_HANDLER(handle_cose_sign1) {
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    // Actual length filled in later.
    memcpy(sctx->Sign1.Signature1, "\x84\x6ASignature1", SUIT_SIGNATURE1_CONTEXT_LEN+2);
    sctx->Sign1.offset = SUIT_SIGNATURE1_CONTEXT_LEN+2;
    return pull_cbor_handle_list(p, end, ctx, &cose_sign1_elements.elements, val->ref.uival);
}

CBOR_KPARSE_ELEMENT_LIST(cose_auth_elements,
    CBOR_KPARSE_ELEMENT_H(COSE_SIGN1_TAG, CBOR_TYPE_LIST, handle_cose_sign1, "COSE Sign 1"),
);

CBOR_KPARSE_ELEMENT_LIST(auth_list_elements,
    CBOR_KPARSE_ELEMENT_C_BWRAP(0, CBOR_TYPE_TAG, &cose_auth_elements, "Authorisation list"),
);

// CBOR_KPARSE_ELEMENT_A_BWRAP(SUIT_ENVELOPE_AUTH, CBOR_TYPE_LIST, &auth_list_elements, "Authorisation"),
PARSE_HANDLER(auth_list_handler)
{
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    bm_cbor_value_t digest;

    if (val->ref.uival < 2 ) {
        // ERROR: Unsigned manifest
        RETURN_ERROR(SUIT_ERR_SIG, *p);
    }

    // Extract the wrapped digest
    int rc = bm_cbor_check_type_extract_ref(p, end, &digest, CBOR_TYPE_BSTR);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    sctx->manifest_digest.ptr = digest.cbor_start;
    sctx->manifest_digest.end = digest.ref.ptr + digest.ref.uival;
    *p = sctx->manifest_digest.end;

    return pull_cbor_handle_array(p, end, ctx, &auth_list_elements.elements, val->ref.uival-1);
}

PARSE_HANDLER(version_handler)
{
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    if (val->u != SUIT_SUPPORTED_VERSION) {
        RETURN_ERROR(SUIT_ERR_VERSION, *p);
    }
    return CBOR_ERR_NONE;
}

PARSE_HANDLER(suit_common_handler) {
    //TODO: use the bstr better here.
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    suit_set_reference(&sctx->common, end, val);
    return 0;
}

int check_id(const int key, const uint8_t *id, suit_parse_context_t *ctx, int failcode) {
    suit_reference_t *ref;
    int rc = key_to_reference(key, &ref, ctx);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    const uint8_t *p = ref->ptr;
    bm_cbor_value_t val;
    rc = bm_cbor_check_type_extract_ref(&p, ref->end, &val, CBOR_TYPE_BSTR);
    if (rc != CBOR_ERR_NONE || val.ref.uival != UUID_SIZE) {
        RETURN_ERROR(failcode, p);
    }
    rc = memcmp(id, val.ref.ptr, UUID_SIZE);
    if (rc != 0) {
        SET_ERROR(rc, failcode, p);
    }
    return rc;
}

PARSE_HANDLER(vendor_match_handler)
{
    int rc = check_id(key, vendor_id, ctx, SUIT_MFST_ERR_VENDOR_MISMATCH);
    if (rc != CBOR_ERR_NONE) {
        bm_cbor_get_err_info()->ptr = *p;
    }
    return rc;
}
PARSE_HANDLER(class_match_handler)
{
    int rc = check_id(key, class_id, ctx, SUIT_MFST_ERR_CLASS_MISMATCH);
    if (rc != CBOR_ERR_NONE) {
        bm_cbor_get_err_info()->ptr = *p;
    }
    return rc;
}

static bm_cbor_value_t exp_digest_alg;
static bm_cbor_value_t exp_digest;
CBOR_KPARSE_ELEMENT_LIST(suit_digest_elements,
    CBOR_KPARSE_ELEMENT_EX(0, CBOR_TYPE_NINT, &exp_digest_alg, "SUIT Digest Algorithm"),
    CBOR_KPARSE_ELEMENT_EX(1, CBOR_TYPE_BSTR, &exp_digest, "SUIT Digest Bytes"),
);
CBOR_KPARSE_ELEMENT_LIST(suit_digest_container,
    CBOR_KPARSE_ELEMENT_C(0, CBOR_TYPE_LIST, &suit_digest_elements, "SUIT Digest"),
    CBOR_KPARSE_ELEMENT_C_BWRAP(0, CBOR_TYPE_LIST, &suit_digest_elements, "SUIT Digest Wrapped"),
);

int suit_extract_digest(const suit_reference_t *suit_digest, bm_cbor_value_t *digest_alg, bm_cbor_value_t *digest)
{
    const uint8_t *p = suit_digest->ptr;
    const uint8_t *end = suit_digest->end;
    int rc = pull_cbor_handle_keyed_element(&p, end, NULL, &suit_digest_container.elements, 0);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    digest_alg->i = exp_digest_alg.i;
    digest->ref.ptr = exp_digest.ref.ptr;
    digest->ref.uival = exp_digest.ref.uival;
    return CBOR_ERR_NONE;
}

int suit_check_digest(suit_reference_t* expected_digest, const uint8_t *data, size_t data_len)
{
    const uint8_t *p = expected_digest->ptr;
    const uint8_t *end = expected_digest->end;
    int rc = pull_cbor_handle_keyed_element(&p, end, NULL, &suit_digest_container.elements, 0);
    // int rc = suit_process_kv(&p, end, NULL, &suit_digest_elements.elements, CBOR_TYPE_LIST);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    //printf("Data: %c\n len: %lu\n", *data, data_len);
    return suit_platform_verify_digest(
        data, data_len, 
        exp_digest.ref.ptr, exp_digest.ref.uival,
        exp_digest_alg.i);
}


PARSE_HANDLER(image_match_handler)
{
    // suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    // bm_cbor_value_t size, digest, uri;
    // bm_cbor_value_t *values[] = {&size, &digest, &uri, NULL};
    // const uint8_t cbor_types[] = {CBOR_TYPE_UINT, CBOR_TYPE_LIST, CBOR_TYPE_TSTR};
    // const int parameters[] = {SUIT_PARAMETER_IMAGE_SIZE, SUIT_PARAMETER_IMAGE_DIGEST, SUIT_PARAMETER_URI};
    // int rc = suit_get_parameters(values, parameters, cbor_types, sctx);

    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    uint64_t image_size;
    suit_reference_t *sz;
    suit_reference_t component_id;
    int rc = key_to_reference(SUIT_PARAMETER_IMAGE_SIZE, &sz, ctx);
    const uint8_t *np = sz->ptr;
    rc = rc ? rc : bm_cbor_get_uint(&np, sz->end, &image_size);
    rc = rc ? rc : suit_get_current_component_id(&component_id, sctx);
    const uint8_t *image;
    rc = rc ? rc : suit_platform_get_image_ref(&component_id, &image);
    suit_reference_t *exp;
    rc = rc ? rc : key_to_reference(SUIT_PARAMETER_IMAGE_DIGEST, &exp, ctx);
    rc = rc ? rc : suit_check_digest(exp, image, image_size);
    if (rc != CBOR_ERR_NONE) {
        bm_cbor_get_err_info()->ptr = *p;
    }
    return rc;
}

//TODO: multiple components
PARSE_HANDLER(parameter_handler) {
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    suit_reference_t *ref;
    int rc = key_to_reference(key, &ref, ctx);
    if (rc != CBOR_ERR_NONE) {
        bm_cbor_get_err_info()->ptr = *p;
        return rc;
    }
    ref->ptr = val->cbor_start;
    ref->end = end;
    if (key == SUIT_PARAMETER_IMAGE_DIGEST) {
        printf("Stored %p to key %d (%u bytes)\n", val->ref.ptr, key, (unsigned)val->ref.uival);
    }
    *p = val->cbor_start;
    return bm_cbor_skip(p, end);
}
//TODO: This could be optimised: each parameter uses same handler, so this structure is too big
CBOR_KPARSE_ELEMENT_LIST(parameter_handlers,
    CBOR_KPARSE_ELEMENT_H(SUIT_PARAMETER_VENDOR_ID, CBOR_TYPE_BSTR, parameter_handler, "vendor-id"),
    CBOR_KPARSE_ELEMENT_H(SUIT_PARAMETER_CLASS_ID, CBOR_TYPE_BSTR, parameter_handler, "class-id"),
    CBOR_KPARSE_ELEMENT_H_BWRAP(SUIT_PARAMETER_IMAGE_DIGEST, CBOR_TYPE_LIST, parameter_handler, "img-digest"),
    CBOR_KPARSE_ELEMENT_H(SUIT_PARAMETER_IMAGE_SIZE, CBOR_TYPE_UINT, parameter_handler, "img-size"),
    CBOR_KPARSE_ELEMENT_H(SUIT_PARAMETER_URI, CBOR_TYPE_TSTR, parameter_handler, "uri"),
    CBOR_KPARSE_ELEMENT_H(SUIT_PARAMETER_SOURCE_COMPONENT, CBOR_TYPE_UINT, parameter_handler, "source-comp"),
);

PARSE_HANDLER(image_fetch_handler)
{
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    bm_cbor_value_t size, uri;
    bm_cbor_value_t *values[] = {&size, &uri, NULL};
    const uint8_t cbor_types[] = {CBOR_TYPE_UINT, CBOR_TYPE_TSTR};
    const int parameters[] = {SUIT_PARAMETER_IMAGE_SIZE, SUIT_PARAMETER_URI};
    int rc = suit_get_parameters(values, parameters, cbor_types, sctx);
    if (rc != CBOR_ERR_NONE) {
        // bm_cbor_get_err_info()->ptr = *p;
        return rc;
    }
    suit_reference_t component_id;
    rc = suit_get_current_component_id(&component_id, sctx);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    suit_reference_t *digest;
    rc = key_to_reference(SUIT_PARAMETER_IMAGE_DIGEST, &digest, ctx);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    bm_cbor_value_t digest_alg, digest_bytes;
    rc = suit_extract_digest(digest, &digest_alg, &digest_bytes);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    rc = suit_platform_do_fetch(&component_id, digest_alg.i, digest_bytes.ref.ptr, digest_bytes.ref.uival, size.u, uri.ref.ptr, uri.ref.uival);
    if (rc != CBOR_ERR_NONE) {
        bm_cbor_get_err_info()->ptr = *p;
    }
    return rc;
}

PARSE_HANDLER(invoke_handler)
{
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    suit_reference_t component_id;
    int rc = suit_get_current_component_id(&component_id, sctx);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }
    return suit_platform_do_run(component_id.ptr);
}

CBOR_KPARSE_ELEMENT_LIST(sequence_elements,
    CBOR_KPARSE_ELEMENT_H(SUIT_CONDITION_VENDOR_ID, CBOR_TYPE_UINT, vendor_match_handler, "vendor-match"),
    CBOR_KPARSE_ELEMENT_H(SUIT_CONDITION_CLASS_ID, CBOR_TYPE_UINT, class_match_handler, "class-match"),
    CBOR_KPARSE_ELEMENT_H(SUIT_CONDITION_IMAGE_MATCH, CBOR_TYPE_UINT, NULL, "image-match"), // TODO: review this
    // CBOR_KPARSE_ELEMENT(SUIT_DIRECTIVE_SET_COMP_IDX, CBOR_TYPE_UINT, set_component_handler),
    CBOR_KPARSE_ELEMENT_C(SUIT_DIRECTIVE_SET_PARAMETERS, CBOR_TYPE_MAP, &parameter_handlers, "set-parameters"),
    CBOR_KPARSE_ELEMENT_C(SUIT_DIRECTIVE_OVERRIDE_PARAMETERS, CBOR_TYPE_MAP, &parameter_handlers, "override-parameters"),
    CBOR_KPARSE_ELEMENT_H(SUIT_DIRECTIVE_FETCH, CBOR_TYPE_UINT, image_fetch_handler, "Fetch"),
    CBOR_KPARSE_ELEMENT_H(SUIT_DIRECTIVE_INVOKE, CBOR_TYPE_UINT, invoke_handler, "invoke"),
);


CBOR_KPARSE_ELEMENT_LIST(common_elements,
    CBOR_KPARSE_ELEMENT(SUIT_COMMON_DEPENDENCIES, CBOR_TYPE_LIST, NULL, "Dependencies"),
    CBOR_KPARSE_ELEMENT(SUIT_COMMON_COMPONENTS, CBOR_TYPE_LIST, NULL, "Components"),
    CBOR_KPARSE_ELEMENT_C_BWRAP_KV(SUIT_COMMON_SEQUENCE, CBOR_TYPE_LIST, &sequence_elements, "common-sequence"),
);

CBOR_KPARSE_ELEMENT_LIST(common_entry_elements,
    CBOR_KPARSE_ELEMENT_C_BWRAP(0, CBOR_TYPE_MAP, &common_elements, "Common Block")
);

PARSE_HANDLER(suit_sequence_handler) {
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    // clear vars
    memset(sctx->vars, 0, sizeof(sctx->vars));
    const uint8_t *cp = sctx->common.ptr;
    const uint8_t *cend = sctx->common.end;
    int rc = pull_cbor_handle_keyed_element(&cp, cend, ctx, &common_entry_elements.elements, 0);
    if (rc == CBOR_ERR_NONE) {
        printf("Sequence Key: %d\n", key);
        rc = pull_cbor_handle_pairs(p, end, ctx, &sequence_elements.elements, val->ref.uival);
    }
    return rc;
}

// Text entry handler
PARSE_HANDLER(text_handler) {
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    // Verify it's a list with algorithm and digest bytes
    if (val->ref.uival != 2) { // Should have 2 elements: algorithm-id and digest-bytes
        bm_cbor_get_err_info()->ptr = *p;
        printf("Text digest should have 2 elements\n");
        return CBOR_ERR_UNIMPLEMENTED;
    }
    
    // Parse algorithm ID (first element)
    bm_cbor_value_t alg;
    int rc = bm_cbor_check_type_extract_ref(p, end, &alg, CBOR_TYPE_NINT);
    if (rc != CBOR_ERR_NONE) {
        bm_cbor_get_err_info()->ptr = *p;
        printf("Text digest algorithm should be SHA-256\n");
        return CBOR_ERR_UNIMPLEMENTED;
    }

    // Parse digest bytes (second element) 
    bm_cbor_value_t digest;
    rc = bm_cbor_check_type_extract_ref(p, end, &digest, CBOR_TYPE_BSTR);
    if (rc != CBOR_ERR_NONE) {
        bm_cbor_get_err_info()->ptr = *p;
        return rc;
    }

    // Store digest info if needed
    // sctx->text_digest.ptr = digest.ref.ptr;
    // sctx->text_digest.end = digest.ref.ptr + digest.ref.uival;

    printf("Text digest algorithm: SHA-256\n");
    printf("Text digest bytes: ");
    for (size_t i = 0; i < digest.ref.uival; i++) {
        printf("%02x", digest.ref.ptr[i]);
    }
    printf("\n");

    // Update pointer to skip the digest bytes
    *p = digest.ref.ptr + digest.ref.uival;
    
    // Validate we haven't exceeded the buffer
    if (*p > end) {
        return CBOR_ERR_OVERRUN;
    }

    return CBOR_ERR_NONE;
}

// First add handlers to print the values
PARSE_HANDLER(cert_man_property_handler) {
    printf("Property ID: ");
    for(size_t i = 0; i < val->ref.uival; i++) {
        printf("%02x", val->ref.ptr[i]);
    }
    printf("\n");
    return 0;
}

PARSE_HANDLER(cert_man_language_handler) {
    printf("Language ID: ");
    for (size_t i = 0; i < val->ref.uival; i++) {
        printf("%c", val->ref.ptr[i]); 
    }
    printf("\n");
    
    // Update parser position to consume the text string
    *p = val->ref.ptr + val->ref.uival;
    return CBOR_ERR_NONE;
}

PARSE_HANDLER(cert_man_proof_cert_handler) {
    printf("Proof Certificate: ");
    for(size_t i = 0; i < val->ref.uival; i++) {
        printf("%c", val->ref.ptr[i]);
    }
    *p = val->ref.ptr + val->ref.uival;
    printf("\n");
    return 0;
}

PARSE_HANDLER(cert_man_locality_handler) {
    printf("Locality Constraint: %lu\n", (unsigned long)val->u);
    return 0;
}

// TODO: fix it, doesn't work
PARSE_HANDLER(cert_man_component_handler) {
    printf("Component ID: ");

    // Get list value since we already know it's a list
    bm_cbor_value_t list_val = *val;
    const uint8_t *list_p = list_val.ref.ptr;
    const uint8_t *list_end = list_val.ref.ptr + list_val.ref.uival;

    // Extract the byte string from the array
    bm_cbor_value_t comp_id;
    int rc = bm_cbor_check_type_extract_ref(&list_p, list_end, &comp_id, CBOR_TYPE_BSTR);
    if (rc != CBOR_ERR_NONE) {
        return rc;
    }

    // Print component ID bytes
    for (size_t i = 0; i < comp_id.ref.uival; i++) {
        printf("%02x", comp_id.ref.ptr[i]);
    }
    printf("\n");
    
    // Update main parser position
    *p = list_val.ref.ptr + list_val.ref.uival;
    
    return CBOR_ERR_NONE;
}

//TODO: improve this, check on the end of the elements not enforced
PARSE_HANDLER(cert_man_verification_servers_handler) {
    // Get the list item count to parse through
    const uint8_t *ptr = val->ref.ptr;
    const uint8_t *end_ptr = val->ref.ptr + val->ref.uival;
    
    //printf("ptr: %p, end: %p\n", ptr, end_ptr);

    // Parse each map in the list
    //printf("Number of verification servers: %lu\n", (unsigned long)val->ref.uival);
    for (size_t i = 0; i < val->ref.uival; i++) {
        bm_cbor_value_t server_map;
        int rc = bm_cbor_check_type_extract_ref(&ptr, end, &server_map, CBOR_TYPE_MAP);
        if (rc != CBOR_ERR_NONE) {
            return rc;
        }

        // Parse through the map contents
        const uint8_t *map_ptr = ptr;
        size_t remaining_pairs = server_map.ref.uival;
        //printf("Remaining pairs: %lu\n", (unsigned long)remaining_pairs);
        
        while (remaining_pairs > 0) {
            bm_cbor_value_t key_val;
            rc = bm_cbor_get_uint(&map_ptr, end, &key_val.u);
            if (rc != CBOR_ERR_NONE) {
                return rc;
            }

            if (key_val.u == 1) { // 'uri' key
                bm_cbor_value_t uri_val;
                rc = bm_cbor_check_type_extract_ref(&map_ptr, end, &uri_val, CBOR_TYPE_TSTR);
                if (rc != CBOR_ERR_NONE) {
                    return rc;
                }
                printf("Verification Server URI: %.*s\n", (int)uri_val.ref.uival, (char *)uri_val.ref.ptr);
                map_ptr = uri_val.ref.ptr + uri_val.ref.uival;
            } else {
                rc = bm_cbor_skip(&map_ptr, end);
                if (rc != CBOR_ERR_NONE) {
                    return rc;
                }
            }
            remaining_pairs--;
        }
        ptr = map_ptr;
    }

    *p = ptr;
    return CBOR_ERR_NONE;
}


// Update element list to use the handlers
CBOR_KPARSE_ELEMENT_LIST(cert_manifest_elements,
    CBOR_KPARSE_ELEMENT_H(SUIT_CERT_MAN_PROPERTY_ID, CBOR_TYPE_BSTR, cert_man_property_handler, "Property ID"),
    CBOR_KPARSE_ELEMENT_H(SUIT_CERT_MAN_LANGUAGE_ID, CBOR_TYPE_TSTR, cert_man_language_handler, "Language ID"),
    CBOR_KPARSE_ELEMENT_H(SUIT_CERT_MAN_COMPONENT_ID, CBOR_TYPE_LIST, NULL, "Component ID"),  // Fix this
    CBOR_KPARSE_ELEMENT_H(SUIT_CERT_MAN_PROOF_CERTIFICATE, CBOR_TYPE_TSTR, cert_man_proof_cert_handler, "Proof Certificate"), 
    CBOR_KPARSE_ELEMENT_H(SUIT_CERT_MAN_LOCALITY_CONSTRAINT, CBOR_TYPE_UINT, cert_man_locality_handler, "Locality Constraint"),
    CBOR_KPARSE_ELEMENT_H(SUIT_CERT_MAN_VERIFICATION_SERVERS, CBOR_TYPE_LIST, cert_man_verification_servers_handler, "Verification Servers")
);


PARSE_HANDLER(cert_manifest_handler) {
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;

    const uint8_t list_size = val->ref.uival;
    printf("Number of certification manifest entry: %lu\n", (unsigned long)list_size);
    
    // First unwrap the BSTR if present
    bm_cbor_value_t bstr_wrap;
    int rc = bm_cbor_check_type_extract_ref(p, end, &bstr_wrap, CBOR_TYPE_BSTR);
    if (rc == CBOR_ERR_NONE) {
        // Update pointers to BSTR content
        end = bstr_wrap.ref.ptr + bstr_wrap.ref.uival;
        *p = bstr_wrap.ref.ptr;
    }

    // Process the map directly - we expect a map containing the certification fields
    //rc = pull_cbor_process_kv(p, end, ctx, &cert_manifest_elements.elements, CBOR_TYPE_MAP);
    //if (rc != CBOR_ERR_NONE) {
    //    return rc;
    //}
    
    const uint8_t *list_ptr = *p;
    const uint8_t *list_end = end;

    // Process each map in the list
    for (size_t i = 0; i < list_size; i++) {
        rc = pull_cbor_process_kv(&list_ptr, list_end, ctx, &cert_manifest_elements.elements, CBOR_TYPE_MAP);
        if (rc != CBOR_ERR_NONE) {
            return rc;
        }
    }

    return CBOR_ERR_NONE;
}

CBOR_KPARSE_ELEMENT_LIST(manifest_elements,
    CBOR_KPARSE_ELEMENT_H(SUIT_MANIFEST_VERSION, CBOR_TYPE_UINT, version_handler, "SUIT Structure Version"),
    CBOR_KPARSE_ELEMENT_H(SUIT_MANIFEST_SEQUCENCE_NUMBER, CBOR_TYPE_UINT, NULL, "SUIT Sequence Number"),
    CBOR_KPARSE_ELEMENT_H(SUIT_MANIFEST_COMMON, CBOR_TYPE_BSTR, suit_common_handler, "SUIT Common"),
    CBOR_KPARSE_ELEMENT_H_BWRAP(SUIT_MANIFEST_INSTALL, CBOR_TYPE_LIST, &suit_sequence_handler, "Install sequence"),
    CBOR_KPARSE_ELEMENT_H_BWRAP(SUIT_MANIFEST_VALIDATE, CBOR_TYPE_LIST, &suit_sequence_handler, "Validate sequence"),
    CBOR_KPARSE_ELEMENT_H_BWRAP(SUIT_MANIFEST_RUN, CBOR_TYPE_LIST, &suit_sequence_handler, "Run sequence"),
    CBOR_KPARSE_ELEMENT_H(SUIT_MANIFEST_TEXT, CBOR_TYPE_LIST, text_handler, "Text Digest"), 
    CBOR_KPARSE_ELEMENT_H_BWRAP(SUIT_MANIFEST_CERTIFICATION_MANIFEST, CBOR_TYPE_LIST, &cert_manifest_handler, "Certification Manifest")
);

//TODO: Add pre-handler/bwrap-handler option

PARSE_HANDLER(manifest_handler) {
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    const uint8_t *data = val->cbor_start;
    size_t data_len = val->ref.ptr - val->cbor_start + val->ref.uival;
    // suit_reference_t manifest_digest = {sctx->manifest_suit_digest, sctx->manifest_suit_digest + sizeof(sctx->manifest_suit_digest)};
    //printf("Data: %s\n len: %lu\n", data, data_len);
    int rc = suit_check_digest(&sctx->manifest_digest, data, data_len);
    //printf("RC: %d\n", rc);
    if (rc != CBOR_ERR_NONE) {
        bm_cbor_get_err_info()->ptr = *p;
    }
    else {
        rc = pull_cbor_process_kv(p, end, ctx, &manifest_elements.elements, CBOR_TYPE_MAP);
    }
    return rc;
}

CBOR_KPARSE_ELEMENT_LIST(envelope_handlers,
    CBOR_KPARSE_ELEMENT_H_BWRAP(SUIT_ENVELOPE_AUTH, CBOR_TYPE_LIST, &auth_list_handler, "Authorisation"),
    // CBOR_KPARSE_ELEMENT_A_BWRAP(SUIT_ENVELOPE_AUTH, CBOR_TYPE_LIST, &auth_list_elements, "Authorisation"),
    CBOR_KPARSE_ELEMENT_H(SUIT_ENVELOPE_MANIFEST, CBOR_TYPE_BSTR, &manifest_handler, "Manifest"),
);

CBOR_KPARSE_ELEMENT_LIST(outer_tag_elements,
    CBOR_KPARSE_ELEMENT_C(SUIT_ENVELOPE_TAG, CBOR_TYPE_MAP, &envelope_handlers, "Tagged Envelope")
);

CBOR_KPARSE_ELEMENT_LIST(tag_or_envelope,
    CBOR_KPARSE_ELEMENT_C(0, CBOR_TYPE_MAP, &envelope_handlers, "Envelope"),
    CBOR_KPARSE_ELEMENT_C(0, CBOR_TYPE_TAG, &outer_tag_elements, "Outer Tag"),
);


int suit_do_process_manifest(const uint8_t *manifest, size_t manifest_size) {
    suit_parse_context_t sctx = {0};
    sctx.envelope.ptr = manifest;
    sctx.envelope.end = manifest + manifest_size;
    const uint8_t *p = manifest;
    const uint8_t *end = manifest + manifest_size;
    int rc = pull_cbor_handle_keyed_element(&p, end, &sctx, &tag_or_envelope.elements, 0);
    // int rc = pull_cbor_process_kv(
    //     &p, end, &sctx, &envelope_handlers.elements, CBOR_TYPE_MAP
    // );
    return rc;
}

PARSE_HANDLER(vs_seq_num_handler)
{
    suit_parse_context_t *sctx = (suit_parse_context_t *)ctx;
    sctx->search_result.ptr = val->cbor_start;
    sctx->search_result.end = end;
    return 0;
}


CBOR_KPARSE_ELEMENT_LIST(vs_manifest_handlers,
    CBOR_KPARSE_ELEMENT_H(SUIT_MANIFEST_VERSION, CBOR_TYPE_UINT, version_handler, "Manifest version"),
    CBOR_KPARSE_ELEMENT_H(SUIT_MANIFEST_SEQUCENCE_NUMBER, CBOR_TYPE_UINT, vs_seq_num_handler, "Sequence number"),
);

CBOR_KPARSE_ELEMENT_LIST(vs_wrapper_handlers,
    CBOR_KPARSE_ELEMENT_H(SUIT_ENVELOPE_AUTH, CBOR_TYPE_BSTR, NULL, "Authorisation"),
    CBOR_KPARSE_ELEMENT_C_BWRAP(SUIT_ENVELOPE_MANIFEST, CBOR_TYPE_MAP, &vs_manifest_handlers, "Manifest"),
);


int suit_get_seq(const uint8_t *manifest, size_t manifest_size, uint64_t *seqnum) {
    suit_parse_context_t sctx = {0};
    sctx.envelope.ptr = manifest;
    sctx.envelope.end = manifest + manifest_size;
    const uint8_t *p = manifest;
    const uint8_t *end = manifest + manifest_size;
    pull_cbor_process_kv(
        &p, end, &sctx, &vs_wrapper_handlers.elements, CBOR_TYPE_MAP
    );
    if (!sctx.search_result.ptr) {
        return CBOR_ERR_INTEGER_ENCODING;
    }
    p = sctx.search_result.ptr;
    return bm_cbor_get_uint(&p, sctx.search_result.end, seqnum);
}
