// ----------------------------------------------------------------------------
// Copyright 2021 ARM Ltd.
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

#include "cli.h"
#include "suit_platform.h"
#include "suit_parser.h"
#include "bm_cbor.h"
#include "mbedtls/mbedtls_config.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdsa.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

//const uint8_t vendor_id[16] = {
//    0xfa, 0x6b, 0x4a, 0x53, 0xd5, 0xad, 0x5f, 0xdf,
//    0xbe, 0x9d, 0xe6, 0x63, 0xe4, 0xd4, 0x1f, 0xfe
//};
//const uint8_t class_id[16] = {
//    0x14, 0x92, 0xaf, 0x14, 0x25, 0x69, 0x5e, 0x48,
//    0xbf, 0x42, 0x9b, 0x2d, 0x51, 0xf2, 0xab, 0x45
//};
//
//const uint8_t public_key[] = {
//    0x04, 0x84, 0x96, 0x81, 0x1a, 0xae, 0x0b, 0xaa, 0xab,
//    0xd2, 0x61, 0x57, 0x18, 0x9e, 0xec, 0xda, 0x26,
//    0xbe, 0xaa, 0x8b, 0xf1, 0x1b, 0x6f, 0x3f, 0xe6,
//    0xe2, 0xb5, 0x65, 0x9c, 0x85, 0xdb, 0xc0, 0xad,
//    0x3b, 0x1f, 0x2a, 0x4b, 0x6c, 0x09, 0x81, 0x31,
//    0xc0, 0xa3, 0x6d, 0xac, 0xd1, 0xd7, 0x8b, 0xd3,
//    0x81, 0xdc, 0xdf, 0xb0, 0x9c, 0x05, 0x2d, 0xb3,
//    0x39, 0x91, 0xdb, 0x73, 0x38, 0xb4, 0xa8, 0x96,
//};

const uint8_t vendor_id[16] = {
    0xfa, 0x6b, 0x4a, 0x53, 0xd5, 0xad, 0x5f, 0xdf,
    0xbe, 0x9d, 0xe6, 0x63, 0xe4, 0xd4, 0x1f, 0xfe
};
const uint8_t class_id[16] = {
    0x14, 0x92, 0xaf, 0x14, 0x25, 0x69, 0x5e, 0x48,
    0xbf, 0x42, 0x9b, 0x2d, 0x51, 0xf2, 0xab, 0x45
};

const uint8_t public_key[] = {
    0x04, 0x07, 0x30, 0xc9, 0xc4, 0xae, 0x4b, 0x76, 0x7a, 0xb6, 
    0x9c, 0x4b, 0xab, 0xac, 0x00, 0x85, 0x8d, 0x07, 0x52, 0x90, 
    0x2a, 0xcb, 0x52, 0x33, 0x75, 0x1b, 0x92, 0xfe, 0x38, 0xe9, 
    0xdb, 0x32, 0xd9, 0xd4, 0x8b, 0xcd, 0x61, 0x7b, 0x6c, 0x45, 
    0x9f, 0xc1, 0xa0, 0x89, 0xc7, 0x7f, 0xcd, 0x60, 0x6d, 0x6c, 
    0x02, 0x8c, 0x0c, 0xce, 0x04, 0xc8, 0xef, 0x42, 0x5a, 0xe7, 
    0x3f, 0x38, 0xa8, 0x89, 0x8d
};

const size_t public_key_size = sizeof(public_key);

void s_print(const char *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%c", p[i]);
    }
}
void x_print(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
}

void compute_sha256(uint8_t *hash, const uint8_t *msg, size_t msg_len) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init (&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, msg, msg_len);
    mbedtls_sha256_finish(&ctx, hash);
    mbedtls_sha256_free(&ctx);
}

int mbedtls_md_helper(
    const uint8_t *msg, size_t msg_len,
    uint8_t *hash, mbedtls_md_type_t mdtype)
{
    int ret = 0;
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    ret = mbedtls_md_setup(&md_ctx, mbedtls_md_info_from_type(mdtype), 0);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
    ret = mbedtls_md_starts(&md_ctx);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
    ret = mbedtls_md_update(&md_ctx, msg, msg_len);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
    ret = mbedtls_md_finish(&md_ctx, hash);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
    return ret;
}

int mbedtls_ecdsa_helper(
                const uint8_t *msg, size_t msg_len,
                const uint8_t *sig, size_t sig_len,
                const uint8_t *pub, size_t pub_len,
                mbedtls_ecp_group_id grpid,
                mbedtls_md_type_t mdtype)
{
    uint8_t hash[64] = {0};
    int ret = mbedtls_md_helper(msg, msg_len, hash, mdtype);
    mbedtls_ecdsa_context ctx_verify;
    mbedtls_ecdsa_init( &ctx_verify );
    ret = mbedtls_ecp_group_load( &ctx_verify.MBEDTLS_PRIVATE(grp), grpid);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
    //printf("pub_len: %d\n", pub_len);
    ret = mbedtls_ecp_point_read_binary( &ctx_verify.MBEDTLS_PRIVATE(grp), &ctx_verify.MBEDTLS_PRIVATE(Q), pub, pub_len);
    //printf("Ret: %d\n", ret);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
    mbedtls_mpi r, s;
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);    
	ret = mbedtls_mpi_read_binary( &r, sig, sig_len / 2 );
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
	ret = mbedtls_mpi_read_binary( &s, sig + sig_len/2, sig_len / 2 );
	    if (ret) {
        RETURN_ERROR(ret, NULL);
    }
	ret = mbedtls_ecdsa_verify(
        &ctx_verify.MBEDTLS_PRIVATE(grp),
        hash,
        mbedtls_md_get_size(mbedtls_md_info_from_type(mdtype)),
        &ctx_verify.MBEDTLS_PRIVATE(Q),
        &r,
        &s);
    if (ret) {
        RETURN_ERROR(ret, NULL);
    }

    return CBOR_ERR_NONE;
}

int ES256_verify(
                const uint8_t *msg, size_t msg_len,
                const uint8_t *sig, size_t sig_len,
                const uint8_t *pub, size_t pub_len)
{
    return mbedtls_ecdsa_helper(
        msg, msg_len,
        sig, sig_len,
        pub, pub_len,
        MBEDTLS_ECP_DP_SECP256R1,
        MBEDTLS_MD_SHA256);
}

int COSEAuthVerify(
                const uint8_t *msg, size_t msg_len,
                const uint8_t *sig, size_t sig_len,
                const uint8_t *kid, size_t kid_len,                
                int alg)
{
    int rc;
    //TODO: Lookup public key by key-id
    switch (alg) {
        case COSE_ES256:
            rc = ES256_verify(
                msg, msg_len,
                sig, sig_len,
                public_key, public_key_size);
            break;
        default:
            SET_ERROR(rc, CBOR_ERR_UNIMPLEMENTED, NULL);
            break;
    }
    return rc;
}
int mbedtls_md_verify_helper256(
    const uint8_t *msg, size_t msg_len,
    const uint8_t *exp, size_t exp_len,
    mbedtls_md_type_t mdtype)
{
    uint8_t hash[32];
    if (exp_len != 32) {
        RETURN_ERROR( SUIT_ERROR_DIGEST_MISMATCH, NULL);
    }
    int ret;
    ret = mbedtls_md_helper(msg, msg_len, hash, mdtype);

    if (0==memcmp(hash, exp, sizeof(hash))) {
        return CBOR_ERR_NONE;
    }
    else {
        RETURN_ERROR( SUIT_ERROR_DIGEST_MISMATCH, NULL);
    }

}
// int mbedtls_md_verify_helper512(
//     const uint8_t *msg, size_t msg_len,
//     const uint8_t *exp, size_t exp_len,
//     mbedtls_md_type_t mdtype)

int suit_platform_verify_digest(
    const uint8_t *data, size_t data_len,
    const uint8_t *exp, size_t exp_len,
    int alg)
{
    if (dry_run){
        printf("Checking digest (alg=%d): ", alg);
    }
    switch (alg) {
        // TODO: expected digest length.
        case SUIT_DIGEST_TYPE_SHA256:
            if (dry_run) {
                printf("Matching SHA256: ");
                x_print(exp,exp_len);
                printf("\n");
                return CBOR_ERR_NONE;
            } else {
                printf("Matching SHA256: ");
                x_print(exp,exp_len);
                printf("\n");
                return mbedtls_md_verify_helper256(data, data_len, exp, exp_len, MBEDTLS_MD_SHA256);
            }
    }
    RETURN_ERROR(SUIT_ERROR_DIGEST_MISMATCH, NULL);
}

void print_component_id(uint8_t *cid, uint8_t* end) {

}

int suit_platform_get_image_ref(
    suit_reference_t *component_id,
    const uint8_t **image) {
    //TODO: open/create component_id with mmap
    return 0;
}

int suit_platform_do_fetch(
    suit_reference_t *component_id,
    int digest_type,
    const uint8_t *digest_bytes,
    size_t digest_len,
    size_t image_size,
    const uint8_t* uri,
    size_t uri_len) 
{
    printf("Fetching ");
    if (component_id == NULL) {
        printf("<only component>\n");
    } else {
        //TODO
    }
    printf("  Target digest type %i\n", digest_type);
    printf("  Target digest bytes: ");
    x_print(digest_bytes, digest_len);
    printf("\n");
    printf("  Source: ");
    s_print((char*) uri, uri_len);
    printf("\n");
    return 0;
}

int suit_platform_do_run(const uint8_t *component_id) {
    printf("booted\n");
    //TODO
    return 0;
}


static uint8_t *suit_report_buf = NULL;
static uint8_t *suit_report_p = NULL;
static uint8_t *suit_report_end = NULL;

int suit_platform_report_init(
    uint8_t *report_buffer,
    size_t report_buffer_size,
    bm_cbor_reference_t *manifest_digest

) {
    suit_report_buf = suit_report_p = report_buffer;
    suit_report_end = suit_report_buf + report_buffer_size;
    return CBOR_ERR_NONE;
}

int suit_platform_report_set_digest(
    bm_cbor_reference_t *digest
) {
    printf("Manifest Digest is: ");
    printf("\n");
    // *(suit_report_p++) = SUIT_RECORD_MANIFEST_ID;
    // TODO: Copy  in the digest
    return 0;
}

int suit_platform_report_set_URI(
    bm_cbor_reference_t *uri
) {
    return 0;
}

int suit_platform_start_records()
{
    // Start indefinite length list of SUIT records
    // *(suit_report_p++) = SUIT_RECORD_M | 31;
    // *(suit_report_p++) = CBOR_TYPE_LIST | 31;
    return 0;
}

//    suit-record = {
//        suit-record-manifest-id        => [* uint ],
//        suit-record-manifest-section   => int,
//        suit-record-section-offset     => uint,
//        (
//            suit-record-component-index  => uint //
//            suit-record-dependency-index => uint
//        ),
//        suit-record-failure-reason     => SUIT_Parameters / int,
//    }
// #define SUIT_RECORD_MANIFEST_ID 
int suit_platform_report_record(
    suit_parse_context_t *ctx,
    char **p,
    int section_id, 
    int idx,
    int key,
    suit_vars_t* vars
) {
    // *(suit_report_p++) = SUIT_RECORD_MANIFEST_ID;

    return CBOR_ERR_NONE;
}