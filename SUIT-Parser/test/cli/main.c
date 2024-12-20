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
#include "suit_parser.h"

#include "mbedtls/error.h"

#include <string.h>    /* strcmp */
#include <stdio.h>     /* printf */
#include <stdlib.h>    /* exit */
#include <fcntl.h>     /* O_BINARY */
#include <unistd.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>  /* mmap */
#include <getopt.h>

uint32_t g_debug_classes = ~(uint32_t)0;
uint32_t g_debug_level = 0;

#define p_debug(CLASS, LEVEL, ...)\
    if (((CLASS) & g_debug_classes) && (g_debug_level >= (LEVEL))) {\
        printf(##__VA_ARGS__);\
    }

void print_usage(const char *argv0)
{
    printf("Usage: %s [-h] [-v [-v [...]]] FILE\n", argv0);

    printf("-v increase verbosity level\n");
    printf("-h show this message and exit\n");
}

unsigned verbosity = 0;

int dry_run = 0;
int
main(int argc, char **argv)
{

    int c;
    int digit_optind = 0;
    const struct option long_options[] = {
        // {"verbose", optional_argument, 0, 'v'}
        // {"vendor-id"}
        // {"class-id"}
        // {"slot"}
        {"dry-run", no_argument, 0, 0},
        // boot / update

        {0,         0,                 0,  0 }
    };

    while (1) {
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;

        c = getopt_long(argc, argv, "",
                 long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 0:
            if (0 == strcmp("dry-run", long_options[option_index].name)) {
                dry_run = 1;
            }
            printf("option %s", long_options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");
            break;

        case '?':
            print_usage(*argv);
            break;

        default:
            printf("?? getopt returned character code 0%o ??\n", c);
            print_usage(*argv);
        }
    }
    if (optind >= argc) {
        printf("Missing manifest argument\n");
        exit(EXIT_FAILURE);
    }

    char* manifest_name = argv[optind];
    int manifest_fd = -1;
    struct stat st;

    if((manifest_fd = open(manifest_name, O_RDONLY)) < 0)
        perror("Error in file opening");

    if(fstat(manifest_fd,&st) < 0)
        perror("Error in fstat");

    uint8_t *mfst_ptr;
    if((mfst_ptr=mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, manifest_fd, 0)) == MAP_FAILED)
        perror("Error in mmap");

    printf("Preparing to parse manifest: %s\n", argv[optind]);
    int rc = suit_do_process_manifest(mfst_ptr, st.st_size);
    printf("Parser Result: %d\n", rc);
    if (rc != CBOR_ERR_NONE) {
        bm_cbor_err_info_t *err = bm_cbor_get_err_info();
        printf("bm_cbor_err_info raw data:\n");
        printf("Error occured at: %p\n", err->ptr);
        printf("Error code: %d\n", err->cbor_err);
        if (err->cbor_err < 0) {
            char buf[64];
            //mbedtls_strerror(err->cbor_err,buf, sizeof(buf));
            printf("mbedtls error: %s\n", buf);
        }
        printf("Source File Name: %s\n", err->file);
        printf("Source Line Number: %lu\n", (unsigned long) err->line);
        printf("----------------\n");
        intptr_t offset = (intptr_t)err->ptr - (intptr_t)mfst_ptr;
        printf("Manifest offset: %ld\n", offset);
        //for(size_t i = 0; i < offset; i++) {
        //    printf("%02x", (unsigned)mfst_ptr[i]);
        //    if (i%16 == 15) {
        //        printf("\n");
        //    }
        //}
        //printf("\n--> %02x\n", (unsigned)mfst_ptr[offset]);
        //for(size_t i = offset+1; i < st.st_size; i++) {
        //    printf("%02x", (unsigned)mfst_ptr[i]);
        //    if ((i-offset)%16 == 15) {
        //        printf("\n");
        //    }
        //}
        printf("\n");
    }
   exit(EXIT_SUCCESS);
}