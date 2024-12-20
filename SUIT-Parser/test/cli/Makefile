# -*- coding: utf-8 -*-
# ----------------------------------------------------------------------------
# Copyright 2021 ARM Limited or its affiliates
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ----------------------------------------------------------------------------


CC?=cc
AR?=ar

OUT?=../../out/test/cli/
LIBMBEDCRYPTO?=$(abspath ${OUT}lib/libmbedcrypto.a)
LIMMBEDTLS?=$(abspath ${OUT}lib/libmbedtls.a)
CBOR_INC?=$(abspath ../../pull-cbor/source)
SRC_ROOT?=$(abspath ../../source)

CBOR_LIB?=${CBOR}/out/source/bm_cbor.a
Q?=@

TARGET=${OUT}cli

SRCS=main.c
STUBS=stubs.c
SRC_OBJS=$(patsubst %.c,${OUT}%.o,${SRCS})
STUB_OBJS=$(patsubst %.c,${OUT}%.o,${STUBS})
CFLAGS+=-I${CBOR_INC} -I$(abspath ./uecc/) -I$(abspath ${OUT}/include)

all: tests

test: tests
	# ${TARGET} example1.json.suit
	${TARGET} --dry-run signed-example1.json.suit

tests: ${TARGET}

${OUT}:
	${Q}mkdir -p ${OUT}

${OUT}%.o: %.c ${OUT} ${LIBMBEDCRYPTO} ${LIMMBEDTLS}
	${Q}echo "  [CC] $@"
	${Q}${CC} ${CFLAGS} -I${SRC_ROOT} -c -o $@ $<

${LIBMBEDCRYPTO}:
	${Q}sh -c "cd mbedtls && python3 ./scripts/config.py crypto"
	${Q}make -C mbedtls install DESTDIR=$(abspath ${OUT})

${TARGET}:${SRC_OBJS} ${SUIT_LIB} ${CBOR_LIB} ${STUB_OBJS} ${LIBMBEDCRYPTO} ${LIMMBEDTLS}
	${Q}echo "  [LD] $@"
	${CC} -o $@ ${SRC_OBJS} ${SUIT_LIB} ${CBOR_LIB} ${STUB_OBJS} ${LIBMBEDCRYPTO} ${LIMMBEDTLS}