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

OUT?=./out

ABS_OUT=$(abspath ${OUT})/

ifdef PARSER_DEBUG
CFLAGS+=-DPARSER_DEBUG -g -O0
Q=
endif

ifdef DEBUG
CFLAGS+=-g -O0
endif

Q?=@

SUIT_LIB?=${ABS_OUT}source/suit_parser.a
CBOR_LIB?=$(abspath ./pull-cbor/out/source/pull_cbor.a)
CBOR_INC?=$(abspath ./pull-cbor/source)

export Q
export CFLAGS
export SUIT_LIB
export CBOR_LIB
export CBOR_INC

.PHONY: all
all: lib

${ABS_OUT}:
	${Q}mkdir -p ${ABS_OUT}

.PHONY: ${CBOR_LIB}
${CBOR_LIB}:
	${Q}make -C pull-cbor lib

.PHONY: lib
lib: ${ABS_OUT} ${CBOR_LIB}
	${Q}make -C source OUT=${ABS_OUT}source/ Q=${Q}

.PHONY: tests
tests: lib ${OUT} ${SUIT_LIB} ${CBOR_LIB}
	${Q}make -C test OUT=${ABS_OUT}test/
.PHONY: test
test: tests
	${Q}make -C test OUT=${ABS_OUT}test/ test

.PHONY: clean ${ABS_OUT}
clean:
	rm -rf ${ABS_OUT}
	${Q}make -C pull-cbor clean
