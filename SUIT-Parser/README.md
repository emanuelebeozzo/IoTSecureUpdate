# SUIT PARSER EXTENSION

This is a fork and an extension of the suit-parser reference implementation, developed by ARM, and available at: https://gitlab.arm.com/research/ietf-suit/suit-parser.

## Content of the repo

Demonstration parser for SUIT manifests as described in [draft-ietf-suit-manifest](https://datatracker.ietf.org/doc/draft-ietf-suit-manifest/).

## Build instructions

1. Build the dependency, namely `mbedtls` and `pull-cbor`
2. Build the source of the parser, located in `/source`
3. Build the cli for testing using this command: 

```
$ make CBOR_LIB=/home/emanuele/Desktop/suit-parser/pull-cbor/out/source/pull_cbor.a CBOR_INC=/home/emanuele/Desktop/suit-parser/pull-cbor/source SUIT_LIB=/home/emanuele/Desktop/suit-parser/out/suit_parser.a
```

4. Execute the cli with an signed manifest as input:

```
$ ./cli/cli signed-example.json.suit
```
