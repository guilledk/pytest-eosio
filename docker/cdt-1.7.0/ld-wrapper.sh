#!/bin/bash

echo "Running " `dirname $0`/wasm-ld.real --no-threads "$@"
`dirname $0`/wasm-ld.real --no-threads "$@"

