#!/bin/bash

set -e
set -o xtrace

function main {
  export WORKDIR=`mktemp -d`
  trap "rm -rf $WORKDIR" EXIT

  export CGO_ENABLED=0
  export GO111MODULE=on

  go build -tags netgo -o "$WORKDIR"/server ./server

  docker build -f ./server/Dockerfile -t wile:latest "$WORKDIR"
}

main "$@"
