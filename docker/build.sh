#! /bin/bash

docker build \
    --rm \
    -t alphonse:0.1.0-alpine \
    -f docker/Dockerfile.alpine \
    .
