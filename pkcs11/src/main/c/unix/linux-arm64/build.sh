#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")/../.."
echo $DIR

docker run -a stdin -a stdout \
	-it \
	-v $DIR:/app \
	--name build-wrapper1 \
	--rm --workdir /app/unix/linux-arm64 \
	dockcross/linux-arm64 \
	make all


