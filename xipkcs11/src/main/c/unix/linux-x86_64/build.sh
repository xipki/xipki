#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")/../.."
echo $DIR

docker run -a stdin -a stdout \
	-it \
	-v $DIR:/app \
	--name build-wrapper1 \
	--rm --workdir /app/unix/linux-x86_64 \
	dockcross/linux-x64 \
	make all
	

