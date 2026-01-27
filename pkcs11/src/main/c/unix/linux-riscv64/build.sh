#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")/../.."
echo $DIR

docker run -a stdin -a stdout \
	-it \
	-v $DIR:/app \
	--name riscv64builder \
	--rm --workdir /app/unix/linux-riscv64 \
	dockcross/linux-riscv64 \
	make all
	
