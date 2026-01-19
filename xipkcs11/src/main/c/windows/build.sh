#!/bin/bash

DIR="$(dirname "$(readlink -f "$0")")../../"
echo $DIR

echo "build win32"
docker run -a stdin -a stdout \
	-it \
	-v $DIR:/app \
	--name win32builder \
	--rm --workdir /app/windows/win-x86 \
	dockcross/windows-shared-x86 \
	make all

echo "build win64"
docker run -a stdin -a stdout \
	-it \
	-v $DIR:/app \
	--name win64builder \
	--rm --workdir /app/windows/win-x86_64 \
	dockcross/windows-shared-x64 \
	make all

echo "build arm64"
docker run -a stdin -a stdout \
	-it \
	-v $DIR:/app \
	--name arm64builder \
	--rm --workdir /app/windows/win-arm64 \
	dockcross/windows-arm64 \
	make all

