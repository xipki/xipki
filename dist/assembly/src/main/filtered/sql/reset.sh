#!/bin/sh

./ca-db.sh dropAll

./ca-db.sh update

./ocsp-db.sh dropAll

./ocsp-db.sh update
