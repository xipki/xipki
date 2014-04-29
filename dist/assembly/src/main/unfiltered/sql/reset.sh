#!/bin/sh

./ca-db.sh dropAll
echo ""
echo ""

./ca-db.sh update
echo ""
echo ""

./ocsp-db.sh dropAll
echo ""
echo ""

./ocsp-db.sh update
echo ""
echo ""
