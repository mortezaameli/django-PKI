#!/bin/bash

mkdir -p \
  ./pki_app/pki_db/ca-db \
  ./pki_app/pki_db/cert \
  ./pki_app/pki_db/csr \
  ./pki_app/pki_db/crl \
  ./pki_app/pki_db/privkey \
  ./pki_app/pki_db/trusted \
  ./pki_app/pki_db/tmp

touch \
  ./pki_app/pki_db/ca-db/crlnumber \
  ./pki_app/pki_db/ca-db/crlnumber.old \
  ./pki_app/pki_db/ca-db/index.txt \
  ./pki_app/pki_db/ca-db/index.txt.old \
  ./pki_app/pki_db/ca-db/index.txt.attr \
  ./pki_app/pki_db/ca-db/index.txt.attr.old \
  ./pki_app/pki_db/ca-db/serial \
  ./pki_app/pki_db/ca-db/serial.old

echo 01 > ./pki_app/pki_db/ca-db/crlnumber
echo 01 > ./pki_app/pki_db/ca-db/serial
echo "unique_subject = no" > ./pki_app/pki_db/ca-db/index.txt.attr
echo "unique_subject = no" > ./pki_app/pki_db/ca-db/index.txt.attr.old



  