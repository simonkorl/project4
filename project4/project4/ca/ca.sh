#!/usr/bin/env bash
echo bashshell


# touch private
# touch crl
mkdir server

touch index.txt

echo 01>serial

openssl rand -out ~/.rnd 1000


echo CA

#生成根密钥
openssl genrsa -out rootca.key 1024


openssl pkcs8 -topk8 -inform PEM -outform DER -in rootca.key -out rootcaPri.der -nocrypt
 
openssl rsa -in rootca.key -pubout -outform DER -out rootcaPub.der

openssl req -x509  -new -nodes -key rootca.key -sha256 -days 100 -subj  "/C=CN/ST=CQ/L=CQ/O=cqupt.com/OU=mata/CN=qi" -out rootca.pem






