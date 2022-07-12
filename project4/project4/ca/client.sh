#!/usr/bin/env bash

echo bashshell

# echo server
cd server


openssl genrsa -out server.key 1024

openssl req -new -key server.key -out server.csr -subj "/C=CN/ST=CQ/L=CQ/O=cqupt.com/OU=mata/CN=qi"

openssl x509 -req -in server.csr -CA ../rootca.pem -CAkey ../rootca.key -CAcreateserial -out  server$1.pem -days 10 -sha256






