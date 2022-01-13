# tls-multi-echo-server
> Implement a TLS 1.3 multi echo server using openssl
> In echo_client.c, there is a variable named DNS.
> If DNS = 0, implement TLS 1.3.
> else, implement ZTLS.
# Compile
> gcc -o server echo_mpserv.c -lssl -lcrypto
> gcc -o client echo_client.c -lssl -lcrypto -lresolv


# How to implement
> ./server port


> ./client ip port

# Easy to implement
> clear; make clean;make server;./server port

> clear; make clean;make client;./client ip port

# TroubleShooting

1. add environment variables
export LD_LIBRARY_PATH=/usr/local/lib

