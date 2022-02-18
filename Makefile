ztls_client: echo_client.c 
	gcc -o ztls_client echo_client.c -lssl -lcrypto -lresolv -pthread -DMODE=1

tls_client: echo_client.c 
	gcc -o tls_client echo_client.c -lssl -lcrypto -lresolv -pthread -DMODE=0

server: echo_mpserv.c
	gcc -o server echo_mpserv.c -lssl -lcrypto

all: ztls_client tls_client server

clean:
	rm server tls_client ztls_client
