ztls_client: echo_client.c 
	gcc -o ztls_client echo_client.c -lssl -lcrypto -lresolv -pthread

tls_client: echo_client.c 
	gcc -o tls_client echo_client.c -lssl -lcrypto -lresolv -pthread

server: echo_mpserv.c
	gcc -o server echo_mpserv.c -lssl -lcrypto

clean:
	rm server tls_client ztls_client
