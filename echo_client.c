#include "echo_client.h"

#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>
#include <string.h>
#include <pthread.h>

#define BUF_SIZE 10000

#if MODE
int DNS = 1; 
#else
int DNS = 0;
#endif
// 0 = false; //normal TLS 1.3
// 1 = true;  //ZTLS

struct DNS_info{
    struct {
        time_t validity_period_not_before; //gmt unix time
        time_t validity_period_not_after;  //gmt unix time
        uint32_t dns_cache_id;
		uint32_t max_early_data_size;
    } DNSCacheInfo;
    struct {
        uint8_t *extension_type;
        uint16_t *extension_data;
    } EncryptedExtensions;
    struct {
        uint8_t group;
        EVP_PKEY *skey; // server's keyshare
    } KeyShareEntry;
    X509* cert; // server's cert
    struct {
        uint8_t certificate_request_context;
        uint16_t extensions;
    } CertRequest;
    struct {
        uint16_t signature_algorithms;
        unsigned char cert_verify[BUF_SIZE]; // signature
    } CertVerifyEntry;
} dns_info;

static void init_openssl();
static int load_dns_info2(struct DNS_info* dp, char* truncated_dnsmsg_out, char* dnsmsg);
static SSL_CTX *create_context();
static void keylog_callback(const SSL* ssl, const char *line);
static size_t resolve_hostname(const char *host, const char *port, struct sockaddr_storage *addr);
static void configure_connection(SSL *ssl);
static void error_handling(char *message);
static int dns_info_add_cb(SSL *s, unsigned int ext_type,
                    unsigned int context,
                    const unsigned char **out,
                    size_t *outlen, X509 *x, size_t chainidx,
                    int *al, void *arg);

static void dns_info_free_cb(SSL *s, unsigned int ext_type,
                     unsigned int context,
                     const unsigned char *out,
                     void *add_arg);

static int ext_parse_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *in,
                        size_t inlen, int *al, void *parse_arg);
static time_t is_datetime(const char *datetime);

static void init_tcp_sync(char *argv[], struct sockaddr_storage * addr, int sock);

struct arg_struct {
	char ** argv;
	struct sockaddr_storage * addr;
	int sock;
};

static void *thread_init_tcp_sync(void* arguments)
{
	struct arg_struct * args = (struct arg_struct *) arguments;
	init_tcp_sync(args->argv, args->addr, args->sock);
	pthread_exit(NULL);
}

int main(int argc, char *argv[]){
	res_init();
	_res.options = _res.options | RES_USEVC ; 	// use TCP connections for queries instead of UDP datagrams 
												// to avoid TCP retry after UDP failure
    init_openssl();
    SSL_CTX *ctx = create_context();
    // static ctx configurations 
    SSL_CTX_load_verify_locations(ctx, "./dns/cert/CarolCert.pem", "./dns/cert/");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); // SSL_VERIFY_NONE
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_keylog_callback(ctx, keylog_callback);
	SSL * ssl = NULL;

    if(argc != 3){
        printf("Usage : %s <port>\n", argv[0]);
        exit(1);
    }

    int sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock < 0){
        error_handling("socket() error");
    }

    struct sockaddr_storage addr;
	char txt_record_except_signature[BUF_SIZE];
	char *txt_record_all;
	unsigned char query_buffer[4096];
	int response;
	ns_type type;
	type= ns_t_txt;
	ns_msg nsMsg;
	ns_rr rr;

    // log
    struct timespec begin;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    printf("start : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
	
	//=============================================================
	// Dynamic interaction start
	//=============================================================
    
	// get TXT record & dynamic ctx configurations for ZTLS
    if(DNS){
		struct arg_struct args;
		args.argv = argv;
		args.addr = &addr;
		args.sock = sock;

		pthread_t ptid;
		pthread_create(&ptid, NULL, &thread_init_tcp_sync,(void *) &args);

//		response = res_query("aaa.nsztls.snu.ac.kr", C_IN, type, query_buffer, sizeof(query_buffer));
		response = res_search(argv[1], C_IN, type, query_buffer, sizeof(query_buffer));
		// log
    	clock_gettime(CLOCK_MONOTONIC, &begin);
    	printf("complete DNS TXT record query : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
		if (response < 0) {
			printf("Error looking up service: TXT");
			return 2;
		}    
		ns_initparse(query_buffer, response, &nsMsg);
		ns_parserr(&nsMsg, ns_s_an, 0, &rr);
		u_char const *rdata = (u_char*)(ns_rr_rdata(rr)+1 );
		txt_record_all=(char*)rdata;
		txt_record_all[strlen((char*)rdata)] = '\0';
        load_dns_info2(&dns_info, txt_record_except_signature, txt_record_all); 
		SSL_CTX_add_custom_ext(ctx, 53, SSL_EXT_CLIENT_HELLO, dns_info_add_cb, dns_info_free_cb,NULL, NULL,NULL);// extentionTye = 53, Extension_data = dns_cache_id
    	if(dns_info.KeyShareEntry.group == 29){  // keyshare group : 0x001d(X25519)
			SSL_CTX_set1_groups_list(ctx, "X25519");
			// for demo, we will add other groups later.
			// switch 
			// P-256, P-384, P-521, X25519, X448, ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192
    	}
    	ssl = SSL_new(ctx);
    	SSL_set_wfd(ssl, DNS); // fd : 1 => ZTLS, fd : 0 => TLS 1.3
        // Check timestamp Valid
    	if(dns_info.DNSCacheInfo.validity_period_not_before < time(NULL) && dns_info.DNSCacheInfo.validity_period_not_after > time(NULL)){
        	printf("Valid Period\n");
    	}else{
       	 	printf("Not Valid Period\n");
    	}
		SSL_use_PrivateKey(ssl, dns_info.KeyShareEntry.skey); // set server's keyshare // this function is modified 
        SSL_use_certificate(ssl, dns_info.cert); // set sever's cert and verify cert_chain // this function is modified
    	if(dns_info.CertVerifyEntry.signature_algorithms == 2052)     //rsa pss rsae sha256 0x0804
		{
			strcat(txt_record_except_signature, "\n");
			strcat(dns_info.CertVerifyEntry.cert_verify, "\n");
			SSL_export_keying_material(ssl, (unsigned char*) txt_record_except_signature, 0, NULL, 0,
				 dns_info.CertVerifyEntry.cert_verify, BUF_SIZE, 0); // cert verify: signature of DNS cache info check. // this function is modified
		}	// for demo, we will only support rsa pss rsae_sha256 

		pthread_join(ptid, NULL);

    }else {
		init_tcp_sync(argv, &addr, sock);
    	ssl = SSL_new(ctx);
    	SSL_set_wfd(ssl, DNS); // fd : 1 => ZTLS, fd : 0 => TLS 1.3
	}
	// threads join

    SSL_set_fd(ssl, sock);
    /*
     * handshake start
     */
    configure_connection(ssl); // SSL do handshake
    char message[BUF_SIZE];
    int str_len;
    struct timespec send_ctos, receive_ctos;

    if(!DNS){ // normal TLS 1.3
        memcpy(message, "hello\n", 6);
        
		SSL_write(ssl, message, strlen(message));
		clock_gettime(CLOCK_MONOTONIC, &send_ctos);
		printf("send : %s", message);
		printf("%f\n",(send_ctos.tv_sec) + (send_ctos.tv_nsec) / 1000000000.0);
				
		if((str_len = SSL_read(ssl, message, BUF_SIZE-1))<=0){
			printf("error\n");
		}
		message[str_len] = 0;
		clock_gettime(CLOCK_MONOTONIC, &receive_ctos);
		printf("Message from server: %s", message);
		printf("%f\n",(receive_ctos.tv_sec) + (receive_ctos.tv_nsec) / 1000000000.0);
    }

    while(1){
        fputs("Input message(Q to quit): ", stdout);
        fgets(message, BUF_SIZE, stdin);

        if(!strcmp(message, "q\n") || !strcmp(message, "Q\n")){
            break;
        }

        SSL_write(ssl, message, strlen(message));
        clock_gettime(CLOCK_MONOTONIC, &send_ctos);
        printf("send : %s", message);
        printf("%f\n",(send_ctos.tv_sec) + (send_ctos.tv_nsec) / 1000000000.0);
        
	if((str_len = SSL_read(ssl, message, BUF_SIZE-1))<=0){
        	printf("error\n");
        }
        message[str_len] = 0;
        clock_gettime(CLOCK_MONOTONIC, &receive_ctos);
        printf("Message from server: %s", message);
        printf("%f\n",(receive_ctos.tv_sec) + (receive_ctos.tv_nsec) / 1000000000.0);
    }
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
static void init_tcp_sync(char *argv[], struct sockaddr_storage * addr, int sock) {
	size_t len = resolve_hostname(argv[1], argv[2], addr);
    struct timespec begin;
    clock_gettime(CLOCK_MONOTONIC, &begin);
    printf("complete A and AAAA DNS records query : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
    
	if(connect(sock, (struct sockaddr*) addr, len) < 0){
        error_handling("connect() error!");
    }else{
    	clock_gettime(CLOCK_MONOTONIC, &begin);
    	printf("complete TCP Sync : %f\n",(begin.tv_sec) + (begin.tv_nsec) / 1000000000.0);
    }
}


static void init_openssl(){
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

static int load_dns_info2(struct DNS_info* dp, char* truncated_dnsmsg_out, char* dnsmsg){
    BIO *bio_key, *bio_cert;
    char *tmp;
	char publickey_prefix[150] = "-----BEGIN PUBLIC KEY-----\n";
	char publickey_postfix[30] = "\n-----END PUBLIC KEY-----\n";
	char certificate_prefix[BUF_SIZE] = "-----BEGIN CERTIFICATE-----\n";
	char certificate_postfix[30] = "-----END CERTIFICATE-----\n";
	char txt_record_signature[BUF_SIZE];
	char newline[4] = "\n";
	char * ztls_version = "v=ztls1";
	
	//v=ztls1 check
	tmp = strtok(dnsmsg," ");
	strcat(truncated_dnsmsg_out,tmp);
	strtok(NULL, " ");//" "
	if(0!=strcmp(tmp,ztls_version)){
		printf("DNS TXT record's ZTLS version error\n");
	}
    
	// load dns cache info
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
    dp->DNSCacheInfo.validity_period_not_before = is_datetime(tmp);
	printf("DNS cache period: %s~", tmp);
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
    dp->DNSCacheInfo.validity_period_not_after = is_datetime(tmp);
	printf("~%s\n", tmp);
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
	dp->DNSCacheInfo.max_early_data_size = strtoul(tmp, NULL, 0);
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
    dp->DNSCacheInfo.dns_cache_id  = strtoul(tmp, NULL, 0);
	strtok(NULL," ");

	// load keyshare entry
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
    dp->KeyShareEntry.group = strtoul(tmp, NULL, 0);
    bio_key = BIO_new(BIO_s_mem());
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
	strcat(publickey_prefix, tmp);
	strcat(publickey_prefix, publickey_postfix);
    BIO_puts(bio_key, publickey_prefix);
    PEM_read_bio_PUBKEY(bio_key, &(dp->KeyShareEntry.skey), NULL, NULL);

	// load certificate
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);

	char * begin_cert = "B_CERTIFICATE";
	char * end_cert = "E_CERTIFICATE";

	// ZTLS DNS certificate format
	// B_CERTIFICATE
	// value (1) (2) (3) iterate
	// E_CERTIFICATE
	
	if(0!=strcmp(tmp,begin_cert)){
		printf("CERTIFICATE INFO ERROR\n");
	}

	strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
	int i =0;
	while((0!=strcmp(tmp,end_cert) && i < 100)){
		strcat(certificate_prefix, tmp);//value (1)
		strcat(certificate_prefix, newline);
		tmp = strtok(NULL," ");
		strcat(truncated_dnsmsg_out,tmp);
		if(0==strcmp(tmp,end_cert)) break;
		strcat(certificate_prefix, tmp);//value (2)
		strcat(certificate_prefix, newline);
		tmp = strtok(NULL," ");
		strcat(truncated_dnsmsg_out,tmp);
		if(0==strcmp(tmp,end_cert)) break;
		strcat(certificate_prefix, tmp);//value (3)
		strcat(certificate_prefix, newline);
		strtok(NULL," ");
		tmp = strtok(NULL," ");
		strcat(truncated_dnsmsg_out,tmp);
		i++;
	}
	if (100 <= i ) {
		printf("CERTIFICATE INFO ERROR\n");
	}
	strcat(certificate_prefix, certificate_postfix);

    bio_cert = BIO_new(BIO_s_mem());
    BIO_puts(bio_cert, certificate_prefix);
    PEM_read_bio_X509(bio_cert, &(dp->cert), NULL, NULL);

// Client Certificate Request Check
// for demo No Client Certificate Request
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
	printf("Client Certificate Request: %s\n", tmp);
	
	strtok(NULL," ");
	tmp = strtok(NULL," ");
	strcat(truncated_dnsmsg_out,tmp);
    
//	load TXT signature (cert verify)
    dp->CertVerifyEntry.signature_algorithms = strtoul(tmp, NULL, 0);
//	printf("%s",truncated_dnsmsg_out);
	strtok(NULL," ");
	tmp = strtok(NULL," ");
    i =0;
	while(i < 100){
		strcat(txt_record_signature, tmp);//value (1)
		tmp = strtok(NULL," ");
		if(tmp == NULL) break;
		strcat(txt_record_signature, newline);
		
		strcat(txt_record_signature, tmp);//value (2)
		tmp = strtok(NULL," ");
		if(tmp == NULL) break;
		strcat(txt_record_signature, newline);
		
		strcat(txt_record_signature, tmp);//value (3)
		strtok(NULL," ");
		tmp = strtok(NULL," ");
		if(tmp == NULL) break;
		strcat(txt_record_signature, newline);
		
		i++;
	}
	if (100 <= i ) {
		printf("SIGNATURE ERROR\n");
	}
	strcpy((char*)dp->CertVerifyEntry.cert_verify, txt_record_signature);
//	printf("signature:\n%s",txt_record_signature);
    return 0;
}

/*
 * SSL 구조체를 생성, 통신 프로토콜 선택;
 * return SSL_CTX* SSL 구조체;
 */
static SSL_CTX *create_context(){
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
    if(!ctx) error_handling("fail to create ssl context");
    /*
     * ssl_check_allowed_versions(ctx->min_proto_version, larg) : larg가 최고 proto로 설정;
               && ssl_set_version_bound(ctx->method->version, (int)larg,
                                        &ctx->max_proto_version);
     */
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    return ctx;
}
/*
 * verify
 * set version
 */
static void keylog_callback(const SSL* ssl, const char *line){
//    printf("==============================================\n");
//    printf("%s\n", line);
}
static size_t resolve_hostname(const char *host, const char *port, struct sockaddr_storage *addr){
    struct addrinfo *res = 0;
    if(getaddrinfo(host, port, 0, &res) != 0)
        error_handling("fail to transform address");
    size_t len = res->ai_addrlen;
    memcpy(addr, res->ai_addr, len);
    freeaddrinfo(res);
    return len;
}
static void configure_connection(SSL *ssl){
    SSL_set_tlsext_host_name(ssl, "ztls.net");
    SSL_set_connect_state(ssl);
    if(SSL_do_handshake(ssl) <= 0){
        ERR_print_errors_fp(stderr);
        error_handling("fail to do handshake");
    }
}
static void error_handling(char *message){
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

static int dns_info_add_cb(SSL *s, unsigned int ext_type,
                            unsigned int context,
                            const unsigned char **out,
                            size_t *outlen, X509 *x, size_t chainidx,
                            int *al, void *arg)
                            {

    if (context == SSL_EXT_CLIENT_HELLO) {
        *out = (unsigned char*)malloc(sizeof(char*)*4);
        memcpy((void*)*out, &(&dns_info)->DNSCacheInfo.dns_cache_id, 4);
        *outlen = 4;
    }

    return 1;
}

static void dns_info_free_cb(SSL *s, unsigned int ext_type,
                     unsigned int context,
                     const unsigned char *out,
                     void *add_arg){
    OPENSSL_free((unsigned char *)out);
}

static int ext_parse_cb(SSL *s, unsigned int ext_type,
                        const unsigned char *in,
                        size_t inlen, int *al, void *parse_arg)
                        {
    return 1;
}

static time_t is_datetime(const char *datetime){
    // datetime format is YYYYMMDDHHMMSSz
    struct tm   time_val;

    strptime(datetime, "%Y%m%d%H%M%Sz", &time_val);

    return mktime(&time_val);       // Invalid
}
