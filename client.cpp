#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
 
#define FAIL -1
 
// OpenConnection(): 소켓 생성하고 서버에게 연결요청
// 인자로 호스트이름, 포트번호 받음
int OpenConnection(const char *hostname, int port)
{   int sd; // socket
    struct hostent *host;
    struct sockaddr_in addr;
 
    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    
    // socket()
    sd = socket(PF_INET, SOCK_STREAM, 0);
    
    // memset 말고 bzero 를 씀.
    bzero(&addr, sizeof(addr)); // 구조체를 0으로 초기화
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    addr.sin_port = htons(port);
    
    // connect()
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort(); // 비정상적 강제 종료
    }
    
    return sd;
}
 
// InitCTX(): 암호화 통신을 위한 초기화 작업 -> SSL_CTX_new 함수를 이용하여 ssl_ctx 를 생성
// 필요 헤더: openssl/ssl.h, openssl/err.h
SSL_CTX* InitCTX(void) {
    const SSL_METHOD *method; // SSL 버전을 나타냄
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* 에러메시지 문자열들을 로드 Bring in and register error messages */
    method = TLSv1_2_client_method(); /* method 함수를 이용해 클라이언트의 통신 방식을 tls 1.3 프로토콜로 지정 */
    ctx = SSL_CTX_new(method);   /* SSL_new 함수를 이용하여 SSL 구조체 생성 Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort(); // 비정상적 강제 종료
    }
    return ctx;
}
 
// openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout mycert.pem -out mycert.pem
void ShowCerts(SSL* ssl) {
    X509 *cert; // X509 해제 필요
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* 서버의 X509 인증서 가져오기 */
    
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}
 
int main(int count, char *strings[]) {
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    char acClientRequest[1024] ={0};
    int bytes;
    char *hostname, *portnum;
 
    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    
    // 사용 가능한 SSL/TLS 암호 및 다이제스트 등록. 반환값은 항상 1
    // 라이브러리 초기화
    SSL_library_init(); /* /=/SSL_CTX* InitCTX()
                         { ...
                         OpenSSL_add_all_algorithm();
                         //과 동의어. 같이 호출하여 사용해야 함
                         ... }
                         */
    // 인자 받기
    hostname=strings[1];
    portnum=strings[2];
 
    ctx = InitCTX(); // InitCTX() 함수 호출. 초기화 작업
    
    server = OpenConnection(hostname, atoi(portnum));
    
    /* SSL_new 함수를 이용하여 SSL 구조체 생성. */
    ssl = SSL_new(ctx);
    /* SSL_set_fd 함수 -> 현재 소켓과 SSL 연결 */
    SSL_set_fd(ssl, server);
    
    /* handshake 과정. 실패시 반환값 -1 */
    if ( SSL_connect(ssl) == FAIL )
        ERR_print_errors_fp(stderr);
    else {
        // SSL_write 함수를 이용하여 서버에게 메시지를 암호화하여 전송하고, 서버로부터 암호화된 메시지를 받음
        const char *msg = "Hello";
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl); // 인증서
        SSL_write(ssl, msg, strlen(msg));
        
        // SSL_read 함수를 이용하여 서버로 부터 받은 메시지를 복호화하여 확인
        bytes = SSL_read(ssl, buf, sizeof(buf));
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
        
        SSL_free(ssl);
    }
    
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    
    return 0;
}

