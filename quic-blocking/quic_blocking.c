#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define	BUF_LEN	2048

static BIO_ADDR *
make_bio_addr(const char *ip_addr, const char *port)
{
 	BIO_ADDR	*bio_addr;
	struct in_addr	 ina;
	int		 e;
	short		 p;

	if (inet_aton(ip_addr, &ina) == 0) {
		fprintf(stderr, "%s invalid ip address (%s)\n",
		    __func__, ip_addr);
		return (NULL);
	}

	e = atoi(port);
	if ((e < 1) || (e > 65535)) {
		fprintf(stderr, "%s invalid port (%s)\n",
		    __func__, port);
		return (NULL);
	}
	p = (short)e;

	bio_addr = BIO_ADDR_new();
	if (bio_addr == NULL) {
		fprintf(stderr, "%s %s\n", __func__, strerror(errno));;
		return (NULL);
	}

	e = BIO_ADDR_rawmake(bio_addr, AF_INET, &ina, sizeof (ina), htons(p));
	if (e == 0) {
		fprintf(stderr, "%s BIO_ADDR_rawmake() error (%s)\n",
		    __func__, strerror(errno));;
		BIO_ADDR_free(bio_addr);
		return (NULL);
	}

	return (bio_addr);
}

static BIO *
make_udp_bio(int udp_sock, BIO_ADDR *bio_addr)
{
	BIO	*udp_bio;

	if (!BIO_socket_nbio(udp_sock, 1)) {
		fprintf(stderr, "%s BIO_socket_nbio: %s\n",
		    __func__, strerror(errno));
		return (NULL);
	}

	udp_bio = BIO_new_dgram(udp_sock, 0);
	if (udp_bio == NULL) {
		fprintf(stderr, "%s BIO_new_dgram: %s\n",
		    __func__, strerror(errno));
		return (NULL);
	}

	if (!BIO_dgram_set_peer(udp_bio, bio_addr)) {
		fprintf(stderr, "%s BIO_dgram_set_peer: %s\n",
		    __func__, strerror(errno));
		BIO_free(udp_bio);
		return (NULL);
	}

	return (udp_bio);
}

static SSL_CTX *
make_ssl_ctx(void)
{
	SSL_CTX		*ssl_ctx;

	ssl_ctx = SSL_CTX_new(OSSL_QUIC_client_thread_method());
	if (ssl_ctx == NULL) {
		fprintf(stderr, "SSL_CTX_new failed\n");
		return (NULL);
	}
#ifdef	ENABLE_VERIFY_PEER
	/* uncomment to break it */
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
	if (SSL_CTX_set_default_verify_paths(ssl_ctx) == 0) {
		fprintf(stderr, "SSL_CTX_set_default_verify_paths failed\n");
		SSL_CTX_free(ssl_ctx);
		return (NULL);
	}
#endif

	return (ssl_ctx);
}

static SSL *
make_ssl(SSL_CTX *ssl_ctx, BIO *udp_bio)
{
	SSL			*ssl;
	static unsigned char	 alpn[] = {
	    8, 'h', 't', 't', 'p', '/', '0', '.', '9'
	};

	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		fprintf(stderr, "%s SSL_new() failed\n", __func__);
		return (NULL);
	}

	if (SSL_set_alpn_protos(ssl, alpn, sizeof (alpn)) != 0) {
		fprintf(stderr, "%s SSL_set_alpn_protos() failed\n", __func__);
		SSL_free(ssl);
		return (NULL);
	}

	SSL_set0_rbio(ssl, udp_bio);
	if (BIO_up_ref(udp_bio) == 0) {
		fprintf(stderr, "%s BIO_upref(rbio)\n", __func__);
		SSL_free(ssl);
		return (NULL);
	}

	SSL_set0_wbio(ssl, udp_bio);

	if (!SSL_set_blocking_mode(ssl, 1)) {
		char	buf[512];
		fprintf(stderr, "%s SSL_set_blocking_mode: %s\n",
		    __func__, ERR_error_string(SSL_get_error(ssl, 0), buf));
		SSL_free(ssl);
		return (NULL);
	}

	return (ssl);
}

int
main(int argc, const char *argv[])
{
	SSL_CTX			*ssl_ctx;
	SSL			*ssl;
	SSL			*ssl_stream;
	int			 udp_sock;
	BIO			*udp_bio;
	BIO_ADDR		*daddr_bio;
	char			 buf[BUF_LEN];
	const char		 req[] = "GET LICENSE.txt\r\n";
	int			 rcvd, sent;

	if (argc < 3) {
		fprintf(stderr, "usage %s server_ip port\n", argv[0]);
		return (1);
	}

	daddr_bio = make_bio_addr(argv[1], argv[2]);
	if (daddr_bio == NULL)
		return (1);

	udp_sock = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0);
	if (udp_sock == -1) {
		fprintf(stderr, "BIO_socket: %s\n", strerror(errno));
		BIO_ADDR_free(daddr_bio);
		return (1);
	}

	udp_bio = make_udp_bio(udp_sock, daddr_bio);
	if (udp_bio == NULL) {
		BIO_ADDR_free(daddr_bio);
		BIO_closesocket(udp_sock);
		return (1);
	}
	BIO_ADDR_free(daddr_bio);
	daddr_bio = NULL;

	ssl_ctx = make_ssl_ctx();
	if (ssl_ctx == NULL) {
		BIO_free(udp_bio);
		BIO_closesocket(udp_sock);
		return (1);
	}

	ssl = make_ssl(ssl_ctx, udp_bio);
	if (ssl == NULL) {
		BIO_free(udp_bio);
		SSL_CTX_free(ssl_ctx);
		BIO_closesocket(udp_sock);
		return (1);
	}
	udp_bio = NULL;	/* onnership transferred to ssl */

	if (SSL_connect(ssl) != 1) {
		fprintf(stderr, "SSL_connect() failed %s\n",
		    ERR_error_string(SSL_get_error(ssl, 0), buf));
		SSL_free(ssl);
		SSL_CTX_free(ssl_ctx);
		return (1);
	}

	if ((sent = SSL_write(ssl, req, sizeof (req) - 1)) !=
	    (sizeof (req) - 1)) {
		fprintf(stderr, "SSL_write() failed %s\n",
		    ERR_error_string(SSL_get_error(ssl, sent), buf));
		SSL_shutdown(ssl);
		SSL_free(ssl);
		SSL_CTX_free(ssl_ctx);
		return (1);
	}

	while ((rcvd = SSL_read(ssl, buf, sizeof (buf))) > 0)
		write(1, buf, rcvd);

	if (rcvd < 0) {
		fprintf(stderr, "SSL_read() failed %s\n",
		    ERR_error_string(SSL_get_error(ssl, rcvd), buf));
		SSL_shutdown(ssl);
		SSL_free(ssl);
		SSL_CTX_free(ssl_ctx);
		return (1);
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	SSL_CTX_free(ssl_ctx);

	return (0);
}

