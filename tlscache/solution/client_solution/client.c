#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <math.h>

#include <tls.h>

#define NODES 5

static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s ipaddress portnumber\n", __progname);
	exit(1);
}

unsigned long hash(unsigned char *str){
	unsigned long hash = 5381;
	int c;

	while(c = *str++){
		// hash * 33 + c
		hash = ((hash << 5) + hash) + c;
	}
	//printf("value oh hash : %lu\n", hash);
	return hash;
}

int findServer(int *nodes, char *filename){
	unsigned long val, max = 0;
	int port = 0;
	int *tmp, i;

	for(tmp = nodes, i = 0; i < NODES; ++i, ++tmp){
		char numtoStr[4];
		char *concat;
		sprintf(numtoStr, "%d", *tmp);
		concat = strcat(numtoStr, filename);
		//printf("value of iteration : %d\n", i);
		val = hash(concat);
		if(val > max){
			max = val;
			port = i;
		}
	}
	return port;
}

int main(int argc, char *argv[])
{
	struct sockaddr_in server_sa;
	char buffer[80], *ep, *filename;
	size_t maxread;
	ssize_t r, rc;
	u_short port;
	u_long p;
	int sd, i;
	struct tls_config *tls_cfg = NULL;
	struct tls *tls_ctx = NULL;

	// assumption - client knows all proxy servers
	int nodes[NODES] = {7700, 7701, 7702, 7703, 7704};



	if (argc != 4)
		usage();

        p = strtoul(argv[2], &ep, 10);
        if (*argv[2] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[2]);
		usage();
	}
        if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
		/* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		fprintf(stderr, "%s - value out of range\n", argv[2]);
		usage();
	}
	/* now safe to do this */

	// first find proxy that will have file
	int size = strlen(argv[3]);
	char fileArr[size];
	strcpy(fileArr, argv[3]);
	int server = findServer(nodes,fileArr);
	
	//port = p;
	port = nodes[server];

	/* set up TLS */
	if (tls_init() == -1)
		errx(1, "unable to initialize TLS");
	if ((tls_cfg = tls_config_new()) == NULL)
		errx(1, "unable to allocate TLS config");
	if (tls_config_set_ca_file(tls_cfg, "/home/csmajs/clega001/Project/TLSCache/CS165-TLSCache/TLSCache-master/TLSCache-master/certificates/root.pem") == -1)
		errx(1, "unable to set root CA file");

	/*
	 * first set up "server_sa" to be the location of the server
	 */
	memset(&server_sa, 0, sizeof(server_sa));
	server_sa.sin_family = AF_INET;
	server_sa.sin_port = htons(port);
	server_sa.sin_addr.s_addr = inet_addr(argv[1]);
	if (server_sa.sin_addr.s_addr == INADDR_NONE) {
		fprintf(stderr, "Invalid IP address %s\n", argv[1]);
		usage();
	}

	/* ok now get a socket. */
	if ((sd=socket(AF_INET,SOCK_STREAM,0)) == -1)
		err(1, "socket failed");

	/* connect the socket to the server described in "server_sa" */
	if (connect(sd, (struct sockaddr *)&server_sa, sizeof(server_sa)) == -1)
		err(1, "connect failed");

	if ((tls_ctx = tls_client()) == NULL)
		errx(1, "tls client creation failed");
	if (tls_configure(tls_ctx, tls_cfg) == -1)
		errx(1, "tls configuration failed (%s)", tls_error(tls_ctx));
	if (tls_connect_socket(tls_ctx, sd, "localhost") == -1)
		errx(1, "tls connection failed (%s)", tls_error(tls_ctx));


	do {
		if ((i = tls_handshake(tls_ctx)) == -1)
			errx(1, "tls handshake failed (%s)", tls_error(tls_ctx));
	} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);

	/*
	 * finally, we are connected. find out what magnificent wisdom
	 * our server is going to send to us - since we really don't know
	 * how much data the server could send to us, we have decided
	 * we'll stop reading when either our buffer is full, or when
	 * we get an end of file condition from the read when we read
	 * 0 bytes - which means that we pretty much assume the server
	 * is going to send us an entire message, then close the connection
	 * to us, so that we see an end-of-file condition on the read.
	 *
	 * we also make sure we handle EINTR in case we got interrupted
	 * by a signal.
	 */
	
	// send message
	char toSend[80] = "Chicken is some pretty good stuff...\n";
	ssize_t written, w;

	w = 0;
	written = 0;
	while (written < strlen(fileArr)) {
		w = tls_write(tls_ctx, fileArr + written, strlen(fileArr) - written);

		if (w == TLS_WANT_POLLIN || w == TLS_WANT_POLLOUT)
			continue;
		if (w < 0) {
			errx(1, "TLS write failed (%s)", tls_error(tls_ctx));
		}
		else
			written += w;
	}








	
	// close connection 
	
	/*
	 * we must make absolutely sure buffer has a terminating 0 byte
	 * if we are to use it as a C string
	 */
	buffer[rc] = '\0';

	printf("Finished handshake\n");
	//printf("Server sent:  %s",buffer);
	
	close(sd);
	return(0);
}
