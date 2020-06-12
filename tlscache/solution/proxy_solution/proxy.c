#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

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

#define NODES 5		 // number of servers
#define CACHE 100	 // number of elements in cache

// PROXY

static void usage()
{
	extern char * __progname;
	fprintf(stderr, "usage: %s portnumber\n", __progname);
	exit(1);
}

static void kidhandler(int signum) {
	/* signal handler for SIGCHLD */
	waitpid(WAIT_ANY, NULL, WNOHANG);
}

// using hash functions from 
// http://www.cse.yorku.ca/~oz/hash.html

int hash1(unsigned char *str){
	unsigned long hash = 5381;
	int c;
	
	while(c = *str++){
		// hash * 33 + c
		hash = ((hash << 5) + hash) + c;
	}
	return hash % CACHE;
}

int hash2(unsigned char *str){
	unsigned long hash = 0;
	int c;

	while(c = *str++){
		hash = c + (hash << 16) + (hash << 16) - hash;
	}
	return hash % CACHE;
}

int hash3(unsigned char *str){
	unsigned long hash = 0;
	int c;

	while(c = *str++){
		hash += c;
	}
	return hash % CACHE;
}

bool checkBloomFilter(int *cache, int hash1, int hash2, int hash3){
		

	if(*(cache + hash1) && *(cache + hash2)  && *(cache + hash3)){
		return true;
	} else { return false; }
}

void addBloomFilter(int *cache, int hash1, int hash2, int hash3){

}

int main(int argc,  char *argv[])
{
	struct sockaddr_in sockname, client;
	char buffer[80], *ep;
	struct sigaction sa;
	int sd, i;
	socklen_t clientlen;
	u_short port;
	pid_t pid;
	u_long p;
	struct tls_config *tls_cfg = NULL; // TLS config
	struct tls *tls_ctx = NULL; // TLS context
	struct tls *tls_cctx = NULL; // client's TLS context

	// build cache
	int cache[CACHE] = {0};
	char itemsInCache[CACHE][CACHE]; 
		

	/*
	 * first, figure out what port we will listen on - it should
	 * be our first parameter.
	 */

	if (argc != 2)
		usage();
		errno = 0;
        p = strtoul(argv[1], &ep, 10);
        if (*argv[1] == '\0' || *ep != '\0') {
		/* parameter wasn't a number, or was empty */
		fprintf(stderr, "%s - not a number\n", argv[1]);
		usage();
	}
        if ((errno == ERANGE && p == ULONG_MAX) || (p > USHRT_MAX)) {
		/* It's a number, but it either can't fit in an unsigned
		 * long, or is too big for an unsigned short
		 */
		fprintf(stderr, "%s - value out of range\n", argv[1]);
		usage();
	}
	/* now safe to do this */
	port = p;

	/* set up TLS */
	if ((tls_cfg = tls_config_new()) == NULL)
		errx(1, "unable to allocate TLS config");
	if (tls_config_set_ca_file(tls_cfg, "/home/csmajs/clega001/Project/TLSCache/CS165-TLSCache/TLSCache-master/TLSCache-master/certificates/root.pem") == -1)
		errx(1, "unable to set root CA file");
	if (tls_config_set_cert_file(tls_cfg, "/home/csmajs/clega001/Project/TLSCache/CS165-TLSCache/TLSCache-master/TLSCache-master/certificates/server.crt") == -1) 
		errx(1, "unable to set TLS certificate file, error: (%s)", tls_config_error(tls_cfg));
	if (tls_config_set_key_file(tls_cfg, "/home/csmajs/clega001/Project/TLSCache/CS165-TLSCache/TLSCache-master/TLSCache-master/certificates/server.key") == -1)
		errx(1, "unable to set TLS key file");
	if ((tls_ctx = tls_server()) == NULL)
		errx(1, "TLS server creation failed");
	if (tls_configure(tls_ctx, tls_cfg) == -1)
		errx(1, "TLS configuration failed (%s)", tls_error(tls_ctx));

	/* the message we send the client */
	strlcpy(buffer,
	    "It was the best of times, it was the worst of times... \n",
	    sizeof(buffer));

	memset(&sockname, 0, sizeof(sockname));
	sockname.sin_family = AF_INET;
	sockname.sin_port = htons(port);
	sockname.sin_addr.s_addr = htonl(INADDR_ANY);
	sd=socket(AF_INET,SOCK_STREAM,0);
	if ( sd == -1)
		err(1, "socket failed");

	if (bind(sd, (struct sockaddr *) &sockname, sizeof(sockname)) == -1)
		err(1, "bind failed");

	if (listen(sd,3) == -1)
		err(1, "listen failed");

	/*
	 * we're now bound, and listening for connections on "sd" -
	 * each call to "accept" will return us a descriptor talking to
	 * a connected client
	 */


	/*
	 * first, let's make sure we can have children without leaving
	 * zombies around when they die - we can do this by catching
	 * SIGCHLD.
	 */
	sa.sa_handler = kidhandler;
        sigemptyset(&sa.sa_mask);
	/*
	 * we want to allow system calls like accept to be restarted if they
	 * get interrupted by a SIGCHLD
	 */
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &sa, NULL) == -1)
                err(1, "sigaction failed");

	/*
	 * finally - the main loop.  accept connections and deal with 'em
	 */
	printf("Server up and listening for connections on port %u\n", port);
	for(;;) {
		int clientsd;
		clientlen = sizeof(&client);
		clientsd = accept(sd, (struct sockaddr *)&client, &clientlen);
		if (clientsd == -1)
			err(1, "accept failed");
		/*
		 * We fork child to deal with each connection, this way more
		 * than one client can connect to us and get served at any one
		 * time.
		 */

		pid = fork();
		if (pid == -1)
		     err(1, "fork failed");

		if(pid == 0) {
			ssize_t written, w;
			i = 0;
			if (tls_accept_socket(tls_ctx, &tls_cctx, clientsd) == -1)
				errx(1, "tls accept failed (%s)", tls_error(tls_ctx));
			else {
				do {
					if ((i = tls_handshake(tls_cctx)) == -1)
						errx(1, "tls handshake failed (%s)", tls_error(tls_ctx));
				} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);
			}

			/*
			 * write the message to the client, being sure to
			 * handle a short write, or being interrupted by
			 * a signal before we could write anything.
			 */

		
			// recieve message
			ssize_t r,rc;
			size_t maxread;
			char toRec[80];
			r = -1;
			rc = 0;


			maxread = sizeof(toRec) - 1;
			while ((r != 0) && rc < maxread) {
				r = tls_read(tls_cctx, toRec + rc, maxread - rc);
				if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT)
					continue;
				
				if (r < 0) {
					err(1, "tls_read failed (%s)", tls_error(tls_ctx));
				} else
					rc += r;
			}

			toRec[rc] = '\0';
			printf("Message received : %si\n", toRec);


			// check cache for file
			bool c = checkBloomFilter(cache, hash1(toRec), hash2(toRec), hash3(toRec));

			printf("in cache (using bloom filter) ??? : %d", c);


			if(c){
				//return file to client
			} else {
				// connect to main server
				//
				//
				// add file to cache & bloom filter
				//
				//
				// return filed to client
				//
				//
				// close
			}

			// close connection
			i = 0;
			do {
				i = tls_close(tls_cctx);
			} while(i == TLS_WANT_POLLIN || i == TLS_WANT_POLLOUT);

			close(clientsd);
			exit(0);
		}
		close(clientsd);
	}
}
