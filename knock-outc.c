/*
 * Knock-OutC - Programa Cliente
 *
 * nitr0us
 *
 */
#include"knock-out.h"
#include<libnet.h>

int main(int argc, char **argv)
{
	config_t	configuracion;
	struct hostent	*hostinfo;
	struct in_addr	ip;
	int		k;
	char		conf[256], errbuf[LIBNET_ERRBUF_SIZE], *errptr = NULL;
	libnet_t	*contexto;

	if(getuid() != (uid_t) 0){
		fprintf(stderr, "Necesitas privilegios de root(uid=0)\n");
		exit(EXIT_FAILURE);
	}

	if(argc != 3){
		fprintf(stderr, "Uso: %s <host|ip_knock-outd> <archivo_de_configuracion>\n", *argv);
		exit(EXIT_FAILURE);
	}

	if((hostinfo = gethostbyname(argv[1])) == NULL){
		herror("gethostbyname()");
		exit(EXIT_FAILURE);
	}

	memcpy(&ip, hostinfo->h_addr, 4);

	/** ENCABEZADO **/
	printf("-=[-----------------------------------------]=-\n");
	printf("-=[-- Knock-Outc : Portknock shell Client --]=-\n");
	printf("-=[-----------------------------------------]=-\n");
	printf("-=[----- Por: A. Alejandro Hernandez^2 -----]=-\n");
	printf("-=[---- nitrousenador[en]gmail[punto]com ---]=-\n");
	printf("-=[--------------=[ nITROUs ]=--------------]=-\n");
	printf("-=[-----------------------------------------]=-\n");
	printf("-=[---------- Mexico - 27/Jul/06 -----------]=-\n");
	printf("-=[-----------------------------------------]=-\n\n");
	/** ENCABEZADO **/

	debugprint("<===== CONFIGURACION =====>\n");
	strncpy(conf, (const char *) argv[2], (size_t) 255);
	conf[255] = '\0';
	Parsear_configuracion(conf, &configuracion);
	debugprint("Configuracion [OK]\n");

	debugprint("<===== LIBNET =====>\n");

	for(k = 0; k < 3; k++){
		sleep(NSECS); // Duerme NSECS segundos entre puerto y puerto

		if((contexto = libnet_init(LIBNET_RAW4,\
						NULL,\
						errbuf)) == NULL){
			fprintf(stderr, "libnet_init(): %s\n", errbuf);
			goto terminar;
		}
		debugprint("[Paquete %d] libnet_init():\t[OK]\n", k + 1);

		if(stringcomp("tcp", configuracion.proto)){
			if(libnet_build_tcp((u_int16_t) rand(),		/* puerto fuente */
						(u_int16_t) (k == 0 ? configuracion.sec1 : k == 1 ? configuracion.sec2 : configuracion.sec3), /* puerto destino */
						(u_long) random(),	/* numero de secuencia */
						(u_long) random(),	/* acuse de recibo */
						FLAG_KNOCK_TCP,		/* flags */
						0xffff,			/* tamano de ventana */
						0,			/* checksum */
						0,			/* puntero de urgente */
						LIBNET_TCP_H,		/* tamano del paquete de esta capa y subsecuentes */
						NULL,			/* payload */
						0,			/* tamano de payload */
						contexto,		/* contexto de libnet */
						0) == -1){		/* libnet ptag */
				if((errptr = libnet_geterror(contexto)) != NULL)
					fprintf(stderr, "libnet_build_tcp(): %s\n", errptr);
				else
					fprintf(stderr, "Error: libnet_build_tcp()\n");
				goto terminar;
			}
			debugprint("[Paquete %d] libnet_build_tcp():\t[OK]\n", k + 1);
		} else{ /* udp */
			if(libnet_build_udp((u_int16_t) rand(),		/* puerto fuente */
						(u_int16_t) (k == 0 ? configuracion.sec1 : k == 1 ? configuracion.sec2 : configuracion.sec3), /* puerto destino */
						LIBNET_UDP_H,		/* tamano del paquete de esta capa y subsecuentes */
						0,			/* checksum */
						NULL,			/* payload */
						0,			/* tamano de payload */
						contexto,		/* contexto de libnet */
						0) == -1){		/* libnet ptag */
				if((errptr = libnet_geterror(contexto)) != NULL)
					fprintf(stderr, "libnet_build_udp(): %s\n", errptr);
				else
					fprintf(stderr, "Error: libnet_build_udp()\n");
				goto terminar;
			}
			debugprint("[Paquete %d] libnet_build_udp():\t[OK]\n", k + 1);
		}

		if(libnet_build_ipv4(LIBNET_IPV4_H + stringcomp("tcp", configuracion.proto) ? LIBNET_TCP_H : LIBNET_UDP_H, /* tamano del paquete de esta capa y subsecuentes */
					0,				/* tipo de servicio */
					0,				/* IP id */
					0,				/* fragmentacion */
					0xff,				/* tiempo de vida */
					stringcomp("tcp", configuracion.proto) ? IPPROTO_TCP : IPPROTO_UDP, /* protocolo de la capa siguiente */
					0,				/* checksum */
					0,				/* IP fuente */
					(u_int32_t) ip.s_addr,		/* IP destino */
					NULL,				/* payload */
					0,				/* tamano de payload */
					contexto,			/* contexto de libnet */
					0) == -1){			/* libnet ptag */
			if((errptr = libnet_geterror(contexto)) != NULL)
				fprintf(stderr, "libnet_build_ipv4(): %s\n", errptr);
			else
				fprintf(stderr, "Error: libnet_build_ipv4()\n");
			goto terminar;
		}
		debugprint("[Paquete %d] libnet_build_ip():\t[OK]\n", k + 1);

		if(libnet_write(contexto) == -1){
			if((errptr = libnet_geterror(contexto)) != NULL)
				fprintf(stderr, "libnet_write(): %s\n", errptr);
			else
				fprintf(stderr, "Error: libnet_write()\n");
			goto terminar;
		}
		debugprint("[Paquete %d] libnet_write():\t[OK]\n", k + 1);

		libnet_destroy(contexto);
		debugprint("[Paquete %d] libnet_destroy():\t[OK]\n", k + 1);

		debugprint("Tocado el puerto %d en %s\n", k == 0 ? configuracion.sec1 : k == 1 ? configuracion.sec2 : configuracion.sec3,\
			inet_ntoa(ip));
	}

	debugprint("Listo!...\n");
	printf("NOTA: El metodo es %s, por lo tanto ", configuracion.metodo);
	if(stringcomp("bind", configuracion.metodo)){
		printf("debes conectar al puerto %d de la\n", configuracion.puerto);
		printf("maquina %s al terminar de tocar.\n", argv[1]);
	} else{
		printf("debes tener el puerto %d escuchando\n", configuracion.puerto);
		printf("en esta maquina.\n");
	}

	exit(EXIT_SUCCESS);

terminar:
	libnet_destroy(contexto);
	exit(EXIT_FAILURE);
}

void interrupcion(int signum)
{
	debugprint("Senal recibida [%d]: %s\n", signum, sys_siglist[signum]);
	debugprint("Saliendo...\n");

	exit(EXIT_SUCCESS);
}
