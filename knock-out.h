#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<signal.h>
#include<unistd.h>
#include<ctype.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>

/* Numero de segundos entre el toque de un puerto y otro, y obvio, debe ser
   menor que el timeout especificado en el servidor (knock-outd) por que de
   otro modo no funcionara. */
#define NSECS		3  // Segundos
#define MAX_TIMEOUT	60 // Segundos
/* Flag TCP para tocar en los puertos (Solo valido para proto=tcp) */
#define FLAG_KNOCK_TCP	TH_RST

#define error(texto, args)	do{\
	fprintf(stderr, texto, args);\
	exit(EXIT_FAILURE);\
	} while(0)

#define error_n(codigo, texto)	do{\
	fprintf(stderr, "%s:%d: %s - %s\n",\
		__FILE__, __LINE__, texto, strerror(codigo));\
	exit(EXIT_FAILURE);\
	} while(0)

#define error_fp(texto, arg, fp)	do{\
	fprintf(stderr, texto, arg);\
	fclose(fp);\
	exit(EXIT_FAILURE);\
	} while(0)

#define stringcomp(str1, str2)	(strcmp(str1, str2) == 0)
#define PUERTO_VALIDO(puerto)	((puerto > 0 && puerto < 65536) ? 1 : 0)
#define FLAGS_VALIDAS(flags)	((flags & FLAG_KNOCK_TCP) ? 1 : 0)

#ifdef	DEBUG
#define debugprint	printf("[DEBUG] "); printf
#else
#define debugprint	//
#endif

typedef struct configuracion{
	unsigned short	sec1;
	unsigned short	sec2;
	unsigned short	sec3;
	unsigned short	puerto;
	char		proto[4];
	char		metodo[8];
	int		timeout;
} config_t;

struct lcooked_hdr{
	u_int16_t	type;
	u_int16_t	arphdr;
	u_int16_t	lenlinkaddr;
	u_int8_t	llayerhdr[8];
	u_int16_t	proto;
};

/*** PROTOTIPOS ***/
void Parsear_configuracion(const char *, config_t *);
void Bind(unsigned short);
void Reverse(const char *, unsigned short);
void uso(char *);
void interrupcion(int); // Manejador de senal SIGINT
void alarma(); // Manejador de la senal SIGALRM (enviada al ocurrir un timeout)
void recargar_config(); // Manejador de la senal SIGHUP (comunmente usada para recargar archivos de configuracion)
char *obtener_ip_disp(const char *);
