#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define CONFIG_FILE	"knock-out.conf"

#define NSECS		3  // Default Timeout (knock-out.conf) in seconds between each port knock
#define MAX_TIMEOUT	60

#define FLAG_KNOCK_TCP	TH_RST // TCP flag needed on each packet (only if TCP used)

#define error(msg, args)	do{\
		fprintf(stderr, msg, args);\
		exit(EXIT_FAILURE);\
	} while(0)

#define error_n(code_n, msg)	do{\
		fprintf(stderr, "%s:%d: %s - %s\n",\
		__FILE__, __LINE__, msg, strerror(code_n));\
		exit(EXIT_FAILURE);\
	} while(0)

#define error_fp(msg, arg, fp)	do{\
		fprintf(stderr, msg, arg);\
		fclose(fp);\
		exit(EXIT_FAILURE);\
	} while(0)

#define stringcomp(str1, str2)	(strcmp(str1, str2) == 0)
#define VALID_PORT(port)	((port > 0 && port < 65536) ? 1 : 0)
#define VALID_FLAGS(flags)	((flags & FLAG_KNOCK_TCP) ? 1 : 0)

#ifdef	DEBUG
#define debugprint	printf
#else
#define debugprint	//
#endif

typedef struct config{
	unsigned short	sec1;
	unsigned short	sec2;
	unsigned short	sec3;
	unsigned short	port;
	char		proto[4];
	char		method[8];
	int		timeout;
} config_t;

struct lcooked_hdr{
	u_int16_t	type;
	u_int16_t	arphdr;
	u_int16_t	lenlinkaddr;
	u_int8_t	llayerhdr[8];
	u_int16_t	proto;
};

void usage(char *);
void Parse_config(config_t *);
void Reload_config(); // SIGHUP handler
void Bind(unsigned short);
void Reverse(const char *, unsigned short);
void sigint_handler(int); // SIGINT handler
void sigalrm_handler(); // SIGALRM handler (sent when timeout is reached)
char *get_IP(const char *);
