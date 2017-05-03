#include "knock-out.h"

void Parse_config(config_t *conf)
{
	FILE	*fp;
	char	buffer[256], buffer2[256], sec[3][6];
	char	*ptr;
	int	port, timeout, i = 0, j = 0;

	if((fp = fopen(CONFIG_FILE, "r")) == NULL)
		error_n(errno, "fopen");

	bzero(sec, sizeof(sec));

	while(fgets(buffer, 256, fp)){
		if(buffer[0] == '#' || isspace((int) buffer[0]))
			continue;

		strncpy(buffer2, buffer, 256);

		if(stringcomp("Protocol", strtok(buffer, "="))){
			ptr = strchr(buffer2, (int) '=') + 1;
			if(stringcomp("tcp\n", ptr)){
				strncpy(conf->proto, "tcp", 4);
				debugprint("-=[ Protocol: %s\n", conf->proto);
			} else if(stringcomp("udp\n", ptr)){
				strncpy(conf->proto, "udp", 4);
				debugprint("-=[ Protocol: %s\n", conf->proto);
			} else
				error_fp("Invalid Protocol: %s", ptr, fp);
		} else if(stringcomp("Sequence", buffer)){
			ptr = strchr(buffer2, (int) '=') + 1;
			while(*ptr){
				if(*ptr == ',' || *ptr == '\n'){
					i++;
					sec[i][j] = '\0';
					j = 0;
					ptr++;
					continue;
				}

				if(j == 5){
					sec[i][j] = '\0';
					error("-=[ Invalid port in Sequence: %s\n", sec[i]);
				}

				sec[i][j] = *ptr++;
				j++;
			}

			port = atoi(sec[0]);
			if(!VALID_PORT(port))
				error("-=[ Invalid port in Sequence: %d\n", port);
			conf->sec1 = (unsigned short) port;
			debugprint("-=[ Sequence port [1]: %d\n", conf->sec1);

			port = atoi(sec[1]);
			if(!VALID_PORT(port))
				error("-=[ Invalid port in Sequence: %d\n", port);
			conf->sec2 = (unsigned short) port;
			debugprint("-=[ Sequence port [2]: %d\n", conf->sec2);

			port = atoi(sec[2]);
			if(!VALID_PORT(port))
				error("-=[ Invalid port in Sequence: %d\n", port);
			conf->sec3 = (unsigned short) port;
			debugprint("-=[ Sequence port [3]: %d\n", conf->sec3);
		} else if(stringcomp("Timeout", buffer)){
			ptr = strchr(buffer2, (int) '=') + 1;
			timeout = atoi(ptr);
			if(timeout < 1 || timeout > MAX_TIMEOUT)
				error_fp("Invalid Timeout: %d\n", timeout, fp);

			conf->timeout = timeout;
			debugprint("-=[ Timeout: %d seconds\n", conf->timeout);
		} else if(stringcomp("Method", buffer)){
			ptr = strchr(buffer2, (int) '=') + 1;
			if(stringcomp("bind\n", ptr))
				strncpy(conf->method, "bind", 8);
			else if(stringcomp("reverse\n", ptr))
				strncpy(conf->method, "reverse", 8);
			else
				error_fp("Invalid Method: %s", ptr, fp);

			debugprint("-=[ Method: %s\n", conf->method);
		} else if(stringcomp("Port", buffer)){
			ptr = strchr(buffer2, (int) '=') + 1;
			port = atoi(ptr);
			if(VALID_PORT(port)){
				conf->port = (unsigned short) port;
				debugprint("-=[ Port: %d\n", conf->port);
			}
			else
				error_fp("Invalid Port: %d\n", port, fp);
		} else
			error_fp("Unknown option: %s\nExiting...\n", buffer2, fp);
	}
}
