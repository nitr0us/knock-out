// nitr0us
#include"knock-out.h"

/* Funcion para extraer los valores del archivo de configuracion pasado como
 * primer argumento.
 */
void Parsear_configuracion(const char *file, config_t *conf)
{
	FILE	*fp;
	char	buffer[256], buffer2[256], sec[3][6];
	char	*ptr;
	int	puerto, timeout, i = 0, j = 0;

	if((fp = fopen(file, "r")) == NULL)
		error_n(errno, "fopen");

	bzero(sec, sizeof(sec));

	while(fgets(buffer, 256, fp)){
		if(buffer[0] == '#' || isspace((int) buffer[0]))
			continue;

		strncpy(buffer2, buffer, 256);

		if(stringcomp("Protocolo", strtok(buffer, "="))){
			ptr = strchr(buffer2, (int) '=') + 1;
			if(stringcomp("tcp\n", ptr)){
				strncpy(conf->proto, "tcp", 4);
				debugprint("-=[ Protocolo: %s\n", conf->proto);
			} else if(stringcomp("udp\n", ptr)){
				strncpy(conf->proto, "udp", 4);
				debugprint("-=[ Protocolo: %s\n", conf->proto);
			} else
				error_fp("Protocolo invalido: %s", ptr, fp);
		} else if(stringcomp("Secuencia", buffer)){
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
					error("-=[ Puerto de secuencia invalido: %s\n", sec[i]);
				}

				sec[i][j] = *ptr++;
				j++;
			}

			puerto = atoi(sec[0]);
			if(!PUERTO_VALIDO(puerto))
				error("-=[ Puerto de secuencia invalido: %d\n", puerto);
			conf->sec1 = (unsigned short) puerto;
			debugprint("-=[ Puerto de secuencia[1]: %d\n", conf->sec1);

			puerto = atoi(sec[1]);
			if(!PUERTO_VALIDO(puerto))
				error("-=[ Puerto de secuencia invalido: %d\n", puerto);
			conf->sec2 = (unsigned short) puerto;
			debugprint("-=[ Puerto de secuencia[2]: %d\n", conf->sec2);

			puerto = atoi(sec[2]);
			if(!PUERTO_VALIDO(puerto))
				error("-=[ Puerto de secuencia invalido: %d\n", puerto);

			conf->sec3 = (unsigned short) puerto;
			debugprint("-=[ Puerto de secuencia[3]: %d\n", conf->sec3);
		} else if(stringcomp("Timeout", buffer)){
			ptr = strchr(buffer2, (int) '=') + 1;
			timeout = atoi(ptr);
			if(timeout < 1 || timeout > MAX_TIMEOUT)
				error_fp("Timeout invalido: %d\n", timeout, fp);

			conf->timeout = timeout;
			debugprint("-=[ Timeout: %d segundos\n", conf->timeout);
		} else if(stringcomp("Metodo", buffer)){
			ptr = strchr(buffer2, (int) '=') + 1;
			if(stringcomp("bind\n", ptr))
				strncpy(conf->metodo, "bind", 8);
			else if(stringcomp("reverse\n", ptr))
				strncpy(conf->metodo, "reverse", 8);
			else
				error_fp("Metodo invalido: %s", ptr, fp);

			debugprint("-=[ Metodo: %s\n", conf->metodo);
		} else if(stringcomp("Puerto", buffer)){
			ptr = strchr(buffer2, (int) '=') + 1;
			puerto = atoi(ptr);
			if(PUERTO_VALIDO(puerto)){
				conf->puerto = (unsigned short) puerto;
				debugprint("-=[ Puerto: %d\n", conf->puerto);
			}
			else
				error_fp("Puerto invalido: %d\n", puerto, fp);
		} else
			error_fp("Opcion desconocida: %sSaliendo...\n", buffer2, fp);
	}
}
