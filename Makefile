CC = gcc
CFLAGS = -ggdb -O2 -DDEBUG -Wall
OBJETOS_SERVIDOR = knock-outd.o parser.o bind.o reverse.o
OBJETOS_CLIENTE = knock-outc.o parser.o

all:
	@echo ""
	@echo "Especifica una opcion:"
	@echo "make servidor"
	@echo "make cliente"
	@echo "make clean"
	@echo ""
	@echo "#Nota: Si no quieres ver informacion de debug, borra "-DDEBUG" de CFLAGS. (no recomendado)"

servidor: $(OBJETOS_SERVIDOR)
	$(CC) $(OBJETOS_SERVIDOR) $(CFLAGS) -lpcap -o knock-outd

cliente: $(OBJETOS_CLIENTE)
	$(CC) $(OBJETOS_CLIENTE) $(CFLAGS) -lnet -o knock-outc

clean:
	@echo "rm -f knock-outd knock-outc *.o"
	@rm -f knock-outd knock-outc *.o

$(OBJETOS_SERVIDOR) $(OBJETOS_CLIENTE): knock-out.h
