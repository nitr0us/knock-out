CC = gcc
CFLAGS = -ggdb -O2 -DDEBUG -Wall
SERVER_OBJS = knock-outd.o parser.o bind.o reverse.o
CLIENT_OBJS = knock-outc.o parser.o

all:
	@echo ""
	@echo "Select an option:"
	@echo ""
	@echo "make server"
	@echo "make client"
	@echo "make clean"
	@echo ""

server: $(SERVER_OBJS)
	$(CC) $(SERVER_OBJS) $(CFLAGS) -lpcap -o knock-outd

client: $(CLIENT_OBJS)
	$(CC) $(CLIENT_OBJS) $(CFLAGS) -lnet -o knock-outc

clean:
	@echo "rm -f knock-outd knock-outc *.o"
	@rm -f knock-outd knock-outc *.o

$(SERVER_OBJS) $(CLIENT_OBJS): knock-out.h
