ifeq ($(CONF),Debug)
	CFLAGS = $(CONF:) -g
	DEBUG_POSTFIX = d
endif

all: main$(DEBUG_POSTFIX).o
	gcc -o main$(DEBUG_POSTFIX) main$(DEBUG_POSTFIX).o -lcrypto

main$(DEBUG_POSTFIX).o: main.c
	gcc $(CFLAGS) -c main.c -o main$(DEBUG_POSTFIX).o

clean:
	rm -f main maind *.o
