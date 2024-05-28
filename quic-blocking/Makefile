all: 	quic_blocking
CFLAGS += -g -O0

quic_blocking: quic_blocking.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o quic_blocking quic_blocking.c $(LDFLAGS) -lssl -lcrypto
clean:
	rm -f quic_blocking
