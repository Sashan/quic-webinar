all: 	quic_singlestream	\
	quic_broken		\
	quic_multistream

CFLAGS += -g -O0

quic_singlestream: quic_singlestream.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o quic_singlestream quic_singlestream.c \
	    $(LDFLAGS) -lssl -lcrypto

quic_broken: quic_singlestream.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -D ENABLE_VERIFY_PEER -o quic_broken \
	    quic_singlestream.c $(LDFLAGS) -lssl -lcrypto

quic_multistream: quic_multistream.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -o quic_multistream quic_multistream.c \
	    $(LDFLAGS) -lssl -lcrypto

clean:
	rm -f quic_singlestream quic_broken quic_multistream
