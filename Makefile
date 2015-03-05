# 
# Simple makefile for testdes utilities
#
CC	= gcc
CCOPTS	= -O2
IDIR	=.
CFLAGS	=-I$(IDIR) $(CCOPTS)
LDFLAGS	= -L ./
LIBS	=
DEPS	=
OBJ 	= testdes.o desutils.o

%.o:		%.c $(DEPS)
		$(CC) -c -o $@ $< $(CFLAGS)

all:	testdes

testdes:	$(OBJ)
		$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *~ *.o core

cleanall:
	rm -f *~ *.o core testdes

install:
	install -s testdes /usr/local/sbin

