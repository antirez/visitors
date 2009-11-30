# Makefile for visitors
# Copyright (C) 2004 Salvatore Sanfilippo <antirez@invece.org>
# All Rights Reserved
# Under the BSD license (see COPYING)

DEBUG?= -g
CFLAGS?= -O2 -Wall -W
CCOPT= $(CFLAGS)

OBJ = visitors.o aht.o antigetopt.o tail.o
PRGNAME = visitors

all: visitors

visitors.o: visitors.c blacklist.h
visitors: $(OBJ)
	$(CC) -o $(PRGNAME) $(CCOPT) $(DEBUG) $(OBJ)

.c.o:
	$(CC) -c $(CCOPT) $(DEBUG) $(COMPILE_TIME) $<

clean:
	rm -rf $(PRGNAME) *.o
