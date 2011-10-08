#Makefile for MYDNS
#Author: Petr Nohejl (xnohej00)

CC=g++
LIBS=-lm -lpcrecpp
FLAGS=-std=c++98 -pedantic -Wall
FILES=Makefile mydns.h mydns.cpp config testuj
PROG=mydns

all: mydns.o
	$(CC) $(FLAGS) $(LIBS) -o $(PROG) mydns.o

mydns.o: mydns.cpp
	$(CC) -c $(FLAGS) -o $@ $<

clean:
	rm -rf *o *~ $(PROG)

pack:
	tar -zcvf xnohej00.tar.gz $(FILES)
