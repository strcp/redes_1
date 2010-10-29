CC = gcc
CFLAGS = -Wall -ansi -lpthread
EXEC = disturber
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

all:
	cd src && $(MAKE)

.PHONY: clean mrproper

clean:
	cd src/ && $(MAKE) clean
	rm -rf docs/refs

pkgtest:
	cd src && $(MAKE) pkgtest
