CC = gcc
CFLAGS = -g -W -Wall -I../include -lpthread
EXEC = disturber
SRC = $(wildcard *.c)
OBJ = disturber.o

all: $(EXEC)

disturber: disturber.o $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

.PHONY: clean mrproper
clean:
	rm -rf *.o
	rm -rf $(EXEC)

