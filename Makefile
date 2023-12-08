CFLAGS  = -Wall -Werror -pedantic -fsanitize=address,undefined
SRC     = main.c
CC      = gcc

all: $(SRC)
	$(CC) $(CFLAGS) -o ping $^

fast:
	$(CC) -Wall -Werror -pedantic $(SRC)
