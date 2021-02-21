# Main purpuse is to test stuff

CC=g++
CFLAGS=-std=c++11

all:
	$(CC) $(CFLAGS) test.cpp -o test
clean:
	rm test
