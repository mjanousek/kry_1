CC=g++
CFLAGS=-std=c++11 -pedantic -lcrypto -lssl



proj:
	$(CC) proj.cpp -o $@ $(CFLAGS)