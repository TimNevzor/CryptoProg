target =  m
sources = main.cpp
CC = g++
LDLIBS = -lcrypto++
all:build
build:
	$(CC) $(sources) -o $(target) $(LDLIBS)
dbg:
	$(CC) -g $(sources) -o $(target)DBG
clean:
	rm -f $(target) $(DEBUG_EXEC)
