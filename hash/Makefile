target =  m
sources = sha256.cpp 
CC = g++
LDLIBS = -lcryptopp
all:build
build:
	$(CC) $(sources) -o $(target) $(LDLIBS)
dbg:
	$(CC) -g $(sources) -o $(target)DBG
clean:
	rm -f $(target) $(DEBUG_EXEC)
