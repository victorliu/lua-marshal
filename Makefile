LUA_INC = -I/usr/include/lua5.2

CFLAGS = -Wall -O0 -ggdb

all: marshal.so	
	lua simple_test.lua
	
lmarshal.o: lmarshal.c
	gcc -c $(CFLAGS) $(LUA_INC) -fpic -Wall -I. $< -o $@
marshal.so: lmarshal.o
	gcc $(CFLAGS) -shared -fpic -Wall $(LUA_INCLUDE) -o $@ $^
clean:
	rm -f *.o *.so