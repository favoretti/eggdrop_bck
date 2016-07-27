CC = gcc
CC_FLAGS = -Wall -I/usr/local/include -L/usr/local/lib -ggdb -ldb-4.2 -D_GNU_SOURCE -D_REENTRANT -Wl,--rpath -Wl,/usr/local/lib -lpthread
    
all: botmaint botchk

botchk: bck.c
	$(CC) -c bck.c -o bck.o
	$(CC) $(CC_FLAGS) -o bck bck.o /usr/local/lib/libdb-4.2.so /usr/lib/x86_64-linux-gnu/libpthread.so

botmaint: botmaint.c
	$(CC) $(CC_FLAGS) botmaint.c -o botmaint

static:
	$(CC) $(CC_FLAGS) -static bck.c -o botchk.static
      
clean: 
	@rm -f botchk botchk.static botmaint
