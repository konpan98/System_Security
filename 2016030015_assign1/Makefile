OBJS	= demo.o simple_crypto.o
SOURCE 	= demo.c simple_crypto.c
HEADER 	= simple_crypto.h
OUT		= exec
CC		= gcc
FLAGS	= -g -c 

$(OUT): $(OBJS)
	$(CC) -g $(OBJS) -o $@


demo.o: demo.c
	$(CC) $(FLAGS) demo.c 


simple_crypto.o: simple_crypto.c
	$(CC) $(FLAGS) simple_crypto.c 


clean:
	rm -f $(OBJS) $(OUT)
