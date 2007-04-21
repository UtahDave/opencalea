#
# Example Makefile to build test routine
#
TARGET	 = VoP
CFLAGS	+= -I. -I../../T1.678/VoP 
LDFLAGS += -L../../T1.678/VoP 
OBJS	 = main.o
OBJS	+= routines.o
OBJS	+= directsignalreporting.o
LIBS	+= -lVoP
CC	= gcc

all: $(TARGET)

$(TARGET): ${OBJS}
	$(CC) $(CFLAGS) -o $(TARGET) ${OBJS} $(LDFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(TARGET)
	rm -f $(OBJS)
