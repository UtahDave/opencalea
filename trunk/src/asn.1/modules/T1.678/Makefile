#
# Example Makefile to build test routine
#
TARGET	 = VoP
CFLAGS	+= -I. -I/usr/local/include/open_calea/T1.678/VoP
LDFLAGS += -lvop
OBJS	 = main.o
OBJS	+= subjectsignal.o

all: $(TARGET)

$(TARGET): ${OBJS}
	$(CC) $(CFLAGS) -o $(TARGET) ${OBJS} $(LDFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(TARGET)
	rm -f $(OBJS)
