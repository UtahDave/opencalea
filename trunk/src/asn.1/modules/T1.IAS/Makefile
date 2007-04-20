#
# Example Makefile to build test routine
#
TARGET  = IAS
CFLAGS  += -I. -I../../T1.IAS/CmII
LDFLAGS += -lias
OBJS    = main.o
OBJS    += access_attempt.o

all: $(TARGET)

$(TARGET): ${OBJS}
	$(CC) $(CFLAGS) -o $(TARGET) ${OBJS} $(LDFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(TARGET)
	rm -f $(OBJS)
