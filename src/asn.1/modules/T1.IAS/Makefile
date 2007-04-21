#
# Example Makefile to build test routine
#
TARGET   = IAS
CFLAGS  += -I. -I../../T1.IAS/CmCC -I../../T1.IAS/CmII -I../../T1.678/VoP
LDFLAGS += -L../../T1.IAS/CmCC -L../../T1.IAS/CmII -L../../T1.678/VoP
OBJS     = main.o
OBJS    += routines.o
OBJS    += ias_cc_apdu.o
LIBS    += -lCmCC -lCmII -lVoP
CC      = gcc

all: $(TARGET)

$(TARGET): ${OBJS}
	$(CC) $(CFLAGS) -o $(TARGET) ${OBJS} $(LDFLAGS) $(LIBS)

.c.o:
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(TARGET)
	rm -f $(OBJS)
