#created by lijk<lijk@infosec.com.cn>
ifndef CC
CC := gcc
endif
CFLAGS += -g -O0 -Wall -fPIC
CFLAGS += -D__DEBUG__
CFLAGS += -I./
LDFLAGS += -L./
LIBS += -lssl -lcrypto
LIBS += -ldl

.PHONY : default all clean

SRCS += sm2_asn1.c test.c

OBJS = $(SRCS:.c=.o)

TARGET = test

default : all

all : ${TARGET}

${TARGET} : ${OBJS}
	${CC} -o $@ ${OBJS} ${LDFLAGS} ${LIBS}
	@echo "$@"

%.o : %.c %.h
	${CC} ${CFLAGS} -o $@ -c $<

clean :
	rm -rf ${OBJS} ${TARGET}
