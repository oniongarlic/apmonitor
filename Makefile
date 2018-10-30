CC=gcc
CFLAGS=-O2 -ggdb -Werror

# MQTT Support
LDFLAGS+=-lmosquitto

all: apmonitor

apmonitor: apmonitor.c

clean:
	rm apmonitor
