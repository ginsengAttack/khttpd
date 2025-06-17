KDIR=/lib/modules/$(shell uname -r)/build

CFLAGS_user = -std=gnu11 -Wall -Wextra -Werror
LDFLAGS_user = -lpthread

EXTRA_CFLAGS += -pg
obj-m += khttpd.o
khttpd-objs := \
	http_server.o \
	main.o \
	data_compress.o\
	picohttpparser.o

GIT_HOOKS := .git/hooks/applied
all: $(GIT_HOOKS) htstress
	make -C $(KDIR) M=$(PWD) modules

$(GIT_HOOKS):
	@scripts/install-git-hooks
	@echo

htstress: htstress.c
	$(CC) $(CFLAGS_user) -o $@ $< $(LDFLAGS_user)

check: all
	@scripts/test.sh

clean:
	make -C $(KDIR) M=$(PWD) clean
	$(RM) htstress


