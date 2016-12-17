obj-m := urlfilter.o
urlfilter-objs := uf_url_filter.o uf_send_skb.o

PWD:=$(shell pwd)
KDIR:=/lib/modules/$(shell uname -r)/build

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions
	rm -rf Module.* modules.*

.PHONY: default clean
