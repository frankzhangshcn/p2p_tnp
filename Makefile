TOPDIR := $(shell cd ../..;pwd)
include $(TOPDIR)/build/base.mk

LIBS := -Llib -lPPPP_API -lframeshare -lrt -ldl -lpthread -lm -lmp4 -lcommon -lcyassl -luartcom
OBJS := p2p_tnp.o
TARGET := p2p_tnp
CFLAGS += -Iinclude -DLINUX 
LDFLAGS += -L$(TOPDIR)/tools/uart_ptz

# added by Frank Zhang
OBJS += xlink_process.o
CFLAGS += -Iinclude_xlink
LIBS += -Llib_xlink -lXlinkV3forGE -lcurl -lcyassl

include $(BUILD_APP)
