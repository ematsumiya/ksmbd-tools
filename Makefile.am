## Makefile.am

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = lib
AM_CFLAGS = -Iinclude $(GLIB_CFLAGS) $(LIBNL_CFLAGS) -fno-common
LIBS = $(GLIB_LIBS) $(LIBNL_LIBS) $(LIBKRB5_LIBS)
ksmbdctl_LDADD = lib/libksmbdtools.a

sbin_PROGRAMS = ksmbdctl

ksmbdctl_SOURCES = share/share_admin.c share/share.c share/share_admin.h \
		   ksmbdctl.c user/md4_hash.c user/user_admin.c user/user.c \
		   user/md4_hash.h user/user_admin.h daemon/worker.c \
		   daemon/ipc.c daemon/rpc.c  daemon/rpc_srvsvc.c \
		   daemon/rpc_wkssvc.c daemon/daemon.c daemon/smbacl.c \
		   daemon/rpc_samr.c daemon/rpc_lsarpc.c

# other stuff
EXTRA_DIST =			\
	include
