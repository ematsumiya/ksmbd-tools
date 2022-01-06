AM_CFLAGS = -DSYSCONFDIR='"${sysconfdir}"' -DRUNSTATEDIR='"${runstatedir}"' \
            -I$(top_srcdir)/include $(GLIB_CFLAGS) $(LIBNL_CFLAGS) -fno-common
LIBS = $(GLIB_LIBS) $(LIBNL_LIBS) $(LIBKRB5_LIBS)
daemon_LDADD = $(top_builddir)/lib/libksmbdtools.a

daemon_SOURCES = daemon.c ipc.c rpc.c rpc_lsarpc.c rpc_samr.c rpc_srvsvc.c \
		 rpc_wkssvc.c smbacl.c worker.c 
