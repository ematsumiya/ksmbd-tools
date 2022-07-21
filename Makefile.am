ACLOCAL_AMFLAGS = -I m4

SUBDIRS = lib
AM_CFLAGS = -DSYSCONFDIR='"${sysconfdir}"' -DRUNSTATEDIR='"${runstatedir}"' \
	    -I$(top_srcdir)/include $(GLIB_CFLAGS) $(LIBNL_CFLAGS) -fno-common
LIBS = $(GLIB_LIBS) $(LIBNL_LIBS) $(LIBKRB5_LIBS)
ksmbdctl_LDADD = lib/libksmbdtools.a

sbin_PROGRAMS = ksmbdctl

share_SOURCES = share/share_admin.c share/share.c share/share_admin.h
user_SOURCES = user/md4_hash.c user/user_admin.c user/user.c user/md4_hash.h \
	       user/user_admin.h
daemon_SOURCES = daemon/worker.c daemon/ipc.c daemon/rpc.c daemon/rpc_srvsvc.c \
		 daemon/rpc_wkssvc.c daemon/daemon.c daemon/smbacl.c \
		 daemon/rpc_samr.c daemon/rpc_lsarpc.c daemon/daemon.h

ksmbdctl_SOURCES = $(share_SOURCES) $(user_SOURCES) $(daemon_SOURCES) \
		   ksmbdctl.c

EXTRA_DIST = include \
             README.md \
             Documentation \
             ksmbd-tools.spec \
             ksmbd.service.in

pkgsysconfdir = $(sysconfdir)/ksmbd
dist_pkgsysconf_DATA = smb.conf.example

systemdsystemunit_DATA = ksmbd.service
$(systemdsystemunit_DATA): %: %.in
	@$(SED) -e 's,[@]sbindir[@],$(sbindir),g' \
	        -e 's,[@]runstatedir[@],$(runstatedir),g' \
	        $< >$@

CLEANFILES = $(systemdsystemunit_DATA)

AM_DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$${dc_install_base}/$(systemdsystemunitdir)
