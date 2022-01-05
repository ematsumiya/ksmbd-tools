AM_CFLAGS = -DSYSCONFDIR='"${sysconfdir}"' -DRUNSTATEDIR='"${runstatedir}"' \
            -I$(top_srcdir)/include $(GLIB_CFLAGS) $(LIBNL_CFLAGS) -fno-common
LIBS = $(GLIB_LIBS)
user_LDADD = $(top_builddir)/lib/libksmbdtools.a

user_SOURCES = md4_hash.c user_admin.c user.c md4_hash.h user_admin.h
