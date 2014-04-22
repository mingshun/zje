noinst_PROGRAMS = zje
INCLUDES= -I$(top_srcdir)/deps/jansson-2.4/src
LIBS = -lssl
zje_SOURCES = \
	zje_log.c \
	zje_log.h \
	zje_path.c \
	zje_path.h \
	zje_stack.c \
	zje_stack.h \
	zje_rbtree.c \
	zje_rbtree.h \
	zje_config.c \
	zje_config.h \
	zje_workdir.c \
	zje_workdir.h \
	zje_init.c \
	zje_init.h \
	zje_cpufreq.c \
	zje_cpufreq.h \
	zje_fs.c \
	zje_fs.h \
	zje_utils.c \
	zje_utils.h \
	zje_net.c \
	zje_net.h \
	zje_digest.c \
	zje_digest.h \
	zje_sj.c \
	zje_sj.h \
	zje_compile.c \
	zje_compile.h \
	zje_execute.c \
	zje_execute.h \
	zje_review.c \
	zje_review.h \
	zje_worker.c \
	zje_worker.h \
	zje_master.c \
	zje_master.h \
	zje.c
zje_LDADD = $(top_srcdir)/deps/jansson-2.4/src/.libs/libjansson.a
#AM_CFLAGS = -Wall -Werror

