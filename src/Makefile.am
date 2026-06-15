AM_CPPFLAGS = -D_POSIX_C_SOURCE=200809L
AM_CFLAGS = -Wall -Wextra

bin_PROGRAMS = shc
shc_SOURCES = shc.c

check: shc
	$(srcdir)/../test/ttest.sh ./shc
