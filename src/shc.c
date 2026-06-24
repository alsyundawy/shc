#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* shc.c */

/**
 * This software contains an ad hoc version of the 'Alleged RC4' algorithm,
 * which was anonymously posted on sci.crypt news by cypherpunks on Sep 1994.
 *
 * My implementation is a complete rewrite of the one found in
 * an unknown-copyright (283 characters) version picked up from:
 *    From: allen@gateway.grumman.com (John L. Allen)
 *    Newsgroups: comp.lang.c
 *    Subject: Shrink this C code for fame and fun
 *    Date: 21 May 1996 10:49:37 -0400
 * And it is licensed also under GPL.
 *
 * That's where I got it, now I am going to do some work on it
 * It will reside here: https://github.com/alsyundawy/shc
 *
 * Audit and Hardening by HARRY DS ALSYUNDAWY - ALSYUNDAWY IT SOLUTION (2026)
 */

static const char my_name[] = "shc";
static const char version[] = "Version 5.0.8-Hardened-Audit-2026";
static const char subject[] = "Generic Shell Script Compiler";
static const char cpright[] = "GNU GPL Version 3";
static const struct {const char *f, *s, *e;}
provider = { "Md Jahidul", "Hamid", "<jahidulhamid@yahoo.com>" };
static const struct {const char *f, *s, *e;}
original_author = { "Francisco", "Garcia", "<frosal@fi.upm.es>" };

static const char *version_credits[] = {
	"Original author    : Francisco Garcia <frosal@fi.upm.es>",
	"Provider/Maintainer: Md Jahidul Hamid <jahidulhamid@yahoo.com>",
	"Core collaborator  : @mdeweerd and SHC contributors",
	"Audit & Hardening  : HARRY DS ALSYUNDAWY - ALSYUNDAWY IT SOLUTION (2026)",
	"Repository         : https://github.com/alsyundawy/shc",
	0
};

/*This is the original author who first came up with this*/

static const char *copying[] = {
	"Copying:",
	"",
	"    This program is free software; you can redistribute it and/or modify",
	"    it under the terms of the GNU General Public License as published by",
	"    the Free Software Foundation; either version 3 of the License, or",
	"    (at your option) any later version.",
	"",
	"    This program is distributed in the hope that it will be useful,",
	"    but WITHOUT ANY WARRANTY; without even the implied warranty of",
	"    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the",
	"    GNU General Public License for more details.",
	"",
	"    You should have received a copy of the GNU General Public License",
	"    along with this program; if not, write to the Free Software",
	"    @Neurobin, Dhaka, Bangladesh",
	"",
	"    Report problems and questions to: https://github.com/alsyundawy/shc/issues",
	"",
	0
};

static const char *abstract[] = {
	"Abstract:",
	"",
	"    This tool generates a stripped binary executable version",
	"    of the SCRIPT specified at command line.",
	"",
	"    The generated binary defaults to SCRIPT.x by default.",
	"    Use [-o OUTFILE] to specifou a different output file name.",
	"",
	"    An expiration date can be set with [-e DATE], the binary will",
	"    refuse execute after DATE, displaying \"[-m]\" instead.",
	"",
	"    Compile any interpreted script using [-i], [-x] and [-l] options.",
	"",
	0
};

static const char usage[] =
	"Usage: shc [--version] [-e DATE] [-m MESSAGE] [-i IOPT] [-x CMD] [-l LOPT] [-o OUTFILE] [-2ABCDhHpPrSUVv] -f SCRIPT";

static const char *help[] = {
	"",
	"    -e %s  Expiration DATE in dd/mm/yyyy format [none]",
	"    -m %s  MESSAGE to display upon expiration [\"Please contact your provider\"]",
	"    -f %s  File name of the SCRIPT to compile",
	"    -i %s  Inline option for the shell interpreter i.e: -e",
	"    -x %s  eXec command, in printf format i.e: \"exec('%s',@ARGV);\"",
	"    -l %s  Last shell option i.e: \"--\"",
	"    -o %s  output filename",
	"    -r     Relax security. Make a redistributable binary",
	"    -v     Verbose compilation",
	"    -V, --version  Display version and exit",
	"    -S     Switch ON setuid for root callable programs [OFF]",
	"    -D     Switch ON debug exec calls [OFF]",
	"    -U     Make binary untraceable [no]",
	"    -H     Hardening : extra security protection [no]",
	"           Requires bourne shell (sh), arguments not supported",
	"    -P     Submit script as a pipe, with argv forging [no]",
	"    -p     Submit script as a pipe, without argv forging [no]",
	"    -B     Compile for busybox",
	"    -2     Use the system call mmap2",
	"    -C     Display license and exit",
	"    -A     Display abstract and exit",
	"    -h     Display help and exit",
	"",
	"    Environment variables used:",
	"    Name    Default  Usage",
	"    CC      cc       C compiler command",
	"    STRIP   strip    Strip command",
	"    CFLAGS  <none>   C compiler flags",
	"    LDFLAGS <none>   Linker flags",
	"",
	"    Please consult the shc man page.",
	"",
	0
};

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SIZE 4096

static char *file;
static char *file2;
static char date[21];
static const char *mail = "Please contact your provider";
static char rlax[1];
static char *shll;
static char *inlo;
static char *pfmt;
static char *xecc;
static char *lsto;
static char *opts;
static char *text;
static int verbose;
static const char SETUID_line[] =
	"#define SETUID %d	/* Define as 1 to call setuid(0) at start of script */\n";
static int SETUID_flag = 0;
static const char DEBUGEXEC_line[] =
	"#define DEBUGEXEC	%d	/* Define as 1 to debug execvp calls */\n";
static int DEBUGEXEC_flag = 0;
static const char TRACEABLE_line[] =
	"#define TRACEABLE	%d	/* Define as 1 to enable ptrace the executable */\n";
static int TRACEABLE_flag = 1;
static const char HARDENING_line[] =
	"#define HARDENING	%d	/* Define as 1 to disable ptrace/dump the executable */\n";
static int HARDENING_flag = 0;
static const char MMAP2_line[] =
	"#define MMAP2		%d	/* Define as 1 to use syscall mmap2 */\n";
static int MMAP2_flag = 0;
static const char BUSYBOXON_line[] =
	"#define BUSYBOXON	%d	/* Define as 1 to enable work with busybox */\n";
static int BUSYBOXON_flag = 0;
static const char PIPESCRIPT_line[] =
	"#define PIPESCRIPT	%d	/* Define as 1 to submit script as a pipe */\n";
static int PIPESCRIPT_flag = 0;
static const char FIXARGV0_line[] =
	"#define FIXARGV0	%d	/* Define as 1 fix handling of ARGV0 */\n";
static int FIXARGV0_flag = 1;

static const char *RTC[] = {
	"#if defined(__GNUC__)",
	"#define _UNUSED_R(x) { int __attribute__((unused)) _tmp = (int) (x); }",
	"#else",
	"#define _UNUSED_R(x) (void) (x)",
	"#endif",
	"#if HARDENING",
	"",
	"static const char * shc_x[] = {",
	"\"/*\",",
	"\" * Copyright 2019-2026 - Intika <intika@librefox.org>\",",
	"\" * Audit and Hardening by HARRY DS ALSYUNDAWY - ALSYUNDAWY IT SOLUTION (2026)\",",
	"\" * Replace ******** with secret read from fd 21\",",
	"\" * Also change arguments location of sub commands (sh script commands)\",",
	"\" * gcc -Wall -fpic -shared -o shc_secret.so shc_secret.c -ldl\",",
	"\" */\",",
	"\"\",",
	"\"#define _GNU_SOURCE /* needed to get RTLD_NEXT defined in dlfcn.h */\",",
	"\"#define PLACEHOLDER \\\"********\\\"\",",
	"\"#include <dlfcn.h>\",",
	"\"#include <stdlib.h>\",",
	"\"#include <string.h>\",",
	"\"#include <unistd.h>\",",
	"\"#include <stdio.h>\",",
	"\"#include <signal.h>\",",
	"\"\",",
	"\"static char secret[128000]; //max size\",",
	"\"typedef int (*pfi)(int, char **, char **);\",",
	"\"static pfi real_main;\",",
	"\"\",",
	"\"// copy argv to new location\",",
	"\"char **copyargs(int argc, char** argv){\",",
	"\"	char **newargv = malloc((argc+1)*sizeof(*argv));\",",
	"\"	char *from,*to;\",",
	"\"	int i,len;\",",
	"\"\",",
	"\"	for (i = 0; i<argc; i++) {\",",
	"\"		from = argv[i];\",",
	"\"		len = strlen(from)+1;\",",
	"\"		to = malloc(len);\",",
	"\"		memcpy(to,from,len);\",",
	"\"		// zap old argv space\",",
	"\"		memset(from,'\\\\0',len);\",",
	"\"		newargv[i] = to;\",",
	"\"		argv[i] = 0;\",",
	"\"	}\",",
	"\"	newargv[argc] = 0;\",",
	"\"	return newargv;\",",
	"\"}\",",
	"\"\",",
	"\"static int mymain(int argc, char** argv, char** env) {\",",
	"\"	//fprintf(stderr, \\\"Inject main argc = %d\\\\n\\\", argc);\",",
	"\"	return real_main(argc, copyargs(argc,argv), env);\",",
	"\"}\",",
	"\"\",",
	"\"int __libc_start_main(\",",
	"\"	int (*main) (int, char**, char**),\",",
	"\"	int argc,\",",
	"\"	char **argv,\",",
	"\"	void (*init) (void),\",",
	"\" 	void (*fini)(void),\",",
	"\"	void (*rtld_fini)(void),\",",
	"\"	void (*stack_end)\",",
	"\") {\",",
	"\"	static int (*real___libc_start_main)() = NULL;\",",
	"\"	int n;\",",
	"\"\",",
	"\"	if (!real___libc_start_main) {\",",
	"\"		real___libc_start_main = dlsym(RTLD_NEXT, \\\"__libc_start_main\\\");\",",
	"\"		if (!real___libc_start_main) abort();\",",
	"\"	}\",",
	"\"\",",
	"\"	n = read(21, secret, sizeof(secret));\",",
	"\"	if (n > 0) {\",",
	"\"		int i;\",",
	"\"\",",
	"\"		if (secret[n - 1] == '\\\\n') { secret[--n] = '\\\\0'; }\",",
	"\"		for (i = 1; i < argc; i++) {\",",
	"\"			if (strcmp(argv[i], PLACEHOLDER) == 0) {\",",
	"\"				argv[i] = secret;\",",
	"\"			}\",",
	"\"		}\",",
	"\"	}\",",
	"\"\",",
	"\"	real_main = main;\",",
	"\"\",",
	"\"	return real___libc_start_main(mymain, argc, argv, init, fini, rtld_fini, stack_end);\",",
	"\"}\",",
	"\"\",",
	"0};",
	"#endif /* HARDENING */",
	"",
	"/* rtc.c */",
	"",
	"#ifndef _GNU_SOURCE",
	"#define _GNU_SOURCE",
	"#endif",
	"#ifndef _POSIX_C_SOURCE",
	"#define _POSIX_C_SOURCE 200809L",
	"#endif",
	"",
	"#include <sys/stat.h>",
	"#include <sys/types.h>",
	"#include <sys/wait.h>",
	"",
	"#include <errno.h>",
	"#include <stdio.h>",
	"#include <stdlib.h>",
	"#include <string.h>",
	"#include <time.h>",
	"#include <unistd.h>",
	"#include <fcntl.h>",
	"#include <limits.h>",
	"",
	"#ifndef PATH_MAX",
	"#define PATH_MAX 4096",
	"#endif",
	"",
	"/* 'Alleged RC4' */",
	"",
	"static unsigned char stte[256], indx, jndx, kndx;",
	"",
	"/*",
	" * Reset arc4 stte.",
	" */",
	"void stte_0(void) {",
	"	indx = jndx = kndx = 0;",
	"	do {",
	"		stte[indx] = indx;",
	"	} while (++indx);",
	"}",
	"",
	"/*",
	" * Set key. Can be used more than once.",
	" */",
	"void key(void * str, int len) {",
	"	unsigned char tmp, * ptr = (unsigned char *)str;",
	"	while (len > 0) {",
	"		do {",
	"			tmp = stte[indx];",
	"			kndx += tmp;",
	"			kndx += ptr[(int)indx % len];",
	"			stte[indx] = stte[kndx];",
	"			stte[kndx] = tmp;",
	"		} while (++indx);",
	"		ptr += 256;",
	"		len -= 256;",
	"	}",
	"}",
	"",
	"/*",
	" * Encrypt data.",
	" */",
	"void arc4(void * str, int len) {",
	"	unsigned char tmp, * ptr = (unsigned char *)str;",
	"	while (len > 0) {",
	"		indx++;",
	"		tmp = stte[indx];",
	"		jndx += tmp;",
	"		stte[indx] = stte[jndx];",
	"		stte[jndx] = tmp;",
	"		tmp += stte[indx];",
	"		*ptr ^= stte[tmp];",
	"		ptr++;",
	"		len--;",
	"	}",
	"}",
	"",
	"/* End of ARC4 */",
	"",
	"#if HARDENING",
	"",
	"#include <sys/ptrace.h>",
	"#include <sys/wait.h>",
	"#include <signal.h>",
	"#include <sys/prctl.h>",
	"#define PR_SET_PTRACER 0x59616d61",
	"",
	"/* Seccomp Sandboxing Init */",
	"#include <stdlib.h>",
	"#include <stdio.h>",
	"#include <stddef.h>",
	"#include <string.h>",
	"#include <unistd.h>",
	"#include <errno.h>",
	"",
	"#include <sys/types.h>",
	"#include <sys/prctl.h>",
	"#include <sys/syscall.h>",
	"#include <sys/socket.h>",
	"",
	"#include <linux/filter.h>",
	"#include <linux/seccomp.h>",
	"#include <linux/audit.h>",
	"",
	"#define ArchField offsetof(struct seccomp_data, arch)",
	"",
	"#define Allow(syscall) \\",
	"    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_##syscall, 0, 1), \\",
	"    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)",
	"",
	"struct sock_filter filter[] = {",
	"    /* validate arch */",
	"    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, ArchField),",
	"    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_X86_64, 1, 0),",
	"    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),",
	"",
	"    /* load syscall */",
	"    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),",
	"",
	"    /* list of allowed syscalls */",
	"    Allow(exit_group),  /* exits a process */",
	"    Allow(brk),         /* for malloc(), inside libc */",
	"#if MMAP2",
	"    Allow(mmap2),       /* also for malloc() */",
	"#else",
	"    Allow(mmap),        /* also for malloc() */",
	"#endif",
	"    Allow(munmap),      /* for free(), inside libc */",
	"",
	"    /* and if we don't match above, die */",
	"    BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL),",
	"};",
	"struct sock_fprog filterprog = {",
	"    .len = sizeof(filter)/sizeof(filter[0]),",
	"    .filter = filter",
	"};",
	"",
	"/* Seccomp Sandboxing - Set up the restricted environment */",
	"void seccomp_hardening() {",
	"    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {",
	"        perror(\"Could not start seccomp:\");",
	"        exit(1);",
	"    }",
	"    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &filterprog) == -1) {",
	"        perror(\"Could not start seccomp:\");",
	"        exit(1);",
	"    }",
	"}",
	"/* End Seccomp Sandboxing Init */",
	"",
	"void arc4_hardrun(void * str, int len) {",
	"	char *tmp2;",
	"	unsigned char tmp, * ptr;",
	"",
	"	if (len <= 0) { exit(1); }",
	"	tmp2 = malloc((size_t)len + 1U);",
	"	if (!tmp2) { exit(1); }",
	"	memcpy(tmp2, str, (size_t)len);",
	"	tmp2[len] = '\\0';",
	"	ptr = (unsigned char *)tmp2;",
	"",
	"	while (len > 0) {",
	"		indx++;",
	"		tmp = stte[indx];",
	"		jndx += tmp;",
	"		stte[indx] = stte[jndx];",
	"		stte[jndx] = tmp;",
	"		tmp += stte[indx];",
	"		*ptr ^= stte[tmp];",
	"		ptr++;",
	"		len--;",
	"	}",
	"",
	"	_UNUSED_R(system(tmp2));",
	"	memset(tmp2, 0, strlen(tmp2));",
	"	free(tmp2);",
	"	exit(0);",
	"}",
	"#endif /* HARDENING */",
	"",
	"/*",
	" * Key with file invariants.",
	" */",
	"int key_with_file(char * file) {",
	"	struct stat statf[1];",
	"	struct stat control[1];",
	"",
	"	if (stat(file, statf) < 0)",
	"		return -1;",
	"",
	"	/* Turn on stable fields */",
	"	memset(control, 0, sizeof(control));",
	"	control->st_ino = statf->st_ino;",
	"	control->st_dev = statf->st_dev;",
	"	control->st_rdev = statf->st_rdev;",
	"	control->st_uid = statf->st_uid;",
	"	control->st_gid = statf->st_gid;",
	"	control->st_size = statf->st_size;",
	"	control->st_mtime = statf->st_mtime;",
	"	control->st_ctime = statf->st_ctime;",
	"	key(control, sizeof(control));",
	"	return 0;",
	"}",
	"",
	"#if DEBUGEXEC",
	"void debugexec(char * sh11, int argc, char ** argv) {",
	"	int i;",
	"	fprintf(stderr, \"shll=%s\\n\", sh11 ? sh11 : \"<null>\");",
	"	fprintf(stderr, \"argc=%d\\n\", argc);",
	"	if (!argv) {",
	"		fprintf(stderr, \"argv=<null>\\n\");",
	"	} else {",
	"		for (i = 0; i <= argc ; i++) {",
	"			fprintf(stderr, \"argv[%d]=%s\\n\", i, argv[i] ? argv[i] : \"<null>\");",
	"		}",
	"	}",
	"}",
	"#endif /* DEBUGEXEC */",
	"",
	"void rmarg(char ** argv, char * arg) {",
	"	for (; argv && *argv && *argv != arg; argv++) {}",
	"	for (; argv && *argv; argv++)",
	"		*argv = argv[1];",
	"}",
	"",
	"void chkenv_end(void);",
	"",
	"int chkenv(int argc) {",
	"	char buff[512];",
	"	unsigned long mask, m;",
	"	int l, a, c;",
	"	char * string;",
	"	extern char ** environ;",
	"",
	"	mask = (unsigned long)getpid();",
	"	stte_0();",
	"	 key(&chkenv, (void*)&chkenv_end - (void*)&chkenv);",
	"	 key(&data, sizeof(data));",
	"	 key(&mask, sizeof(mask));",
	"	arc4(&mask, sizeof(mask));",
	"	snprintf(buff, sizeof(buff), \"x%lx\", mask);",
	"	string = getenv(buff);",
	"#if DEBUGEXEC",
	"	fprintf(stderr, \"getenv(%s)=%s\\n\", buff, string ? string : \"<null>\");",
	"#endif",
	"	l = strlen(buff);",
	"	if (!string) {",
	"		/* 1st */",
	"		snprintf(&buff[l], sizeof(buff)-l, \"=%lu %d\", mask, argc);",
	"		putenv(strdup(buff));",
	"		return 0;",
	"	}",
	"	c = sscanf(string, \"%lu %d%c\", &m, &a, buff);",
	"	if (c == 2 && m == mask) {",
	"		/* 3rd */",
	"		rmarg(environ, &string[-l - 1]);",
	"		return 1 + (argc - a);",
	"	}",
	"	return -1;",
	"}",
	"",
	"void chkenv_end(void) {}",
	"",
	"#if HARDENING",
	"",
	"static void gets_process_name(const pid_t pid, char * name, size_t name_len) {",
	"	char procfile[BUFSIZ];",
	"	if (!name || name_len == 0) { return; }",
	"	name[0] = '\\0';",
	"	snprintf(procfile, sizeof(procfile), \"/proc/%d/cmdline\", pid);",
	"	FILE* f = fopen(procfile, \"r\");",
	"	if (f) {",
	"		size_t size;",
	"		size = fread(name, sizeof(char), name_len - 1, f);",
	"		name[size] = '\\0';",
	"		if (size > 0 && ('\\n' == name[size - 1] || '\\0' == name[size - 1])) {",
	"			name[size - 1] = '\\0';",
	"		}",
	"		fclose(f);",
	"	}",
	"}",
	"",
	"void hardening() {",
	"	prctl(PR_SET_DUMPABLE, 0);",
	"	prctl(PR_SET_PTRACER, -1);",
	"",
	"	int pid = getppid();",
	"	char name[256] = {0};",
	"	gets_process_name(pid, name, sizeof(name));",
	"",
	"	if (   (strcmp(name, \"bash\") != 0)",
	"	    && (strcmp(name, \"/bin/bash\") != 0)",
	"	    && (strcmp(name, \"sh\") != 0)",
	"	    && (strcmp(name, \"/bin/sh\") != 0)",
	"	    && (strcmp(name, \"sudo\") != 0)",
	"	    && (strcmp(name, \"/bin/sudo\") != 0)",
	"	    && (strcmp(name, \"/usr/bin/sudo\") != 0)",
	"	    && (strcmp(name, \"gksudo\") != 0)",
	"	    && (strcmp(name, \"/bin/gksudo\") != 0)",
	"	    && (strcmp(name, \"/usr/bin/gksudo\") != 0)",
	"	    && (strcmp(name, \"kdesu\") != 0)",
	"	    && (strcmp(name, \"/bin/kdesu\") != 0)",
	"	    && (strcmp(name, \"/usr/bin/kdesu\") != 0)",
	"	) {",
	"		printf(\"Operation not permitted\\n\");",
	"		kill(getpid(), SIGKILL);",
	"		exit(1);",
	"	}",
	"}",
	"",
	"#endif /* HARDENING */",
	"",
	"#if !TRACEABLE",
	"",
	"#define _LINUX_SOURCE_COMPAT",
	"#include <sys/ptrace.h>",
	"#include <sys/types.h>",
	"#include <sys/wait.h>",
	"#include <fcntl.h>",
	"#include <signal.h>",
	"#include <stdio.h>",
	"#include <unistd.h>",
	"",
	"#if !defined(PT_ATTACHEXC) /* New replacement for PT_ATTACH */",
	"	#if !defined(PTRACE_ATTACH) && defined(PT_ATTACH)",
	"		#define PT_ATTACHEXC	PT_ATTACH",
	"	#elif defined(PTRACE_ATTACH)",
	"		#define PT_ATTACHEXC PTRACE_ATTACH",
	"	#endif",
	"#endif",
	"",
	"void untraceable(char * argv0) {",
	"	char proc[80];",
	"	int pid, mine;",
	"",
	"	switch(pid = fork()) {",
	"	case  0:",
	"		pid = getppid();",
	"		/* For problematic SunOS ptrace */",
	"#if defined(__FreeBSD__)",
	"		snprintf(proc, sizeof(proc), \"/proc/%d/mem\", (int)pid);",
	"#else",
	"		snprintf(proc, sizeof(proc), \"/proc/%d/as\",  (int)pid);",
	"#endif",
	"		close(0);",
	"		mine = !open(proc, O_RDWR|O_EXCL);",
	"		if (!mine && errno != EBUSY) {",
	"			if ((mine=2*!ptrace(PT_ATTACHEXC, pid, 0, 0))) { wait(0); }",
	"		}",
	"		if (!mine) {",
	"			perror(argv0);",
	"			kill(pid, SIGKILL);",
	/*"			fprintf(stderr, \"%s is being traced!\\n\", argv0);",*/
	"		} else if (mine>1) {",
	"			ptrace(PTRACE_DETACH, pid, 0, 0);",
	"		}",
	"		_exit(mine);",
	"	case -1:",
	"		break;",
	"	default:",
	"		if (pid == waitpid(pid, 0, 0)) {",
	"			return;",
	"		}",
	"	}",
	"	perror(argv0);",
	"	_exit(1);",
	"}",
	"#endif /* !TRACEABLE */",
	"",
	"char * xsh(int argc, char ** argv) {",
	"	char * scrpt;",
	"	int ret, i, j;",
	"	char ** varg;",
	"	char * me = argv[0];",
	"	if (me == NULL) { me = getenv(\"_\"); }",
	"	if (me == 0) { fprintf(stderr, \"E: neither argv[0] nor $_ works.\"); exit(1); }",
	"",
	"	ret = chkenv(argc);",
	"	stte_0();",
	"	 key(pswd, pswd_z);",
	"	arc4(msg1, msg1_z);",
	"	arc4(date, date_z);",
	"	if (date[0] && (atoll(date) < time(NULL))) {",
	"		return msg1;",
	"	}",
	"	arc4(shll, shll_z);",
	"	arc4(inlo, inlo_z);",
	"	arc4(pfmt, pfmt_z);",
	"	arc4(xecc, xecc_z);",
	"	arc4(lsto, lsto_z);",
	"	arc4(opts, opts_z);",
	"	arc4(tst1, tst1_z);",
	"	 key(tst1, tst1_z);",
	"	arc4(chk1, chk1_z);",
	"	if ((chk1_z != tst1_z) || memcmp(tst1, chk1, tst1_z)) {",
	"		return tst1;",
	"	}",
	"	arc4(msg2, msg2_z);",
	"	if (ret < 0) {",
	"		return msg2;",
	"	}",
	"	varg = (char **)calloc(argc + 10, sizeof(char *));",
	"	if (!varg) {",
	"		return 0;",
	"	}",
	"	if (ret) {",
	"		arc4(rlax, rlax_z);",
	"		if (!rlax[0] && key_with_file(shll)) {",
	"			free(varg);",
	"			return shll;",
	"		}",
	"#if HARDENING",
	"	    arc4_hardrun(text, text_z);",
	"	    exit(0);",
	"       /* Seccomp Sandboxing - Start */",
	"       seccomp_hardening();",
	"#endif",
	"		arc4(text, text_z);",
	"		arc4(tst2, tst2_z);",
	"		 key(tst2, tst2_z);",
	"		arc4(chk2, chk2_z);",
	"		if ((chk2_z != tst2_z) || memcmp(tst2, chk2, tst2_z)) {",
	"			free(varg);",
	"			return tst2;",
	"		}",
	"		/* Prepend hide_z spaces to script text to hide it. */",
	"		scrpt = malloc(hide_z + text_z);",
	"		if (!scrpt) {",
	"			free(varg);",
	"			return 0;",
	"		}",
	"		memset(scrpt, (int) ' ', hide_z);",
	"		memcpy(&scrpt[hide_z], text, text_z);",
	"	} else {			/* Reexecute */",
	"		if (*xecc) {",
	"			scrpt = malloc(512);",
	"			if (!scrpt) {",
	"				free(varg);",
	"				return 0;",
	"			}",
	"			snprintf(scrpt, 512, xecc, me);",
	"		} else {",
	"			scrpt = me;",
	"		}",
	"	}",
	"	j = 0;",
	"#if BUSYBOXON",
	"	varg[j++] = \"busybox\";",
	"	varg[j++] = \"sh\";",
	"#else",
	"	varg[j++] = argv[0];		/* My own name at execution */",
	"#endif",
	"	setenv(\"SHC_ARGV0\", argv[0], 1);",
	"	char pids[16]; snprintf(pids, sizeof(pids), \"%d\", getpid());",
	"	setenv(\"SHC_PID\", pids, 1);",
	"	char 	tnm[PATH_MAX];",
	"	char 	tdir[PATH_MAX];",
	"	char	i0 = 0;",
	"	if (PIPESCRIPT && ret) {",
	"		const char *tmpbase = getenv(\"TMPDIR\");",
	"		int n;",
	"		if (!tmpbase || !*tmpbase) { tmpbase = \"/tmp\"; }",
	"		n = snprintf(tdir, sizeof(tdir), \"%s/shc.%d.XXXXXX\", tmpbase, (int)getpid());",
	"		if (n < 0 || (size_t)n >= sizeof(tdir) || !mkdtemp(tdir)) { exit(1); }",
	"		n = snprintf(tnm, sizeof(tnm), \"%s/script\", tdir);",
	"		if (n < 0 || (size_t)n >= sizeof(tnm) || mkfifo(tnm, S_IWUSR|S_IRUSR) != 0) {",
	"			rmdir(tdir);",
	"			exit(1);",
	"		}",
	"		if ((i=fork())) {",
	"			if (i < 0) { unlink(tnm); rmdir(tdir); exit(1); }",
	"			waitpid(i, 0, 0);",
	"		} else if (fork()) {",
	"			_exit(0);",
	"		} else {",
	"			int	w,",
	"				fd;",
	"			close(0);",
	"			close(1);",
	"			close(2);",
	"			fd = open(tnm, O_WRONLY);",
	"			if (fd < 0) { _exit(1); }",
	"			unlink(tnm);",
	"			for (i=0, n=strlen(text); i < n; i+=w) {",
	"				if ((w=n-i) > BUFSIZ) { w=BUFSIZ; }",
	"				if ((w=write(fd, text+i, w)) < 0) { break; }",
	"				memset(text+i, 0, w);",
	"			}",
	"			close(fd);",
	"			rmdir(tdir);",
	"			_exit(0);",
	"		}",
	"		if (!FIXARGV0) {",
	"			varg[j++] = tnm;",
	"			i0 = 1;",
	"			goto xec;",
	"		}",
	"	}",
	"	if (*opts) {",
	"		varg[j++] = opts;	/* Options on 1st line of code */",
	"	}",
	"	if (*inlo) {",
	"		varg[j++] = inlo;	/* Option introducing inline code */",
	"	}",
	"	char *cmd = NULL;",
	"	if (PIPESCRIPT && ret) {",
	"		int n = snprintf(NULL, 0, pfmt, argv[0], tnm);",
	"		if (n < 0) { free(varg); return 0; }",
	"		cmd = malloc((size_t)n + 1U);",
	"		if (!cmd) { free(varg); return 0; }",
	"		snprintf(cmd, (size_t)n + 1U, pfmt, argv[0], tnm);",
	"		varg[j++] = cmd;",
	"	} else {",
	"		varg[j++] = scrpt;		/* The script itself */",
	"	}",
	"	if (*lsto) {",
	"		varg[j++] = lsto;	/* Option meaning last option */",
	"	}",
	"xec:",
	"	i = (ret > 1) ? ret : i0;	/* Args numbering correction */",
	"	while (i < argc) {",
	"		varg[j++] = argv[i++];	/* Main run-time arguments */",
	"	}",
	"	varg[j] = 0;			/* NULL terminated array */",
	"#if DEBUGEXEC",
	"	debugexec(shll, j, varg);",
	"#endif",
	"	execvp(shll, varg);",
	"	return shll;",
	"}",
	"",
	"int main(int argc, char ** argv) {",
	"#if SETUID",
	"	_UNUSED_R(setuid(0));",
	"#endif",
	"#if DEBUGEXEC",
	"	debugexec(\"main\", argc, argv);",
	"#endif",
	"#if HARDENING",
	"	hardening();",
	"#endif",
	"#if !TRACEABLE",
	"	untraceable(argv[0]);",
	"#endif",
	"	argv[1] = xsh(argc, argv);",
	"	fprintf(stderr, \"%s%s%s: %s\\n\", argv[0],",
	"		errno ? \": \" : \"\",",
	"		errno ? strerror(errno) : \"\",",
	"		argv[1] ? argv[1] : \"<null>\"",
	"	);",
	"	return 1;",
	"}",
	0
};


static char *xstrdup(const char *src)
{
	char *dst;
	size_t len;

	if (!src) {
		return NULL;
	}
	len = strlen(src) + 1;
	dst = malloc(len);
	if (!dst) {
		return NULL;
	}
	memcpy(dst, src, len);
	return dst;
}

static int append_suffix(char **dst, const char *suffix)
{
	char *tmp;
	size_t base_len;
	size_t suffix_len;

	if (!dst || !*dst || !suffix) {
		return -1;
	}
	base_len = strlen(*dst);
	suffix_len = strlen(suffix);
	if (suffix_len > ((size_t)-1) - base_len - 1) {
		return -1;
	}
	tmp = realloc(*dst, base_len + suffix_len + 1);
	if (!tmp) {
		return -1;
	}
	memcpy(tmp + base_len, suffix, suffix_len + 1);
	*dst = tmp;
	return 0;
}

struct argv_builder {
	char **argv;
	size_t argc;
	size_t cap;
};

static void argv_builder_free(struct argv_builder *b)
{
	size_t i;

	if (!b || !b->argv) {
		return;
	}
	for (i = 0; i < b->argc; i++) {
		free(b->argv[i]);
	}
	free(b->argv);
	b->argv = NULL;
	b->argc = 0;
	b->cap = 0;
}

static int argv_builder_reserve(struct argv_builder *b, size_t need)
{
	char **tmp;
	size_t new_cap;

	if (need <= b->cap) {
		return 0;
	}
	new_cap = b->cap ? b->cap : 8;
	while (new_cap < need) {
		if (new_cap > ((size_t)-1) / 2) {
			return -1;
		}
		new_cap *= 2;
	}
	tmp = realloc(b->argv, new_cap * sizeof(*tmp));
	if (!tmp) {
		return -1;
	}
	b->argv = tmp;
	b->cap = new_cap;
	return 0;
}

static int argv_builder_push_copy(struct argv_builder *b, const char *arg)
{
	char *copy;

	if (!b || !arg) {
		return -1;
	}
	if (argv_builder_reserve(b, b->argc + 2) != 0) {
		return -1;
	}
	copy = xstrdup(arg);
	if (!copy) {
		return -1;
	}
	b->argv[b->argc++] = copy;
	b->argv[b->argc] = NULL;
	return 0;
}

static int argv_builder_push_owned(struct argv_builder *b, char *arg)
{
	if (!b || !arg) {
		return -1;
	}
	if (argv_builder_reserve(b, b->argc + 2) != 0) {
		return -1;
	}
	b->argv[b->argc++] = arg;
	b->argv[b->argc] = NULL;
	return 0;
}

static int split_words_append(struct argv_builder *b, const char *input)
{
	const char *p;
	char *word = NULL;
	size_t len = 0;
	size_t cap = 0;
	int quote = 0;
	int in_word = 0;

	if (!input || !*input) {
		return 0;
	}
	p = input;
	while (*p) {
		unsigned char c = (unsigned char)*p++;
		if (!quote && isspace(c)) {
			if (in_word) {
				if (argv_builder_push_owned(b, word) != 0) {
					free(word);
					return -1;
				}
				word = NULL;
				len = 0;
				cap = 0;
				in_word = 0;
			}
			continue;
		}
		if ((c == '\'' || c == '"') && (!quote || quote == c)) {
			quote = quote ? 0 : (int)c;
			in_word = 1;
			continue;
		}
		if (c == '\\' && *p && quote != '\'') {
			c = (unsigned char)*p++;
		}
		if (len + 2 > cap) {
			char *tmp;
			size_t new_cap = cap ? cap * 2 : 32;
			while (new_cap < len + 2) {
				if (new_cap > ((size_t)-1) / 2) {
					free(word);
					return -1;
				}
				new_cap *= 2;
			}
			tmp = realloc(word, new_cap);
			if (!tmp) {
				free(word);
				return -1;
			}
			word = tmp;
			cap = new_cap;
		}
		word[len++] = (char)c;
		word[len] = '\0';
		in_word = 1;
	}
	if (quote) {
		free(word);
		return -1;
	}
	if (in_word) {
		if (!word) {
			word = xstrdup("");
			if (!word) {
				return -1;
			}
		}
		if (argv_builder_push_owned(b, word) != 0) {
			free(word);
			return -1;
		}
	}
	return 0;
}

static void print_argv(FILE *out, const char *prefix, char *const argv[])
{
	size_t i;

	if (!out || !argv || !argv[0]) {
		return;
	}
	fprintf(out, "%s", prefix ? prefix : "");
	for (i = 0; argv[i]; i++) {
		fprintf(out, "%s%s", i ? " " : "", argv[i]);
	}
	fputc('\n', out);
}

static int run_argv(char *const argv[])
{
	pid_t pid;
	int status;

	if (!argv || !argv[0]) {
		errno = EINVAL;
		return -1;
	}
	pid = fork();
	if (pid < 0) {
		return -1;
	}
	if (pid == 0) {
		execvp(argv[0], argv);
		perror(argv[0]);
		_exit(127);
	}
	for (;;) {
		if (waitpid(pid, &status, 0) >= 0) {
			break;
		}
		if (errno != EINTR) {
			return -1;
		}
	}
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		return 0;
	}
	if (WIFEXITED(status)) {
		errno = 0;
		return WEXITSTATUS(status) ? WEXITSTATUS(status) : -1;
	}
	errno = 0;
	return -1;
}

static int build_default_output_name(void)
{
	char *tmp;
	size_t len;

	if (!file) {
		return -1;
	}
	len = strlen(file);
	if (len > ((size_t)-1) - 3) {
		return -1;
	}
	tmp = malloc(len + 3);
	if (!tmp) {
		return -1;
	}
	memcpy(tmp, file, len);
	memcpy(tmp + len, ".x", 3);
	file2 = tmp;
	return 0;
}

static void print_version(FILE *out)
{
	int i;

	if (!out) {
		out = stdout;
	}
	fprintf(out, "%s %s, %s\n", my_name, version, subject);
	fprintf(out, "%s License          : %s\n", my_name, cpright);
	for (i = 0; version_credits[i]; i++) {
		fprintf(out, "%s %s\n", my_name, version_credits[i]);
	}
}

static int parse_an_arg(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	const char *opts = "e:m:i:x:l:o:f:2ABCDhHpPrSUVv";
	struct tm tmp[1];
	time_t expdate;
	int cnt, l;
	char ctrl;

	if (optind < argc && strcmp(argv[optind], "--version") == 0) {
		print_version(stdout);
		exit(0);
	}

	switch (getopt(argc, argv, opts)) {
	case 'e':
		memset(tmp, 0, sizeof(tmp));
		cnt = sscanf(optarg, "%2d/%2d/%4d%c",
			&tmp->tm_mday, &tmp->tm_mon, &tmp->tm_year, &ctrl);
		if (cnt == 3) {
			tmp->tm_mon--;
			tmp->tm_year -= 1900;
			expdate = mktime(tmp);
		}
		if ((cnt != 3) || (expdate <= 0)) {
			fprintf(stderr, "%s parse(-e %s): Not a valid date\n",
				my_name, optarg);
			return -1;
		}
		snprintf(date, sizeof(date), "%lld", (long long)expdate);  // NOLINT
		if (verbose) { fprintf(stderr, "%s -e %s", my_name, ctime(&expdate)); }
		expdate = atoll(date);
		if (verbose) { fprintf(stderr, "%s -e %s", my_name, ctime(&expdate)); }
		break;
	case 'm':
		mail = optarg;
		break;
	case 'f':
		if (file) {
			fprintf(stderr, "%s parse(-f '%s'): Can convert exactly one SCRIPT, but -f specified more than once\n",
				my_name, optarg);
			return -1;
		}
		file = optarg;
		break;
	case 'i':
		inlo = xstrdup(optarg);  // Gets encrypted
		if (!inlo) { return -1; }
		break;
	case 'x':
		xecc = xstrdup(optarg);  // Gets encrypted
		if (!xecc) { return -1; }
		break;
	case 'l':
		lsto = xstrdup(optarg);  // Gets encrypted
		if (!lsto) { return -1; }
		break;
	case 'o':
		file2 = optarg;
		break;
	case 'r':
		rlax[0]++;
		break;
	case 'v':
		verbose++;
		break;
	case 'V':
		print_version(stdout);
		exit(0);
		break;
	case 'S':
		SETUID_flag = 1;
		break;
	case 'D':
		DEBUGEXEC_flag = 1;
		break;
	case 'U':
		TRACEABLE_flag = 0;
		break;
	case 'P':
		PIPESCRIPT_flag = 1;
		FIXARGV0_flag = 1;
		break;
	case 'p':
		PIPESCRIPT_flag = 1;
		FIXARGV0_flag = 0;
		break;
	case 'H':
		HARDENING_flag = 1;
		break;
	case 'C':
		fprintf(stderr, "%s %s, %s\n", my_name, version, subject);
		fprintf(stderr, "%s %s %s %s %s\n", my_name, cpright, provider.f, provider.s, provider.e);
		fprintf(stderr, "%s ", my_name);
		for (l = 0; copying[l]; l++) {
			fprintf(stderr, "%s\n", copying[l]);
		}
		fprintf(stderr, "    %s %s %s\n\n", provider.f, provider.s, provider.e);
		exit(0);
		break;
	case 'A':
		fprintf(stderr, "%s %s, %s\n", my_name, version, subject);
		fprintf(stderr, "%s %s %s %s %s\n", my_name, cpright, provider.f, provider.s, provider.e);
		fprintf(stderr, "%s ", my_name);
		for (l = 0; abstract[l]; l++) {
			fprintf(stderr, "%s\n", abstract[l]);
		}
		exit(0);
		break;
	case 'h':
		fprintf(stderr, "%s %s, %s\n", my_name, version, subject);
		fprintf(stderr, "%s %s %s %s %s\n", my_name, cpright, provider.f, provider.s, provider.e);
		fprintf(stderr, "%s %s\n", my_name, usage);
		for (l = 0; help[l]; l++) {
			fprintf(stderr, "%s\n", help[l]);
		}
		exit(0);
		break;
	case -1:
		if (!file) {
			fprintf(stderr, "%s parse: Must specify SCRIPT name argument -f\n", my_name);
			file = "";
			return -1;
		}
		return 0;
	case 'B':
		BUSYBOXON_flag = 1;
		break;
	case '2':
		MMAP2_flag = 1;
		break;
	case ':':
		fprintf(stderr, "%s parse: Missing parameter\n", my_name);
		return -1;
	case '?':
		fprintf(stderr, "%s parse: Unknown option\n", my_name);
		return -1;
	default:
		fprintf(stderr, "%s parse: Unknown return\n", my_name);
		return -1;
	}
	return 1;
}

static void parse_args(int argc, char *argv[])
{
	int err = 0;
	int ret;

#if 0
	my_name = strrchr(argv[0], '/');
	if (my_name) {
		my_name++;
	} else {
		my_name = argv[0];
	}
#endif

	do {
		ret = parse_an_arg(argc, argv);
		if (ret == -1) {
			err++;
		}
	} while (ret);

	if (err) {
		fprintf(stderr, "\n%s %s\n\n", my_name, usage);
		exit(1);
	}
}

/* 'Alleged RC4' */

static unsigned char stte[256], indx, jndx, kndx;

/*
 * Reset arc4 stte.
 */
void stte_0(void)
{
	indx = jndx = kndx = 0;
	do {
		stte[indx] = indx;
	} while (++indx);
}

/*
 * Set key. Can be used more than once.
 */
void key(void *str, int len)
{
	unsigned char tmp, *ptr = (unsigned char *)str;
	while (len > 0) {
		do {
			tmp = stte[indx];
			kndx += tmp;
			kndx += ptr[(int)indx % len];
			stte[indx] = stte[kndx];
			stte[kndx] = tmp;
		} while (++indx);
		ptr += 256;
		len -= 256;
	}
}

/*
 * Encrypt data.
 */
void arc4(void *str, int len)
{
	unsigned char *ptr = (unsigned char *)str;
	while (len > 0) {
		unsigned char tmp;
		indx++;
		tmp = stte[indx];
		jndx += tmp;
		stte[indx] = stte[jndx];
		stte[jndx] = tmp;
		tmp += stte[indx];
		*ptr ^= stte[tmp];
		ptr++;
		len--;
	}
}

/* End of ARC4 */

/*
 * Key with file invariants.
 */
int key_with_file(char *file)
{
	struct stat statf[1];
	struct stat control[1];

	if (stat(file, statf) < 0) {
		return -1;
	}

	/* Turn on stable fields */
	memset(control, 0, sizeof(control));
	control->st_ino = statf->st_ino;
	control->st_dev = statf->st_dev;
	control->st_rdev = statf->st_rdev;
	control->st_uid = statf->st_uid;
	control->st_gid = statf->st_gid;
	control->st_size = statf->st_size;
	control->st_mtime = statf->st_mtime;
	control->st_ctime = statf->st_ctime;
	key(control, sizeof(control));
	return 0;
}

/*
 * NVI stands for Shells that complaint "Not Valid Identifier" on
 * environment variables with characters as "=|#:*?$ ".
 */
static const struct shell_entry {
	const char *shll;
	const char *inlo;
	const char *lsto;
	const char *xecc;
	const char *pfmt;
} shellsDB[] = {
	{ "perl", "-e", "--", "exec('%s',@ARGV);", "$0='%s';open(F,'%s');@SHCS=<F>;close(F);eval(join('',@SHCS));" },
	{ "rc", "-c", "", "builtin exec %s $*", ". %.0s'%s' $*" },
	{ "sh", "-c", "", "exec '%s' \"$@\"", ". %.0s'%s'" },  /* IRIX_nvi */
	{ "dash", "-c", "", "exec '%s' \"$@\"", ". %.0s'%s'" },
	{ "bash", "-c", "", "exec '%s' \"$@\"", ". %.0s'%s'" },
	{ "zsh", "-c", "", "exec '%s' \"$@\"", "setopt posix_argzero ; . %.0s'%s'" },
	{ "bsh", "-c", "", "exec '%s' \"$@\"", ". %.0s'%s'" },          /* AIX_nvi */
	{ "Rsh", "-c", "", "exec '%s' \"$@\"", ". %.0s'%s'" },          /* AIX_nvi */
	{ "ksh", "-c", "", "exec '%s' \"$@\"", ". %.0s'%s'" },          /* OK on Solaris, AIX and Linux (THX <bryan.hogan@dstintl.com>) */
	{ "tsh", "-c", "--", "exec '%s' \"$@\"", ". %.0s'%s'" },        /* AIX */
	{ "ash", "-c", "--", "exec '%s' \"$@\"", ". %.0s'%s'" },        /* Linux */
	{ "csh", "-c", "-b", "exec '%s' $argv:q", "source %.0s'%s'" },  /* AIX: No file for $0 */
	{ "tcsh", "-c", "-b", "exec '%s' $argv:q", "source %.0s'%s'" },
	{ "ksh88", "-c", "", "exec '%s' \"$@\"", ". %.0s'%s'" },
	{ "ksh93", "-c", "", "exec '%s' \"$@\"", ". %.0s'%s'" },
	{ "mksh", "-c", "", "exec '%s' \"$@\"", ". %.0s'%s'" },
	{ "pdksh", "-c", "", "exec '%s' \"$@\"", ". %.0s'%s'" },
	{ "fish", "-c", "", "exec '%s' $argv", "source %.0s'%s'" },
	{ "nu", "-c", "", "", "source %.0s'%s'" },
	{ "pwsh", "-c", "", "", ". %.0s'%s'" },
	{ "powershell", "-c", "", "", ". %.0s'%s'" },
	{ "yash", "-c", "", "exec '%s' \"$@\"", ". %.0s'%s'" },
	{ "osh", "-c", "", "exec '%s' \"$@\"", ". %.0s'%s'" },
	{ "elvish", "-c", "", "", "" },
	{ "python", "-c", "", "import os,sys;os.execv('%s',sys.argv[1:])",
	  "import sys;sys.argv[0:1]=[];__file__='%s'; exec(open('%s').read())" },
	{ "python2", "-c", "", "import os,sys;os.execv('%s',sys.argv[1:])",
	  "import sys;sys.argv[0:1]=[];__file__='%s';exec(open('%s').read())" },
	{ "python3", "-c", "", "import os,sys;os.execv('%s',sys.argv[1:])",
	  "import sys;sys.argv[0:1]=[];__file__='%s';exec(open('%s').read())" },
	{ "env", "-c", "", "exec '%s' \"$@\"", ". %.0s'%s'" }, /* Fallback for env */
	{ NULL, NULL, NULL, NULL, NULL },
};

int eval_shell(char *text)
{
	int i;
	char *ptr;
	char *tmp_realloc;

	ptr = strchr(text, (int)'\n');
	if (!ptr) {
		i = strlen(text);
	} else {
		i = ptr - text;
	}
	ptr = malloc(i + 1);
	shll = malloc(i + 1);
	opts = malloc(i + 1);
	if (!ptr || !shll || !opts) {
		if (ptr) free(ptr);
		if (shll) free(shll);
		if (opts) free(opts);
		return -1;
	}
	strncpy(ptr, text, i);
	ptr[i] = '\0';

	*opts = '\0';
	// cppcheck-suppress invalidscanf   // (required memory checked above)
	i = sscanf(ptr, " #!%s %[^\n]", shll, opts);
	if ((i < 1) || (i > 2)) {
		fprintf(stderr, "%s: invalid first line in script: %s\n", my_name, ptr);
		free(ptr);
		return -1;
	}
	free(ptr);

	tmp_realloc = realloc(shll, strlen(shll) + 1);
	if (!tmp_realloc) {
		fprintf(stderr, "%s: Realloc issue\n", my_name);
		free(shll);
		return -1;
	}
	shll = tmp_realloc;
	ptr = strrchr(shll, (int)'/');
	if (!ptr) {
		fprintf(stderr, "%s: invalid shll\n", my_name);
		return -1;
	}
	if (*ptr == '/') {
		ptr++;
	}
	if (verbose) { fprintf(stderr, "%s: shll=%s\n", my_name, ptr); }

	for (i = 0; shellsDB[i].shll; i++) {
		if (!strcmp(ptr, shellsDB[i].shll)) {
			if (!inlo) {
				inlo = xstrdup(shellsDB[i].inlo);
			}
			if (!pfmt) {
				pfmt = xstrdup(shellsDB[i].pfmt);
			}
			if (!xecc) {
				xecc = xstrdup(shellsDB[i].xecc);
			}
			if (!lsto) {
				lsto = xstrdup(shellsDB[i].lsto);
			}
			if (!inlo || !pfmt || !xecc || !lsto) {
				return -1;
			}
		}
	}
	if (!inlo || !pfmt || !xecc || !lsto) {
		fprintf(stderr, "%s Unknown shell (%s): specify [-i][-x][-l]\n", my_name, ptr);
		return -1;
	}
	if (verbose) { fprintf(stderr, "%s [-i]=%s\n", my_name, inlo); }
	if (verbose) { fprintf(stderr, "%s [-x]=%s\n", my_name, xecc); }
	if (verbose) { fprintf(stderr, "%s [-l]=%s\n", my_name, lsto); }

	tmp_realloc = realloc(opts, strlen(opts) + 1);
	if (!tmp_realloc) {
		free(opts);
		return -1;
	}
	opts = tmp_realloc;
	if (*opts && !strcmp(opts, lsto)) {
		fprintf(stderr, "%s opts=%s : Is equal to [-l]. Removing opts\n", my_name, opts);
		*opts = '\0';
	} else if (!strcmp(opts, "-")) {
		fprintf(stderr, "%s opts=%s : No real one. Removing opts\n", my_name, opts);
		*opts = '\0';
	}
	if (verbose) { fprintf(stderr, "%s opts=%s\n", my_name, opts); }
	return 0;
}

char *read_script(char *file)
{
	FILE *i;
	char *l_text;
	char *tmp_realloc;
	size_t cnt;
	size_t l;
	long arg_max;

	l_text = malloc(SIZE);
	if (!l_text) {
		return NULL;
	}
	i = fopen(file, "r");
	if (!i) {
		free(l_text);
		return NULL;
	}
	for (l = 0;;) {
		if (l > ((size_t)-1) - SIZE - 1) {
			free(l_text);
			fclose(i);
			errno = EOVERFLOW;
			return NULL;
		}
		tmp_realloc = realloc(l_text, l + SIZE);
		if (!tmp_realloc) {
			free(l_text);
			fclose(i);
			return NULL;
		}
		l_text = tmp_realloc;
		cnt = fread(&l_text[l], 1, SIZE, i);
		if (!cnt) {
			if (ferror(i)) {
				free(l_text);
				fclose(i);
				return NULL;
			}
			break;
		}
		l += cnt;
		if (l > (size_t)INT_MAX - (1U << 12) - 1U) {
			fprintf(stderr, "%s: script too large for generated C runtime: %s\n", my_name, file);
			free(l_text);
			fclose(i);
			errno = EOVERFLOW;
			return NULL;
		}
	}
	fclose(i);
	tmp_realloc = realloc(l_text, l + 1);
	if (!tmp_realloc) {
		free(l_text);
		return NULL;
	}
	l_text = tmp_realloc;
	l_text[l] = '\0';

	/* Check current System ARG_MAX limit. */
	arg_max = sysconf(_SC_ARG_MAX);
	if (!PIPESCRIPT_flag && arg_max > 0 && (double)l > 0.80 * (double)arg_max) {
		fprintf(stderr, "%s: WARNING!!\n"
			"   Scripts of length near to (or higher than) the current System limit on\n"
			"   \"maximum size of arguments to EXEC\", could comprise its binary execution.\n"
			"   In the current System the call sysconf(_SC_ARG_MAX) returns %ld bytes\n"
			"   and your script \"%s\" is %zu bytes length.\n",
			my_name, arg_max, file, l);
	}
	return l_text;
}

unsigned rand_mod(unsigned mod)
{
	/* Without skew */
	unsigned rnd, top = RAND_MAX;
	top -= top % mod;
	while (top <= (rnd = rand())) {  // NOLINT
		continue;
	}
	/* Using high-order bits. */
	rnd = 1.0 * mod * rnd / (1.0 + top);
	return rnd;
}

char rand_chr(void)
{
	return (char)rand_mod(1 << (sizeof(char) << 3));
}

int noise(char *ptr, unsigned min, unsigned xtra, int str)
{
	if (xtra) { xtra = rand_mod(xtra); }
	xtra += min;
	for (min = 0; min < xtra; min++, ptr++) {
		do {
			*ptr = rand_chr();
		} while (str && !isalnum((int)*ptr));
	}
	if (str) { *ptr = '\0'; }
	return xtra;
}

static int offset;

void prnt_bytes(FILE *o, char *ptr, int m, int l, int n)
{
	int i;

	l += m;
	n += l;
	for (i = 0; i < n; i++) {
		if ((i & 0xf) == 0) {
			fprintf(o, "\n\t\"");
		}
		fprintf(o, "\\%03o", (unsigned char)((i >= m) && (i < l) ? ptr[i - m] : rand_chr()));
		if ((i & 0xf) == 0xf) {
			fprintf(o, "\"");
		}
	}
	if ((i & 0xf) != 0) {
		fprintf(o, "\"");
	}
	offset += n;
}

void prnt_array(FILE *o, void *ptr, char *name, int l, char *cast)
{
	int m = rand_mod(1 + l / 4);    /* Random amount of random pre  padding (offset) */
	int n = rand_mod(1 + l / 4);    /* Random amount of random post padding  (tail)  */
	int a = l?(offset + m) % l : 0;
	if (cast && a) { m += l - a; }  /* Type alignment. */
	fprintf(o, "\n");
	fprintf(o, "#define      %s_z	%d", name, l);
	fprintf(o, "\n");
	fprintf(o, "#define      %s	(%s(&data[%d]))", name, cast?cast : "", offset + m);
	prnt_bytes(o, ptr, m, l, n);
}

void dump_array(FILE *o, void *ptr, char *name, int l, char *cast)
{
	arc4(ptr, l);
	prnt_array(o, ptr, name, l, cast);
}

void cleanup_write_c(char *msg1, char *msg2, char *chk1, char *chk2, char *tst1, char *tst2, char *kwsh, char *name)
{
	if (msg1) { free(msg1); }
	if (msg2) { free(msg2); }
	if (chk1) { free(chk1); }
	if (chk2) { free(chk2); }
	if (tst1) { free(tst1); }
	if (tst2) { free(tst2); }
	if (kwsh) { free(kwsh); }
	if (name) { free(name); }
}

int write_C(char *file, int argc, char *argv[])
{
	char pswd[256];
	int pswd_z = sizeof(pswd);
	char *msg1 = xstrdup("has expired!\n");
	char *kwsh = xstrdup(shll);
	char *tst1 = xstrdup("location has changed!");
	char *chk1 = xstrdup("location has changed!");
	char *msg2 = xstrdup("abnormal behavior!");
	char *tst2 = xstrdup("shell has changed!");
	char *chk2 = xstrdup("shell has changed!");
	char *name = xstrdup(file);
	int msg1_z;
	int date_z;
	int shll_z;
	int inlo_z;
	int pfmt_z;
	int xecc_z;
	int lsto_z;
	int tst1_z;
	int chk1_z;
	int msg2_z;
	int rlax_z = sizeof(rlax);
	int opts_z;
	int text_z;
	int tst2_z;
	int chk2_z;
	FILE *o;
	int l_idx;
	int numd = 0;
	int done = 0;

	if (!msg1 || !kwsh || !tst1 || !chk1 || !msg2 || !tst2 || !chk2 || !name) {
		fprintf(stderr, "%s: memory allocation failed while preparing generated C source\n", my_name);
		cleanup_write_c(msg1, msg2, chk1, chk2, tst1, tst2, kwsh, name);
		return -1;
	}
	if (!shll || !inlo || !pfmt || !xecc || !lsto || !opts || !text) {
		fprintf(stderr, "%s: internal error: missing generated runtime data\n", my_name);
		cleanup_write_c(msg1, msg2, chk1, chk2, tst1, tst2, kwsh, name);
		return -1;
	}

	msg1_z = (int)strlen(msg1) + 1;
	date_z = (int)strlen(date) + 1;
	shll_z = (int)strlen(shll) + 1;
	inlo_z = (int)strlen(inlo) + 1;
	pfmt_z = (int)strlen(pfmt) + 1;
	xecc_z = (int)strlen(xecc) + 1;
	lsto_z = (int)strlen(lsto) + 1;
	tst1_z = (int)strlen(tst1) + 1;
	chk1_z = tst1_z;
	msg2_z = (int)strlen(msg2) + 1;
	opts_z = (int)strlen(opts) + 1;
	text_z = (int)strlen(text) + 1;
	tst2_z = (int)strlen(tst2) + 1;
	chk2_z = tst2_z;

	/* Encrypt */
	srand((unsigned)time(NULL) ^ (unsigned)getpid());
	pswd_z = noise(pswd, pswd_z, 0, 0); numd++;
	stte_0();
	key(pswd, pswd_z);
	if (append_suffix(&msg1, mail) != 0) {
		fprintf(stderr, "%s: memory allocation failed while preparing expiration message\n", my_name);
		cleanup_write_c(msg1, msg2, chk1, chk2, tst1, tst2, kwsh, name);
		return -1;
	}
	msg1_z = (int)strlen(msg1) + 1;
	arc4(msg1, msg1_z); numd++;
	arc4(date, date_z); numd++;
	arc4(shll, shll_z); numd++;
	arc4(inlo, inlo_z); numd++;
	arc4(pfmt, pfmt_z); numd++;
	arc4(xecc, xecc_z); numd++;
	arc4(lsto, lsto_z); numd++;
	arc4(opts, opts_z); numd++;
	arc4(tst1, tst1_z); numd++;
	key(chk1, chk1_z);
	arc4(chk1, chk1_z); numd++;
	arc4(msg2, msg2_z); numd++;
	l_idx = !rlax[0];
	arc4(rlax, rlax_z); numd++;
	if (l_idx && key_with_file(kwsh)) {
		fprintf(stderr, "%s: invalid file name: %s ", my_name, kwsh);
		perror("");
		cleanup_write_c(msg1, msg2, chk1, chk2, tst1, tst2, kwsh, name);
		exit(1);
	}
	arc4(text, text_z); numd++;
	arc4(tst2, tst2_z); numd++;
	key(chk2, chk2_z);
	arc4(chk2, chk2_z); numd++;

	/* Output */
	if (append_suffix(&name, ".x.c") != 0) {
		fprintf(stderr, "%s: memory allocation failed while preparing output C filename\n", my_name);
		cleanup_write_c(msg1, msg2, chk1, chk2, tst1, tst2, kwsh, name);
		return -1;
	}
	{
		int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
		if (fd < 0) {
			fprintf(stderr, "%s: creating output file: %s ", my_name, name);
			perror("");
			cleanup_write_c(msg1, msg2, chk1, chk2, tst1, tst2, kwsh, name);
			exit(1);
		}
		o = fdopen(fd, "w");
		if (!o) {
			fprintf(stderr, "%s: creating output file: %s ", my_name, name);
			perror("");
			close(fd);
			cleanup_write_c(msg1, msg2, chk1, chk2, tst1, tst2, kwsh, name);
			exit(1);
		}
	}
	fprintf(o, "#if 0\n");
	fprintf(o, "\t%s %s, %s\n", my_name, version, subject);
	fprintf(o, "\t%s %s %s %s\n", cpright, provider.f, provider.s, provider.e);
	fprintf(o, "\tAudit and Hardening by HARRY DS ALSYUNDAWY - ALSYUNDAWY IT SOLUTION (2026)\n\n\t");
	for (l_idx = 0; l_idx < argc; l_idx++) {
		fprintf(o, "%s ", argv[l_idx]);
	}
	fprintf(o, "\n#endif\n\n");
	fprintf(o, "static  char data[] =");
	do {
		done = 0;
		l_idx = rand_mod(16);
		do {
			switch (l_idx) {
			case 0: if (pswd_z >= 0) { prnt_array(o, pswd, "pswd", pswd_z, 0); pswd_z = done = -1; break; }
			/* fall through */
			case 1: if (msg1_z >= 0) { prnt_array(o, msg1, "msg1", msg1_z, 0); msg1_z = done = -1; break; }
			/* fall through */
			case 2: if (date_z >= 0) { prnt_array(o, date, "date", date_z, 0); date_z = done = -1; break; }
			/* fall through */
			case 3: if (shll_z >= 0) { prnt_array(o, shll, "shll", shll_z, 0); shll_z = done = -1; break; }
			/* fall through */
			case 4: if (inlo_z >= 0) { prnt_array(o, inlo, "inlo", inlo_z, 0); inlo_z = done = -1; break; }
			/* fall through */
			case 5: if (xecc_z >= 0) { prnt_array(o, xecc, "xecc", xecc_z, 0); xecc_z = done = -1; break; }
			/* fall through */
			case 6: if (lsto_z >= 0) { prnt_array(o, lsto, "lsto", lsto_z, 0); lsto_z = done = -1; break; }
			/* fall through */
			case 7: if (tst1_z >= 0) { prnt_array(o, tst1, "tst1", tst1_z, 0); tst1_z = done = -1; break; }
			/* fall through */
			case 8: if (chk1_z >= 0) { prnt_array(o, chk1, "chk1", chk1_z, 0); chk1_z = done = -1; break; }
			/* fall through */
			case 9: if (msg2_z >= 0) { prnt_array(o, msg2, "msg2", msg2_z, 0); msg2_z = done = -1; break; }
			/* fall through */
			case 10: if (rlax_z >= 0) { prnt_array(o, rlax, "rlax", rlax_z, 0); rlax_z = done = -1; break; }
			/* fall through */
			case 11: if (opts_z >= 0) { prnt_array(o, opts, "opts", opts_z, 0); opts_z = done = -1; break; }
			/* fall through */
			case 12: if (text_z >= 0) { prnt_array(o, text, "text", text_z, 0); text_z = done = -1; break; }
			/* fall through */
			case 13: if (tst2_z >= 0) { prnt_array(o, tst2, "tst2", tst2_z, 0); tst2_z = done = -1; break; }
			/* fall through */
			case 14: if (chk2_z >= 0) { prnt_array(o, chk2, "chk2", chk2_z, 0); chk2_z = done = -1; break; }
			/* fall through */
			case 15: if (pfmt_z >= 0) { prnt_array(o, pfmt, "pfmt", pfmt_z, 0); pfmt_z = done = -1; break; }
			}
			l_idx = 0;
		} while (!done);
	} while (numd += done);
	cleanup_write_c(msg1, msg2, chk1, chk2, tst1, tst2, kwsh, name);
	fprintf(o, "/* End of data[] */;\n");
	fprintf(o, "#define      %s_z	%d\n", "hide", 1 << 12);
	fprintf(o, SETUID_line, SETUID_flag);
	fprintf(o, DEBUGEXEC_line, DEBUGEXEC_flag);
	fprintf(o, TRACEABLE_line, TRACEABLE_flag);
	fprintf(o, PIPESCRIPT_line, PIPESCRIPT_flag);
	fprintf(o, FIXARGV0_line, FIXARGV0_flag);
	fprintf(o, HARDENING_line, HARDENING_flag);
	fprintf(o, BUSYBOXON_line, BUSYBOXON_flag);
	fprintf(o, MMAP2_line, MMAP2_flag);
	for (l_idx = 0; RTC[l_idx]; l_idx++) {
		fprintf(o, "%s\n", RTC[l_idx]);
	}
	fflush(o);
	fclose(o);

	return 0;
}

int make(void)
{
	const char *cc;
	const char *cflags;
	const char *ldflags;
	const char *strip;
	char *src;
	size_t src_len;
	struct argv_builder build = {0};
	struct argv_builder strip_cmd = {0};
	int ret = -1;

	if (!file) {
		errno = EINVAL;
		return -1;
	}
	if (!file2 && build_default_output_name() != 0) {
		return -1;
	}

	src_len = strlen(file);
	if (src_len > ((size_t)-1) - 5) {
		errno = EOVERFLOW;
		return -1;
	}
	src = malloc(src_len + 5);
	if (!src) {
		return -1;
	}
	memcpy(src, file, src_len);
	memcpy(src + src_len, ".x.c", 5);

	cc = getenv("CC");
	if (!cc || !*cc) {
		cc = "cc";
	}
	cflags = getenv("CFLAGS");
	if (!cflags) {
		cflags = "";
	}
	ldflags = getenv("LDFLAGS");
	if (!ldflags) {
		ldflags = "";
	}

	if (split_words_append(&build, cc) != 0 || build.argc == 0 ||
	    split_words_append(&build, cflags) != 0 ||
	    split_words_append(&build, ldflags) != 0 ||
	    argv_builder_push_copy(&build, src) != 0 ||
	    argv_builder_push_copy(&build, "-o") != 0 ||
	    argv_builder_push_copy(&build, file2) != 0) {
		fprintf(stderr, "%s: failed to prepare compiler argv\n", my_name);
		goto out;
	}

	if (verbose) {
		print_argv(stderr, "shc: ", build.argv);
	}
	ret = run_argv(build.argv);
	if (ret != 0) {
		goto out;
	}

	strip = getenv("STRIP");
	if (!strip || !*strip) {
		strip = "strip";
	}
	if (split_words_append(&strip_cmd, strip) != 0 || strip_cmd.argc == 0 ||
	    argv_builder_push_copy(&strip_cmd, file2) != 0) {
		fprintf(stderr, "%s: failed to prepare strip argv\n", my_name);
		goto chmod_output;
	}
	if (verbose) {
		print_argv(stderr, "shc: ", strip_cmd.argv);
	}
	if (run_argv(strip_cmd.argv) != 0) {
		fprintf(stderr, "%s: strip failed; keeping unstripped output\n", my_name);
	}

chmod_output:
	if (chmod(file2, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0) {
		fprintf(stderr, "%s: chmod failed for %s: %s\n", my_name, file2, strerror(errno));
	}
	ret = 0;

out:
	argv_builder_free(&build);
	argv_builder_free(&strip_cmd);
	free(src);
	return ret;
}


void do_all(int argc, char *argv[])
{
	parse_args(argc, argv);
	text = read_script(file);
	if (!text) {
		return;
	}
	if (eval_shell(text)) {
		return;
	}
	if (
		strstr(shll, "python")
		|| strstr(shll, "perl")
		|| strstr(shll, "csh")
		) {
		// Default to pipe method for python, perl, csh
		// to ensure expected behavior
		// - csh: prevent interpretation of '!' as history
		PIPESCRIPT_flag = 1;
		FIXARGV0_flag = 1;
	}
	if (write_C(file, argc, argv)) {
		return;
	}
	if (make()) {
		return;
	}
	exit(0);
}

int main(int argc, char *argv[])
{
	setenv("LANG", "", 1);
	do_all(argc, argv);
	/* Return on error */
	perror(argv[0]);
	exit(1);
	return 1;
}
