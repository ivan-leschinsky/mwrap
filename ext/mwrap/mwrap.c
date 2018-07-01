/*
 * Copyright (C) 2018 mwrap hackers <mwrap-public@80x24.org>
 * License: GPL-2.0+ <https://www.gnu.org/licenses/gpl-2.0.txt>
 */
#include <ruby/ruby.h>
#include <ruby/thread.h>
#include <ruby/util.h>
#include <ruby/st.h>
#include <ruby/io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

const char *rb_source_location_cstr(int *line); /* requires 2.6.0dev */
static int *(*has_gvl_p)(void);
static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);

/*
 * rb_source_location_cstr relies on GET_EC(), and it's possible
 * to have a native thread but no EC during the early and late
 * (teardown) phases of the Ruby process
 */
static void **ec_loc;

/*
 * we need to fake an OOM condition while dlsym is running,
 * as that calls calloc under glibc, but we don't have the
 * symbol for the jemalloc calloc, yet
 */
#  define RETURN_IF_NOT_READY(x) do { \
	if (!x) { \
		errno = ENOMEM; \
		return NULL; \
	} \
} while (0)

__attribute__((constructor)) static void resolve_malloc(void)
{
	real_calloc = dlsym(RTLD_NEXT, "calloc");
	real_malloc = dlsym(RTLD_NEXT, "malloc");
	real_realloc = dlsym(RTLD_NEXT, "realloc");
	assert(real_calloc && real_malloc && real_realloc);

	has_gvl_p = dlsym(RTLD_DEFAULT, "ruby_thread_has_gvl_p");

	/*
	 * resolve dynamically so it doesn't break when LD_PRELOAD-ed
	 * into non-Ruby binaries
	 */
	ec_loc = dlsym(RTLD_DEFAULT, "ruby_current_execution_context_ptr");
}

#ifndef HAVE_MEMPCPY
#  define mempcpy(dst,src,n) ((char *)memcpy((dst),(src),(n)) + n)
#endif

/* stolen from glibc: */
#define RETURN_ADDRESS(nr) \
  __builtin_extract_return_addr(__builtin_return_address(nr))

static __thread size_t locating;
static st_table *stats;	/* rb_source_location => size */

/* bytes allocated outside of GVL */
static size_t unknown_bytes;

#define INT2STR_MAX (sizeof(int) == 4 ? 10 : 19)
static char *int2str(int num, char *dst, size_t * size)
{
	if (num <= 9) {
		*size -= 1;
		*dst++ = (char)(num + '0');
		return dst;
	} else {
		char buf[INT2STR_MAX];
		char *end = buf + sizeof(buf);
		char *p = end;
		size_t adj;

		do {
			*size -= 1;
			*--p = (char)((num % 10) + '0');
			num /= 10;
		} while (num && *size);

		if (!num) {
			adj = end - p;
			return mempcpy(dst, p, adj);
		}
	}
	return NULL;
}

static int
update_stat(st_data_t *k, st_data_t *v, st_data_t arg, int existing)
{
	size_t *total = (size_t *) v;
	size_t size = arg;

	if (existing) {
		*total += size;
	} else {
		char *key = *(char **)k;
		*k = (st_data_t)ruby_strdup(key);
		*total = size;
	}
	return ST_CONTINUE;
}

static int has_ec_p(void)
{
	return (ec_loc && *ec_loc);
}

static void update_stats(size_t size, const void *caller)
{
	if (locating++) goto out; /* do not recurse into another *alloc */

	if (has_gvl_p && has_gvl_p() && has_ec_p()) {
		int line;
		size_t len;
		char *key, *dst;
		const char *ptr = rb_source_location_cstr(&line);
		size_t int_size = INT2STR_MAX;

		if (!stats) stats = st_init_strtable_with_size(16384);
		if (!ptr) goto unknown;

		/* avoid vsnprintf or anything which could call malloc here: */
		len = strlen(ptr);
		key = alloca(len + 1 + int_size + 1);
		dst = mempcpy(key, ptr, len);
		*dst++ = ':';
		dst = int2str(line, dst, &int_size);
		if (dst) {
			*dst = 0;	/* terminate string */
			st_update(stats, (st_data_t)key,
				   update_stat, (st_data_t)size);
		} else {
			rb_bug("bad math making key from location %s:%d\n",
				ptr, line);
		}
	} else { /* TODO: do something with caller */
unknown:
		__sync_add_and_fetch(&unknown_bytes, size);
	}
out:
	--locating;
}

/*
 * Do we care for *memalign? ruby/gc.c uses it in ways this lib
 * doesn't care about, but maybe some gems use it, too.
 */
void *malloc(size_t size)
{
	RETURN_IF_NOT_READY(real_malloc);
	update_stats(size, RETURN_ADDRESS(0));
	return real_malloc(size);
}

void *calloc(size_t nmemb, size_t size)
{
	RETURN_IF_NOT_READY(real_calloc);
	/* ruby_xcalloc already does overflow checking */
	update_stats(nmemb * size, RETURN_ADDRESS(0));
	return real_calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size)
{
	RETURN_IF_NOT_READY(real_realloc);
	update_stats(size, RETURN_ADDRESS(0));
	return real_realloc(ptr, size);
}

struct dump_arg {
	FILE *fp;
	size_t min;
};

static int dump_i(const char *key, size_t val, struct dump_arg *a)
{
	if (val > a->min) {
		fprintf(a->fp, "%20" PRIuSIZE " %s\n", val, key);
	}

	return ST_CONTINUE;
}

static VALUE dump_to_file(VALUE x)
{
	struct dump_arg *a = (struct dump_arg *)x;

	if (stats) st_foreach(stats, dump_i, (st_data_t) a);
	if (unknown_bytes > a->min) {
		fprintf(a->fp, "%20" PRIuSIZE " (unknown[%d])\n",
			unknown_bytes, getpid());
	}

	return Qnil;
}

static VALUE dump_ensure(VALUE ignored)
{
	--locating;
	return Qfalse;
}

static VALUE mwrap_dump(int argc, VALUE * argv, VALUE mod)
{
	VALUE io, min;
	struct dump_arg a;
	rb_io_t *fptr;

	rb_scan_args(argc, argv, "02", &io, &min);

	if (NIL_P(io))
		io = *((VALUE *)dlsym(RTLD_DEFAULT, "rb_stderr"));

	a.min = NIL_P(min) ? 0 : NUM2SIZET(min);
	io = rb_io_get_write_io(io);
	GetOpenFile(io, fptr);
	a.fp = rb_io_stdio_file(fptr);

	++locating;
	return rb_ensure(dump_to_file, (VALUE) & a, dump_ensure, Qfalse);
}

static int clear_i(char *key, size_t val, void *ignored)
{
	xfree(key);
	return ST_DELETE;
}

static VALUE mwrap_clear(VALUE mod)
{
	unknown_bytes = 0;
	st_foreach(stats, clear_i, 0);
	return Qnil;
}

void Init_mwrap(void)
{
	VALUE mod = rb_define_module("Mwrap");

	if (!stats) stats = st_init_strtable_with_size(16384);

	rb_define_singleton_method(mod, "dump", mwrap_dump, -1);
	rb_define_singleton_method(mod, "clear", mwrap_clear, 0);
}

/* rb_cloexec_open isn't usable by non-Ruby processes */
#ifndef O_CLOEXEC
#  define O_CLOEXEC 0
#endif

__attribute__ ((destructor))
static void mwrap_dump_destructor(void)
{
        const char *opt = getenv("MWRAP");
        const char *modes[] = { "a", "a+", "w", "w+", "r+" };
        struct dump_arg a;
        size_t i;
        int dump_fd;
	char *dump_path;

	if (!opt)
		return;

        ++locating;
        if ((dump_path = strstr(opt, "dump_path:")) &&
			(dump_path += sizeof("dump_path")) &&
			*dump_path) {
		char *end = strchr(dump_path, ',');
		if (end) {
			char *tmp = alloca(end - dump_path + 1);
			*((char *)mempcpy(tmp, dump_path, end - dump_path)) = 0;
			dump_path = tmp;
		}
		dump_fd = open(dump_path, O_CLOEXEC|O_WRONLY|O_APPEND|O_CREAT,
				0666);
		if (dump_fd < 0) {
			fprintf(stderr, "open %s failed: %s\n", dump_path,
				strerror(errno));
			goto out;
		}
	}
	else if (!sscanf(opt, "dump_fd:%d", &dump_fd))
		goto out;

	if (!sscanf(opt, "dump_min:%zu", &a.min))
		a.min = 0;

	switch (dump_fd) {
	case 0: goto out;
	case 1: a.fp = stdout; break;
	case 2: a.fp = stderr; break;
	default:
		if (dump_fd < 0)
			goto out;
		a.fp = 0;

		for (i = 0; !a.fp && i < 5; i++)
			a.fp = fdopen(dump_fd, modes[i]);

		if (!a.fp) {
			fprintf(stderr, "failed to open fd=%d: %s\n",
				dump_fd, strerror(errno));
			goto out;
		}
		/* we'll leak some memory here, but this is a destructor */
	}
	dump_to_file((VALUE)&a);
out:
    --locating;
}
