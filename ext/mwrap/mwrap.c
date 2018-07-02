/*
 * Copyright (C) 2018 mwrap hackers <mwrap-public@80x24.org>
 * License: GPL-2.0+ <https://www.gnu.org/licenses/gpl-2.0.txt>
 */
#define _LGPL_SOURCE /* allows URCU to inline some stuff */
#include <ruby/ruby.h>
#include <ruby/thread.h>
#include <ruby/io.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <urcu-bp.h>
#include <urcu/rculfhash.h>
#include "jhash.h"

static ID id_uminus;
const char *rb_source_location_cstr(int *line); /* requires 2.6.0dev */
static int *(*has_gvl_p)(void);
#ifdef __FreeBSD__
void *__malloc(size_t);
void *__calloc(size_t, size_t);
void *__realloc(void *, size_t);
static void *(*real_malloc)(size_t) = __malloc;
static void *(*real_calloc)(size_t, size_t) = __calloc;
static void *(*real_realloc)(void *, size_t) = __realloc;
#  define RETURN_IF_NOT_READY() do {} while (0) /* nothing */
#else
static int ready;
static void *(*real_malloc)(size_t);
static void *(*real_calloc)(size_t, size_t);
static void *(*real_realloc)(void *, size_t);

/*
 * we need to fake an OOM condition while dlsym is running,
 * as that calls calloc under glibc, but we don't have the
 * symbol for the jemalloc calloc, yet
 */
#  define RETURN_IF_NOT_READY() do { \
	if (!ready) { \
		errno = ENOMEM; \
		return NULL; \
	} \
} while (0)

#endif /* !FreeBSD */

/*
 * rb_source_location_cstr relies on GET_EC(), and it's possible
 * to have a native thread but no EC during the early and late
 * (teardown) phases of the Ruby process
 */
static void **ec_loc;

static struct cds_lfht *totals;

static struct cds_lfht *
lfht_new(void)
{
	return cds_lfht_new(16384, 1, 0, CDS_LFHT_AUTO_RESIZE, 0);
}

__attribute__((constructor)) static void resolve_malloc(void)
{
	int err;

#ifndef __FreeBSD__
	real_malloc = dlsym(RTLD_NEXT, "malloc");
	real_calloc = dlsym(RTLD_NEXT, "calloc");
	real_realloc = dlsym(RTLD_NEXT, "realloc");
	if (!real_calloc || !real_malloc || !real_realloc) {
		fprintf(stderr, "missing calloc/malloc/realloc %p %p %p\n",
			real_calloc, real_malloc, real_realloc);
		_exit(1);
	}
	ready = 1;
#endif

	totals = lfht_new();
	if (!totals)
		fprintf(stderr, "failed to allocate totals table\n");

	err = pthread_atfork(call_rcu_before_fork,
				call_rcu_after_fork_parent,
				call_rcu_after_fork_child);
	if (err)
		fprintf(stderr, "pthread_atfork failed: %s\n", strerror(err));

	has_gvl_p = dlsym(RTLD_DEFAULT, "ruby_thread_has_gvl_p");

	/*
	 * resolve dynamically so it doesn't break when LD_PRELOAD-ed
	 * into non-Ruby binaries
	 */
	ec_loc = dlsym(RTLD_DEFAULT, "ruby_current_execution_context_ptr");
}

#ifndef HAVE_MEMPCPY
static void *
my_mempcpy(void *dest, const void *src, size_t n)
{
	return (char *)memcpy(dest, src, n) + n;
}
#define mempcpy(dst,src,n) my_mempcpy(dst,src,n)
#endif

/* stolen from glibc: */
#define RETURN_ADDRESS(nr) \
  (uintptr_t)(__builtin_extract_return_addr(__builtin_return_address(nr)))

static __thread size_t locating;

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

static int has_ec_p(void)
{
	return (ec_loc && *ec_loc);
}

struct src_loc {
	struct rcu_head rcu_head;
	size_t calls;
	size_t total;
	struct cds_lfht_node hnode;
	uint32_t hval;
	uint32_t capa;
	char k[];
};

static int loc_is_addr(const struct src_loc *l)
{
	return l->capa == 0;
}

static size_t loc_size(const struct src_loc *l)
{
	return loc_is_addr(l) ? sizeof(uintptr_t) : l->capa;
}

static int loc_eq(struct cds_lfht_node *node, const void *key)
{
	const struct src_loc *existing;
	const struct src_loc *k = key;

	existing = caa_container_of(node, struct src_loc, hnode);

	return (k->hval == existing->hval &&
		k->capa == existing->capa &&
		memcmp(k->k, existing->k, loc_size(k)) == 0);
}

static void totals_add(struct src_loc *k)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *cur;
	struct src_loc *l;
	struct cds_lfht *t;


again:
	rcu_read_lock();
	t = rcu_dereference(totals);
	if (!t) goto out_unlock;
	cds_lfht_lookup(t, k->hval, loc_eq, k, &iter);
	cur = cds_lfht_iter_get_node(&iter);
	if (cur) {
		l = caa_container_of(cur, struct src_loc, hnode);
		uatomic_add(&l->total, k->total);
		uatomic_add(&l->calls, 1);
	} else {
		size_t n = loc_size(k);
		l = malloc(sizeof(*l) + n);
		if (!l) goto out_unlock;

		memcpy(l, k, sizeof(*l) + n);
		l->calls = 1;
		cur = cds_lfht_add_unique(t, k->hval, loc_eq, l, &l->hnode);
		if (cur != &l->hnode) { /* lost race */
			rcu_read_unlock();
			free(l);
			goto again;
		}
	}
out_unlock:
	rcu_read_unlock();
}

static void update_stats(size_t size, uintptr_t caller)
{
	struct src_loc *k;
	static const size_t xlen = sizeof(caller);
	char *dst;

	if (locating++) goto out; /* do not recurse into another *alloc */

	if (has_gvl_p && has_gvl_p() && has_ec_p()) {
		int line;
		const char *ptr = rb_source_location_cstr(&line);
		size_t len;
		size_t int_size = INT2STR_MAX;

		if (!ptr) goto unknown;

		/* avoid vsnprintf or anything which could call malloc here: */
		len = strlen(ptr);
		k = alloca(sizeof(*k) + len + 1 + int_size + 1);
		k->total = size;
		dst = mempcpy(k->k, ptr, len);
		*dst++ = ':';
		dst = int2str(line, dst, &int_size);
		if (dst) {
			*dst = 0;	/* terminate string */
			k->capa = (uint32_t)(dst - k->k + 1);
			k->hval = jhash(k->k, k->capa, 0xdeadbeef);
			totals_add(k);
		} else {
			rb_bug("bad math making key from location %s:%d\n",
				ptr, line);
		}
	} else {
unknown:
		k = alloca(sizeof(*k) + xlen);
		k->total = size;
		memcpy(k->k, &caller, xlen);
		k->capa = 0;
		k->hval = jhash(k->k, xlen, 0xdeadbeef);
		totals_add(k);
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
	RETURN_IF_NOT_READY();
	update_stats(size, RETURN_ADDRESS(0));
	return real_malloc(size);
}

void *calloc(size_t nmemb, size_t size)
{
	RETURN_IF_NOT_READY();
	/* ruby_xcalloc already does overflow checking */
	update_stats(nmemb * size, RETURN_ADDRESS(0));
	return real_calloc(nmemb, size);
}

void *realloc(void *ptr, size_t size)
{
	RETURN_IF_NOT_READY();
	update_stats(size, RETURN_ADDRESS(0));
	return real_realloc(ptr, size);
}

struct dump_arg {
	FILE *fp;
	size_t min;
};

static void dump_to_file(struct dump_arg *a)
{
	struct cds_lfht_iter iter;
	struct src_loc *l;
	struct cds_lfht *t;

	rcu_read_lock();
	t = rcu_dereference(totals);
	if (t) {
		cds_lfht_for_each_entry(t, &iter, l, hnode) {
			const void *p = l->k;
			char **s = 0;
			if (l->total <= a->min) continue;

			if (loc_is_addr(l)) {
				s = backtrace_symbols(p, 1);
				p = s[0];
			}
			fprintf(a->fp, "%16zu %12zu %s\n",
				l->total, l->calls, (const char *)p);
			if (s) free(s);
		}
	}
	rcu_read_unlock();
}

static VALUE mwrap_dump(int argc, VALUE * argv, VALUE mod)
{
	VALUE io, min;
	struct dump_arg a;
	rb_io_t *fptr;

	rb_scan_args(argc, argv, "02", &io, &min);

	if (NIL_P(io))
		/* library may be linked w/o Ruby */
		io = *((VALUE *)dlsym(RTLD_DEFAULT, "rb_stderr"));

	a.min = NIL_P(min) ? 0 : NUM2SIZET(min);
	io = rb_io_get_write_io(io);
	GetOpenFile(io, fptr);
	a.fp = rb_io_stdio_file(fptr);

	++locating;
	dump_to_file(&a);
	--locating;
	return Qnil;
}

static void
free_src_loc(struct rcu_head *head)
{
	struct src_loc *l = caa_container_of(head, struct src_loc, rcu_head);
	free(l);
}

static VALUE mwrap_clear(VALUE mod)
{
	struct cds_lfht *new, *old;
	struct cds_lfht_iter iter;
	struct src_loc *l;

	new = lfht_new();
	rcu_read_lock();
	old = rcu_dereference(totals);
	rcu_assign_pointer(totals, new);
	cds_lfht_for_each_entry(old, &iter, l, hnode) {
		cds_lfht_del(old, &l->hnode);
		call_rcu(&l->rcu_head, free_src_loc);
	}
	rcu_read_unlock();

	synchronize_rcu(); /* ensure totals points to new */

	cds_lfht_destroy(old, NULL);

	return Qnil;
}

static VALUE mwrap_reset(VALUE mod)
{
	struct cds_lfht *t;
	struct cds_lfht_iter iter;
	struct src_loc *l;

	rcu_read_lock();
	t = rcu_dereference(totals);
	cds_lfht_for_each_entry(t, &iter, l, hnode) {
		uatomic_set(&l->total, 0);
		uatomic_set(&l->calls, 0);
	}
	rcu_read_unlock();

	return Qnil;
}

static VALUE dump_ensure(VALUE ignored)
{
	rcu_read_unlock();
	--locating;
	return Qfalse;
}

static VALUE dump_each_rcu(VALUE x)
{
	struct dump_arg *a = (struct dump_arg *)x;
	struct cds_lfht *t;
	struct cds_lfht_iter iter;
	struct src_loc *l;

	t = rcu_dereference(totals);
	if (t) {
		cds_lfht_for_each_entry(t, &iter, l, hnode) {
			VALUE v[3];
			if (l->total <= a->min) continue;

			if (loc_is_addr(l)) {
				char **s = backtrace_symbols((void *)l->k, 1);
				v[1] = rb_str_new_cstr(s[0]);
				free(s);
			}
			else {
				v[1] = rb_str_new(l->k, l->capa - 1);
			}
			v[0] = rb_funcall(v[1], id_uminus, 0);

			if (!OBJ_FROZEN_RAW(v[1]))
				rb_str_resize(v[1], 0);

			v[1] = SIZET2NUM(l->total);
			v[2] = SIZET2NUM(l->calls);

			rb_yield_values2(3, v);
			assert(rcu_read_ongoing());
		}
	}
	return Qnil;
}

static VALUE mwrap_each(int argc, VALUE * argv, VALUE mod)
{
	VALUE min;
	struct dump_arg a;

	rb_scan_args(argc, argv, "01", &min);
	a.min = NIL_P(min) ? 0 : NUM2SIZET(min);

	++locating;
	rcu_read_lock();

	return rb_ensure(dump_each_rcu, (VALUE)&a, dump_ensure, 0);
}

void Init_mwrap(void)
{
	VALUE mod = rb_define_module("Mwrap");
	id_uminus = rb_intern("-@");

	rb_define_singleton_method(mod, "dump", mwrap_dump, -1);
	rb_define_singleton_method(mod, "clear", mwrap_clear, 0);
	rb_define_singleton_method(mod, "reset", mwrap_reset, 0);
	rb_define_singleton_method(mod, "each", mwrap_each, -1);
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
			end = mempcpy(tmp, dump_path, end - dump_path);
			*end = 0;
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
	dump_to_file(&a);
out:
    --locating;
}
