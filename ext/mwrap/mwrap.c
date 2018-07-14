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
#include <pthread.h>
#include <urcu-bp.h>
#include <urcu/rculfhash.h>
#include <urcu/rculist.h>
#include "jhash.h"

static ID id_uminus;
const char *rb_source_location_cstr(int *line); /* requires 2.6.0dev */
extern int __attribute__((weak)) ruby_thread_has_gvl_p(void);
extern void * __attribute__((weak)) ruby_current_execution_context_ptr;
extern void * __attribute__((weak)) ruby_current_vm_ptr; /* for rb_gc_count */
extern size_t __attribute__((weak)) rb_gc_count(void);

/* true for glibc/dlmalloc/ptmalloc, not sure about jemalloc */
#define ASSUMED_MALLOC_ALIGNMENT (sizeof(void *) * 2)

int __attribute__((weak)) ruby_thread_has_gvl_p(void)
{
	return 0;
}

#ifdef __FreeBSD__
void *__malloc(size_t);
void __free(void *);
static void *(*real_malloc)(size_t) = __malloc;
static void (*real_free)(void *) = __free;
#  define RETURN_IF_NOT_READY() do {} while (0) /* nothing */
#else
static int ready;
static void *(*real_malloc)(size_t);
static void (*real_free)(void *);

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

static size_t generation;
static size_t page_size;
static struct cds_lfht *totals;
union padded_mutex {
	pthread_mutex_t mtx;
	char pad[64];
};

/* a round-robin pool of mutexes */
#define MUTEX_NR   (1 << 6)
#define MUTEX_MASK (MUTEX_NR - 1)
static size_t mutex_i;
static union padded_mutex mutexes[MUTEX_NR] = {
	[0 ... (MUTEX_NR-1)].mtx = PTHREAD_MUTEX_INITIALIZER
};

static pthread_mutex_t *mutex_assign(void)
{
	return &mutexes[uatomic_add_return(&mutex_i, 1) & MUTEX_MASK].mtx;
}

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
	real_free = dlsym(RTLD_NEXT, "free");
	if (!real_malloc || !real_free) {
		fprintf(stderr, "missing malloc/aligned_alloc/free\n"
			"\t%p %p\n", real_malloc, real_free);
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
	page_size = sysconf(_SC_PAGESIZE);
}

static void
mutex_lock(pthread_mutex_t *m)
{
	int err = pthread_mutex_lock(m);
	assert(err == 0);
}

static void
mutex_unlock(pthread_mutex_t *m)
{
	int err = pthread_mutex_unlock(m);
	assert(err == 0);
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

/*
 * rb_source_location_cstr relies on GET_EC(), and it's possible
 * to have a native thread but no EC during the early and late
 * (teardown) phases of the Ruby process
 */
static int has_ec_p(void)
{
	return (ruby_thread_has_gvl_p() && ruby_current_vm_ptr &&
		ruby_current_execution_context_ptr);
}

/* allocated via real_malloc/real_free */
struct src_loc {
	struct rcu_head rcu_head;
	pthread_mutex_t *mtx;
	size_t calls;
	size_t total;
	struct cds_lfht_node hnode;
	struct cds_list_head allocs; /* <=> alloc_hdr.node */
	uint32_t hval;
	uint32_t capa;
	char k[];
};

/* every allocation has this in the header, maintain alignment with malloc  */
struct alloc_hdr {
	struct cds_list_head anode; /* <=> src_loc.allocs */
	union {
		struct {
			size_t gen; /* rb_gc_count() */
			struct src_loc *loc;
		} live;
		struct rcu_head dead;
	} as;
	void *real; /* what to call real_free on */
	size_t size;
};

static struct alloc_hdr *ptr2hdr(void *p)
{
	return (struct alloc_hdr *)((uintptr_t)p - sizeof(struct alloc_hdr));
}

static void *hdr2ptr(struct alloc_hdr *h)
{
	return (void *)((uintptr_t)h + sizeof(struct alloc_hdr));
}

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

static struct src_loc *totals_add_rcu(struct src_loc *k)
{
	struct cds_lfht_iter iter;
	struct cds_lfht_node *cur;
	struct src_loc *l = 0;
	struct cds_lfht *t;

again:
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
		l = real_malloc(sizeof(*l) + n);
		if (!l) goto out_unlock;
		memcpy(l, k, sizeof(*l) + n);
		l->mtx = mutex_assign();
		l->calls = 1;
		CDS_INIT_LIST_HEAD(&l->allocs);
		cur = cds_lfht_add_unique(t, k->hval, loc_eq, l, &l->hnode);
		if (cur != &l->hnode) { /* lost race */
			rcu_read_unlock();
			real_free(l);
			rcu_read_lock();
			goto again;
		}
	}
out_unlock:
	return l;
}

static struct src_loc *update_stats_rcu(size_t size, uintptr_t caller)
{
	struct src_loc *k, *ret = 0;
	static const size_t xlen = sizeof(caller);
	char *dst;

	assert(rcu_read_ongoing());

	if (locating++) goto out; /* do not recurse into another *alloc */

	if (has_ec_p()) {
		int line;
		const char *ptr = rb_source_location_cstr(&line);
		size_t len;
		size_t int_size = INT2STR_MAX;

		generation = rb_gc_count();

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
			ret = totals_add_rcu(k);
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
		ret = totals_add_rcu(k);
	}
out:
	--locating;
	return ret;
}

size_t malloc_usable_size(void *p)
{
	return ptr2hdr(p)->size;
}

static void
free_hdr_rcu(struct rcu_head *dead)
{
	struct alloc_hdr *h = caa_container_of(dead, struct alloc_hdr, as.dead);
	real_free(h->real);
}

void free(void *p)
{
	if (p) {
		struct alloc_hdr *h = ptr2hdr(p);
		if (h->as.live.loc) {
			h->size = 0;
			mutex_lock(h->as.live.loc->mtx);
			cds_list_del_rcu(&h->anode);
			mutex_unlock(h->as.live.loc->mtx);
			call_rcu(&h->as.dead, free_hdr_rcu);
		}
		else {
			real_free(h->real);
		}
	}
}

static void
alloc_insert_rcu(struct src_loc *l, struct alloc_hdr *h, size_t size, void *real)
{
	/* we need src_loc to remain alive for the duration of this call */
	assert(rcu_read_ongoing());
	if (!h) return;
	h->size = size;
	h->real = real;
	h->as.live.loc = l;
	h->as.live.gen = generation;
	if (l) {
		mutex_lock(l->mtx);
		cds_list_add_rcu(&h->anode, &l->allocs);
		mutex_unlock(l->mtx);
	}
}

static size_t size_align(size_t size, size_t alignment)
{
	return ((size + (alignment - 1)) & ~(alignment - 1));
}

static bool ptr_is_aligned(void *ptr, size_t alignment)
{
	return ((uintptr_t)ptr & (alignment - 1)) == 0;
}

static void *ptr_align(void *ptr, size_t alignment)
{
	return (void *)(((uintptr_t)ptr + (alignment - 1)) & ~(alignment - 1));
}

static void *internal_memalign(size_t alignment, size_t size, uintptr_t caller)
{
	struct src_loc *l;
	struct alloc_hdr *h;
	void *p, *real;
	size_t asize;

	RETURN_IF_NOT_READY();
	if (alignment <= ASSUMED_MALLOC_ALIGNMENT)
		return malloc(size);
	for (; alignment < sizeof(struct alloc_hdr); alignment *= 2)
		; /* double alignment until >= sizeof(struct alloc_hdr) */
	if (__builtin_add_overflow(size, alignment, &asize) ||
	    __builtin_add_overflow(asize, sizeof(struct alloc_hdr), &asize)) {
		errno = ENOMEM;
		return 0;
	}
	/* assert(asize == (alignment + size + sizeof(struct alloc_hdr))); */
	rcu_read_lock();
	l = update_stats_rcu(size, caller);
	real = real_malloc(asize);
	p = hdr2ptr(real);
	if (!ptr_is_aligned(p, alignment))
		p = ptr_align(p, alignment);
	h = ptr2hdr(p);
	alloc_insert_rcu(l, h, size, real);
	rcu_read_unlock();

	return p;
}

void *memalign(size_t alignment, size_t size)
{
	return internal_memalign(alignment, size, RETURN_ADDRESS(0));
}

static bool is_power_of_two(size_t n) { return (n & (n - 1)) == 0; }

int posix_memalign(void **p, size_t alignment, size_t size)
{
	size_t d = alignment / sizeof(void*);
	size_t r = alignment % sizeof(void*);

	if (r != 0 || d == 0 || !is_power_of_two(d))
		return EINVAL;

	*p = internal_memalign(alignment, size, RETURN_ADDRESS(0));
	return *p ? 0 : ENOMEM;
}

void *aligned_alloc(size_t, size_t) __attribute__((alias("memalign")));
void cfree(void *) __attribute__((alias("free")));

void *valloc(size_t size)
{
	return internal_memalign(page_size, size, RETURN_ADDRESS(0));
}

#if __GNUC__ < 7
#  define add_overflow_p(a,b) __extension__({ \
		__typeof__(a) _c; \
		__builtin_add_overflow(a,b,&_c); \
	})
#else
#  define add_overflow_p(a,b) \
		__builtin_add_overflow_p((a),(b),(__typeof__(a+b))0)
#endif

void *pvalloc(size_t size)
{
	size_t alignment = page_size;

	if (add_overflow_p(size, alignment)) {
		errno = ENOMEM;
		return 0;
	}
	size = size_align(size, alignment);
	return internal_memalign(alignment, size, RETURN_ADDRESS(0));
}

void *malloc(size_t size)
{
	struct src_loc *l;
	struct alloc_hdr *h;
	size_t asize;
	void *p;

	if (__builtin_add_overflow(size, sizeof(struct alloc_hdr), &asize)) {
		errno = ENOMEM;
		return 0;
	}
	RETURN_IF_NOT_READY();
	rcu_read_lock();
	l = update_stats_rcu(size, RETURN_ADDRESS(0));
	p = h = real_malloc(asize);
	if (h) {
		alloc_insert_rcu(l, h, size, h);
		p = hdr2ptr(h);
	}
	rcu_read_unlock();
	return p;
}

void *calloc(size_t nmemb, size_t size)
{
	void *p;
	struct src_loc *l;
	struct alloc_hdr *h;
	size_t asize;

	if (__builtin_mul_overflow(size, nmemb, &size)) {
		errno = ENOMEM;
		return 0;
	}
	if (__builtin_add_overflow(size, sizeof(struct alloc_hdr), &asize)) {
		errno = ENOMEM;
		return 0;
	}
	RETURN_IF_NOT_READY();
	rcu_read_lock();
	l = update_stats_rcu(size, RETURN_ADDRESS(0));
	p = h = real_malloc(asize);
	if (p) {
		alloc_insert_rcu(l, h, size, h);
		p = hdr2ptr(h);
		memset(p, 0, size);
	}
	rcu_read_unlock();
	return p;
}

void *realloc(void *ptr, size_t size)
{
	void *p;
	struct src_loc *l;
	struct alloc_hdr *h;
	size_t asize;

	if (!size) {
		free(ptr);
		return 0;
	}
	if (__builtin_add_overflow(size, sizeof(struct alloc_hdr), &asize)) {
		errno = ENOMEM;
		return 0;
	}
	RETURN_IF_NOT_READY();

	rcu_read_lock();
	l = update_stats_rcu(size, RETURN_ADDRESS(0));
	p = h = real_malloc(asize);
	if (p) {
		alloc_insert_rcu(l, h, size, h);
		p = hdr2ptr(h);
	}
	rcu_read_unlock();

	if (ptr) {
		struct alloc_hdr *old = ptr2hdr(ptr);
		memcpy(p, ptr, old->size < size ? old->size : size);
		free(ptr);
	}
	return p;
}

struct dump_arg {
	FILE *fp;
	size_t min;
};

static void *dump_to_file(void *x)
{
	struct dump_arg *a = x;
	struct cds_lfht_iter iter;
	struct src_loc *l;
	struct cds_lfht *t;

	++locating;
	rcu_read_lock();
	t = rcu_dereference(totals);
	if (!t)
		goto out_unlock;
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
out_unlock:
	rcu_read_unlock();
	--locating;
	return 0;
}

/*
 * call-seq:
 *
 *	Mwrap.dump([[io] [, min]] -> nil
 *
 * Dumps the current totals to +io+ which must be an IO object
 * (StringIO and similar are not supported).  Total sizes smaller
 * than or equal to +min+ are skipped.
 *
 * The output is space-delimited by 3 columns:
 *
 * total_size      call_count      location
 */
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
	io = rb_io_get_io(io);
	io = rb_io_get_write_io(io);
	GetOpenFile(io, fptr);
	a.fp = rb_io_stdio_file(fptr);

	rb_thread_call_without_gvl(dump_to_file, &a, 0, 0);
	RB_GC_GUARD(io);
	return Qnil;
}

static void
free_src_loc(struct rcu_head *head)
{
	struct src_loc *l = caa_container_of(head, struct src_loc, rcu_head);
	real_free(l);
}

static void *totals_clear(void *ign)
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
	return 0;
}

/*
 * call-seq:
 *
 *	Mwrap.clear -> nil
 *
 * Atomically replaces the totals table and destroys the old one.
 * This resets all statistics. It is more expensive than `Mwrap.reset'
 * as new allocations will need to be made to repopulate the new table.
 */
static VALUE mwrap_clear(VALUE mod)
{
	rb_thread_call_without_gvl(totals_clear, 0, 0, 0);
	return Qnil;
}

static void *totals_reset(void *ign)
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
	return 0;
}

/*
 * call-seq:
 *
 *	Mwrap.reset -> nil
 *
 * Resets the the total tables by zero-ing all counters.
 * This resets all statistics and is less costly than `Mwrap.clear'
 * but is not an atomic operation.
 */
static VALUE mwrap_reset(VALUE mod)
{
	rb_thread_call_without_gvl(totals_reset, 0, 0, 0);
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

		/* deduplicate and try to free up some memory */
		v[0] = rb_funcall(v[1], id_uminus, 0);
		if (!OBJ_FROZEN_RAW(v[1]))
			rb_str_resize(v[1], 0);

		v[1] = SIZET2NUM(l->total);
		v[2] = SIZET2NUM(l->calls);

		rb_yield_values2(3, v);
		assert(rcu_read_ongoing());
	}
	return Qnil;
}

/*
 * call-seq:
 *
 * 	Mwrap.each([min]) { |location,total_bytes,call_count| ... }
 *
 * Yields each entry of the of the table to a caller-supplied block.
 * +min+ may be specified to filter out lines with +total_bytes+
 * equal-to-or-smaller-than the supplied minimum.
 */
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

/*
 * Document-module: Mwrap
 *
 *   require 'mwrap'
 *
 * Mwrap has a dual function as both a Ruby C extension and LD_PRELOAD
 * wrapper.  As a Ruby C extension, it exposes a limited Ruby API.
 * To be effective at gathering status, mwrap must be loaded as a
 * LD_PRELOAD (using the mwrap(1) executable makes it easy)
 *
 * ENVIRONMENT
 *
 * The "MWRAP" environment variable contains a comma-delimited list
 * of key:value options for automatically dumping at program exit.
 *
 * * dump_fd: a writable FD to dump to
 * * dump_path: a path to dump to, the file is opened in O_APPEND mode
 * * dump_min: the minimum allocation size (total) to dump
 *
 * If both `dump_fd' and `dump_path' are specified, dump_path takes
 * precedence.
 */
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
