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
extern VALUE __attribute__((weak)) rb_cObject;
extern VALUE __attribute__((weak)) rb_eTypeError;
extern VALUE __attribute__((weak)) rb_yield(VALUE);

static size_t total_bytes_inc, total_bytes_dec;

/* true for glibc/dlmalloc/ptmalloc, not sure about jemalloc */
#define ASSUMED_MALLOC_ALIGNMENT (sizeof(void *) * 2)

/* match values in Ruby gc.c */
#define HEAP_PAGE_ALIGN_LOG 14
enum {
	HEAP_PAGE_ALIGN = (1UL << HEAP_PAGE_ALIGN_LOG),
	REQUIRED_SIZE_BY_MALLOC = (sizeof(size_t) * 5),
	HEAP_PAGE_SIZE = (HEAP_PAGE_ALIGN - REQUIRED_SIZE_BY_MALLOC)
};

#define IS_HEAP_PAGE_BODY ((struct src_loc *)-1)

int __attribute__((weak)) ruby_thread_has_gvl_p(void)
{
	return 0;
}

#ifdef __FreeBSD__
void *__malloc(size_t);
void __free(void *);
#  define real_malloc __malloc
#  define real_free __free
#else
static void *(*real_malloc)(size_t);
static void (*real_free)(void *);
static int resolving_malloc;
#endif /* !FreeBSD */

/*
 * we need to fake an OOM condition while dlsym is running,
 * as that calls calloc under glibc, but we don't have the
 * symbol for the jemalloc calloc, yet
 */
#  define RETURN_IF_NOT_READY() do { \
	if (!real_malloc) { \
		errno = ENOMEM; \
		return NULL; \
	} \
} while (0)

static __thread size_t locating;
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
	++locating;

#ifdef __FreeBSD__
	/*
	 * PTHREAD_MUTEX_INITIALIZER on FreeBSD means lazy initialization,
	 * which happens at pthread_mutex_lock, and that calls calloc
	 */
	{
		size_t i;

		for (i = 0; i < MUTEX_NR; i++) {
			err = pthread_mutex_init(&mutexes[i].mtx, 0);
			if (err) {
				fprintf(stderr, "error: %s\n", strerror(err));
				_exit(1);
			}
		}
		/* initialize mutexes used by urcu-bp */
		rcu_read_lock();
		rcu_read_unlock();
	}
#else /* !FreeBSD (tested on GNU/Linux) */
	if (!real_malloc) {
		resolving_malloc = 1;
		real_malloc = dlsym(RTLD_NEXT, "malloc");
	}
	real_free = dlsym(RTLD_NEXT, "free");
	if (!real_malloc || !real_free) {
		fprintf(stderr, "missing malloc/aligned_alloc/free\n"
			"\t%p %p\n", real_malloc, real_free);
		_exit(1);
	}
#endif /* !FreeBSD */
	totals = lfht_new();
	if (!totals)
		fprintf(stderr, "failed to allocate totals table\n");

	err = pthread_atfork(call_rcu_before_fork,
				call_rcu_after_fork_parent,
				call_rcu_after_fork_child);
	if (err)
		fprintf(stderr, "pthread_atfork failed: %s\n", strerror(err));
	page_size = sysconf(_SC_PAGESIZE);
	--locating;
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

struct acc {
	size_t nr;
	size_t min;
	size_t max;
	double m2;
	double mean;
};

#define ACC_INIT(name) { .nr=0, .min=SIZE_MAX, .max=0, .m2=0, .mean=0 }

/* for tracking 16K-aligned heap page bodies (protected by GVL) */
struct {
	pthread_mutex_t lock;
	struct cds_list_head bodies;
	struct cds_list_head freed;

	struct acc alive;
	struct acc reborn;
} hpb_stats = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.bodies = CDS_LIST_HEAD_INIT(hpb_stats.bodies),
	.freed = CDS_LIST_HEAD_INIT(hpb_stats.freed),
	.alive = ACC_INIT(hpb_stats.alive),
	.reborn = ACC_INIT(hpb_stats.reborn)
};

/* allocated via real_malloc/real_free */
struct src_loc {
	pthread_mutex_t *mtx;
	size_t total;
	size_t allocations;
	size_t frees;
	size_t age_total; /* (age_total / frees) => mean age at free */
	size_t max_lifespan;
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
		struct {
			size_t at; /* rb_gc_count() */
		} hpb_freed;
	} as;
	void *real; /* what to call real_free on */
	size_t size;
};

static char kbuf[PATH_MAX + INT2STR_MAX + sizeof(struct alloc_hdr) + 2];

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

/* note: not atomic */
static void
acc_add(struct acc *acc, size_t val)
{
	double delta = val - acc->mean;
	size_t nr = ++acc->nr;

	/* 32-bit overflow, ignore accuracy, just don't divide-by-zero */
	if (nr)
		acc->mean += delta / nr;

	acc->m2 += delta * (val - acc->mean);
	if (val < acc->min)
		acc->min = val;
	if (val > acc->max)
		acc->max = val;
}

static VALUE
acc_max(const struct acc *acc)
{
	return acc->max ? SIZET2NUM(acc->max) : DBL2NUM(HUGE_VAL);
}

static VALUE
acc_min(const struct acc *acc)
{
	return acc->min == SIZE_MAX ? DBL2NUM(HUGE_VAL) : SIZET2NUM(acc->min);
}

static VALUE
acc_mean(const struct acc *acc)
{
	return DBL2NUM(acc->nr ? acc->mean : HUGE_VAL);
}

static double
acc_stddev_dbl(const struct acc *acc)
{
	if (acc->nr > 1) {
		double variance = acc->m2 / (acc->nr - 1);
		return sqrt(variance);
	}
	return 0.0;
}

static VALUE
acc_stddev(const struct acc *acc)
{
	return DBL2NUM(acc_stddev_dbl(acc));
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
		uatomic_add(&l->allocations, 1);
	} else {
		size_t n = loc_size(k);
		l = real_malloc(sizeof(*l) + n);
		if (!l) goto out_unlock;
		memcpy(l, k, sizeof(*l) + n);
		l->mtx = mutex_assign();
		l->age_total = 0;
		l->max_lifespan = 0;
		l->frees = 0;
		l->allocations = 1;
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

static void update_stats_rcu_unlock(const struct src_loc *l)
{
	if (caa_likely(l)) rcu_read_unlock();
}

static struct src_loc *update_stats_rcu_lock(size_t size, uintptr_t caller)
{
	struct src_loc *k, *ret = 0;
	static const size_t xlen = sizeof(caller);
	char *dst;

	if (caa_unlikely(!totals)) return 0;
	if (locating++) goto out; /* do not recurse into another *alloc */

	uatomic_add(&total_bytes_inc, size);

	rcu_read_lock();
	if (has_ec_p()) {
		int line;
		const char *ptr = rb_source_location_cstr(&line);
		size_t len;
		size_t int_size = INT2STR_MAX;

		generation = rb_gc_count();

		if (!ptr) goto unknown;

		/* avoid vsnprintf or anything which could call malloc here: */
		len = strlen(ptr);
		k = (void *)kbuf;
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
		struct src_loc *l = h->as.live.loc;

		if (!real_free) return; /* oh well, leak a little */
		if (l && l != IS_HEAP_PAGE_BODY) {
			size_t age = generation - h->as.live.gen;

			uatomic_add(&total_bytes_dec, h->size);
			uatomic_set(&h->size, 0);
			uatomic_add(&l->frees, 1);
			uatomic_add(&l->age_total, age);

			mutex_lock(l->mtx);
			cds_list_del_rcu(&h->anode);
			if (age > l->max_lifespan)
				l->max_lifespan = age;
			mutex_unlock(l->mtx);

			call_rcu(&h->as.dead, free_hdr_rcu);
		} else if (l == IS_HEAP_PAGE_BODY) {
			size_t gen = generation;
			size_t age = gen - h->as.live.gen;

			h->as.hpb_freed.at = gen;

			mutex_lock(&hpb_stats.lock);
			acc_add(&hpb_stats.alive, age);

			/* hpb_stats.bodies => hpb_stats.freed */
			cds_list_move(&h->anode, &hpb_stats.freed);

			mutex_unlock(&hpb_stats.lock);
		} else {
			real_free(h->real);
		}
	}
}

static void
alloc_insert_rcu(struct src_loc *l, struct alloc_hdr *h, size_t size, void *real)
{
	/* we need src_loc to remain alive for the duration of this call */
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

static bool ptr_is_aligned(const void *ptr, size_t alignment)
{
	return ((uintptr_t)ptr & (alignment - 1)) == 0;
}

static void *ptr_align(void *ptr, size_t alignment)
{
	return (void *)(((uintptr_t)ptr + (alignment - 1)) & ~(alignment - 1));
}

static bool is_power_of_two(size_t n) { return (n & (n - 1)) == 0; }

static int
internal_memalign(void **pp, size_t alignment, size_t size, uintptr_t caller)
{
	struct src_loc *l;
	struct alloc_hdr *h;
	void *real;
	size_t asize;
	size_t d = alignment / sizeof(void*);
	size_t r = alignment % sizeof(void*);

	if (!real_malloc) return ENOMEM;

	if (r != 0 || d == 0 || !is_power_of_two(d))
		return EINVAL;

	if (alignment <= ASSUMED_MALLOC_ALIGNMENT) {
		void *p = malloc(size);
		if (!p) return ENOMEM;
		*pp = p;
		return 0;
	}
	for (; alignment < sizeof(struct alloc_hdr); alignment *= 2)
		; /* double alignment until >= sizeof(struct alloc_hdr) */
	if (__builtin_add_overflow(size, alignment, &asize) ||
	    __builtin_add_overflow(asize, sizeof(struct alloc_hdr), &asize))
		return ENOMEM;


	if (alignment == HEAP_PAGE_ALIGN && size == HEAP_PAGE_SIZE) {
		if (has_ec_p()) generation = rb_gc_count();
		l = IS_HEAP_PAGE_BODY;
	} else {
		l = update_stats_rcu_lock(size, caller);
	}

	if (l == IS_HEAP_PAGE_BODY) {
		void *p;
		size_t gen = generation;

		mutex_lock(&hpb_stats.lock);

		/* reuse existing entry */
		if (!cds_list_empty(&hpb_stats.freed)) {
			size_t deathspan;

			h = cds_list_first_entry(&hpb_stats.freed,
						 struct alloc_hdr, anode);
			/* hpb_stats.freed => hpb_stats.bodies */
			cds_list_move(&h->anode, &hpb_stats.bodies);
			assert(h->size == size);
			assert(h->real);
			real = h->real;
			p = hdr2ptr(h);
			assert(ptr_is_aligned(p, alignment));

			deathspan = gen - h->as.hpb_freed.at;
			acc_add(&hpb_stats.reborn, deathspan);
		}
		else {
			real = real_malloc(asize);
			if (!real) return ENOMEM;

			p = hdr2ptr(real);
			if (!ptr_is_aligned(p, alignment))
				p = ptr_align(p, alignment);
			h = ptr2hdr(p);
			h->size = size;
			h->real = real;
			cds_list_add(&h->anode, &hpb_stats.bodies);
		}
		mutex_unlock(&hpb_stats.lock);
		h->as.live.loc = l;
		h->as.live.gen = gen;
		*pp = p;
	}
	else {
		real = real_malloc(asize);
		if (real) {
			void *p = hdr2ptr(real);
			if (!ptr_is_aligned(p, alignment))
				p = ptr_align(p, alignment);
			h = ptr2hdr(p);
			alloc_insert_rcu(l, h, size, real);
			update_stats_rcu_unlock(l);
			*pp = p;
		}
	}

	return real ? 0 : ENOMEM;
}

static void *
memalign_result(int err, void *p)
{
	if (caa_unlikely(err)) {
		errno = err;
		return 0;
	}
	return p;
}

void *memalign(size_t alignment, size_t size)
{
	void *p;
	int err = internal_memalign(&p, alignment, size, RETURN_ADDRESS(0));
	return memalign_result(err, p);
}

int posix_memalign(void **p, size_t alignment, size_t size)
{
	return internal_memalign(p, alignment, size, RETURN_ADDRESS(0));
}

void *aligned_alloc(size_t, size_t) __attribute__((alias("memalign")));
void cfree(void *) __attribute__((alias("free")));

void *valloc(size_t size)
{
	void *p;
	int err = internal_memalign(&p, page_size, size, RETURN_ADDRESS(0));
	return memalign_result(err, p);
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
	void *p;
	int err;

	if (add_overflow_p(size, alignment)) {
		errno = ENOMEM;
		return 0;
	}
	size = size_align(size, alignment);
	err = internal_memalign(&p, alignment, size, RETURN_ADDRESS(0));
	return memalign_result(err, p);
}

void *malloc(size_t size)
{
	struct src_loc *l;
	struct alloc_hdr *h;
	size_t asize;
	void *p;

	if (__builtin_add_overflow(size, sizeof(struct alloc_hdr), &asize))
		goto enomem;

	/*
	 * Needed for C++ global declarations using "new",
	 * which happens before our constructor
	 */
#ifndef __FreeBSD__
	if (!real_malloc) {
		if (resolving_malloc) goto enomem;
		resolving_malloc = 1;
		real_malloc = dlsym(RTLD_NEXT, "malloc");
	}
#endif
	l = update_stats_rcu_lock(size, RETURN_ADDRESS(0));
	p = h = real_malloc(asize);
	if (h) {
		alloc_insert_rcu(l, h, size, h);
		p = hdr2ptr(h);
	}
	update_stats_rcu_unlock(l);
	if (caa_unlikely(!p)) errno = ENOMEM;
	return p;
enomem:
	errno = ENOMEM;
	return 0;
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
	l = update_stats_rcu_lock(size, RETURN_ADDRESS(0));
	p = h = real_malloc(asize);
	if (p) {
		alloc_insert_rcu(l, h, size, h);
		p = hdr2ptr(h);
		memset(p, 0, size);
	}
	update_stats_rcu_unlock(l);
	if (caa_unlikely(!p)) errno = ENOMEM;
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

	l = update_stats_rcu_lock(size, RETURN_ADDRESS(0));
	p = h = real_malloc(asize);
	if (p) {
		alloc_insert_rcu(l, h, size, h);
		p = hdr2ptr(h);
	}
	update_stats_rcu_unlock(l);

	if (ptr && p) {
		struct alloc_hdr *old = ptr2hdr(ptr);
		memcpy(p, ptr, old->size < size ? old->size : size);
		free(ptr);
	}
	if (caa_unlikely(!p)) errno = ENOMEM;
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
			l->total, l->allocations, (const char *)p);
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

/* The whole operation is not remotely atomic... */
static void *totals_reset(void *ign)
{
	struct cds_lfht *t;
	struct cds_lfht_iter iter;
	struct src_loc *l;

	uatomic_set(&total_bytes_inc, 0);
	uatomic_set(&total_bytes_dec, 0);

	rcu_read_lock();
	t = rcu_dereference(totals);
	cds_lfht_for_each_entry(t, &iter, l, hnode) {
		uatomic_set(&l->total, 0);
		uatomic_set(&l->allocations, 0);
		uatomic_set(&l->frees, 0);
		uatomic_set(&l->age_total, 0);
		uatomic_set(&l->max_lifespan, 0);
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
 * This resets all statistics.  This is not an atomic operation
 * as other threads (outside of GVL) may increment counters.
 */
static VALUE mwrap_reset(VALUE mod)
{
	rb_thread_call_without_gvl(totals_reset, 0, 0, 0);
	return Qnil;
}

/* :nodoc: */
static VALUE mwrap_clear(VALUE mod)
{
	return mwrap_reset(mod);
}

static VALUE rcu_unlock_ensure(VALUE ignored)
{
	rcu_read_unlock();
	--locating;
	return Qfalse;
}

static VALUE location_string(struct src_loc *l)
{
	VALUE ret, tmp;

	if (loc_is_addr(l)) {
		char **s = backtrace_symbols((void *)l->k, 1);
		tmp = rb_str_new_cstr(s[0]);
		free(s);
	}
	else {
		tmp = rb_str_new(l->k, l->capa - 1);
	}

	/* deduplicate and try to free up some memory */
	ret = rb_funcall(tmp, id_uminus, 0);
	if (!OBJ_FROZEN_RAW(tmp))
		rb_str_resize(tmp, 0);

	return ret;
}

static VALUE dump_each_rcu(VALUE x)
{
	struct dump_arg *a = (struct dump_arg *)x;
	struct cds_lfht *t;
	struct cds_lfht_iter iter;
	struct src_loc *l;

	t = rcu_dereference(totals);
	cds_lfht_for_each_entry(t, &iter, l, hnode) {
		VALUE v[6];
		if (l->total <= a->min) continue;

		v[0] = location_string(l);
		v[1] = SIZET2NUM(l->total);
		v[2] = SIZET2NUM(l->allocations);
		v[3] = SIZET2NUM(l->frees);
		v[4] = SIZET2NUM(l->age_total);
		v[5] = SIZET2NUM(l->max_lifespan);

		rb_yield_values2(6, v);
		assert(rcu_read_ongoing());
	}
	return Qnil;
}

/*
 * call-seq:
 *
 *	Mwrap.each([min]) do |location,total,allocations,frees,age_total,max_lifespan|
 *	  ...
 *	end
 *
 * Yields each entry of the of the table to a caller-supplied block.
 * +min+ may be specified to filter out lines with +total+ bytes
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

	return rb_ensure(dump_each_rcu, (VALUE)&a, rcu_unlock_ensure, 0);
}

static size_t
src_loc_memsize(const void *p)
{
	return sizeof(struct src_loc);
}

static const rb_data_type_t src_loc_type = {
	"source_location",
	/* no marking, no freeing */
	{ 0, 0, src_loc_memsize, /* reserved */ },
	/* parent, data, [ flags ] */
};

static VALUE cSrcLoc;

static int
extract_addr(const char *str, size_t len, void **p)
{
	const char *c;
#if defined(__GLIBC__)
	return ((c = memrchr(str, '[', len)) && sscanf(c, "[%p]", p));
#else /* tested FreeBSD */
	return ((c = strstr(str, "0x")) && sscanf(c, "%p", p));
#endif
}

/*
 * call-seq:
 *	Mwrap[location] -> Mwrap::SourceLocation
 *
 * Returns the associated Mwrap::SourceLocation given the +location+
 * String.  +location+ is either a Ruby source location path:line
 * (e.g. "/path/to/foo.rb:5") or a hexadecimal memory address with
 * square-braces part yielded by Mwrap.dump (e.g. "[0xdeadbeef]")
 */
static VALUE mwrap_aref(VALUE mod, VALUE loc)
{
	const char *str = StringValueCStr(loc);
	int len = RSTRING_LENINT(loc);
	struct src_loc *k = 0;
	uintptr_t p;
	struct cds_lfht_iter iter;
	struct cds_lfht_node *cur;
	struct cds_lfht *t;
	struct src_loc *l;
	VALUE val = Qnil;

	if (extract_addr(str, len, (void **)&p)) {
		k = (void *)kbuf;
		memcpy(k->k, &p, sizeof(p));
		k->capa = 0;
		k->hval = jhash(k->k, sizeof(p), 0xdeadbeef);
	} else {
		k = (void *)kbuf;
		memcpy(k->k, str, len + 1);
		k->capa = len + 1;
		k->hval = jhash(k->k, k->capa, 0xdeadbeef);
	}

	if (!k) return val;

	rcu_read_lock();
	t = rcu_dereference(totals);
	if (!t) goto out_unlock;

	cds_lfht_lookup(t, k->hval, loc_eq, k, &iter);
	cur = cds_lfht_iter_get_node(&iter);
	if (cur) {
		l = caa_container_of(cur, struct src_loc, hnode);
		val = TypedData_Wrap_Struct(cSrcLoc, &src_loc_type, l);
	}
out_unlock:
	rcu_read_unlock();
	return val;
}

static VALUE src_loc_each_i(VALUE p)
{
	struct alloc_hdr *h;
	struct src_loc *l = (struct src_loc *)p;

	cds_list_for_each_entry_rcu(h, &l->allocs, anode) {
		size_t gen = uatomic_read(&h->as.live.gen);
		size_t size = uatomic_read(&h->size);

		if (size) {
			VALUE v[2];
			v[0] = SIZET2NUM(size);
			v[1] = SIZET2NUM(gen);

			rb_yield_values2(2, v);
		}
	}

	return Qfalse;
}

static struct src_loc *src_loc_get(VALUE self)
{
	struct src_loc *l;
	TypedData_Get_Struct(self, struct src_loc, &src_loc_type, l);
	assert(l);
	return l;
}

/*
 * call-seq:
 *	loc = Mwrap[location]
 *	loc.each { |size,generation| ... }
 *
 * Iterates through live allocations for a given Mwrap::SourceLocation,
 * yielding the +size+ (in bytes) and +generation+ of each allocation.
 * The +generation+ is the value of the GC.count method at the time
 * the allocation was made.
 *
 * This functionality is only available in mwrap 2.0.0+
 */
static VALUE src_loc_each(VALUE self)
{
	struct src_loc *l = src_loc_get(self);

	assert(locating == 0 && "forgot to clear locating");
	++locating;
	rcu_read_lock();
	rb_ensure(src_loc_each_i, (VALUE)l, rcu_unlock_ensure, 0);
	return self;
}

/*
 * The the mean lifespan (in GC generations) of allocations made from this
 * location.  This does not account for live allocations.
 */
static VALUE src_loc_mean_lifespan(VALUE self)
{
	struct src_loc *l = src_loc_get(self);
	size_t tot, frees;

	frees = uatomic_read(&l->frees);
	tot = uatomic_read(&l->age_total);
	return DBL2NUM(frees ? ((double)tot/(double)frees) : HUGE_VAL);
}

/* The number of frees made from this location */
static VALUE src_loc_frees(VALUE self)
{
	return SIZET2NUM(uatomic_read(&src_loc_get(self)->frees));
}

/* The number of allocations made from this location */
static VALUE src_loc_allocations(VALUE self)
{
	return SIZET2NUM(uatomic_read(&src_loc_get(self)->allocations));
}

/* The total number of bytes allocated from this location */
static VALUE src_loc_total(VALUE self)
{
	return SIZET2NUM(uatomic_read(&src_loc_get(self)->total));
}

/*
 * The maximum age (in GC generations) of an allocation before it was freed.
 * This does not account for live allocations.
 */
static VALUE src_loc_max_lifespan(VALUE self)
{
	return SIZET2NUM(uatomic_read(&src_loc_get(self)->max_lifespan));
}

/*
 * Returns a frozen String location of the given SourceLocation object.
 */
static VALUE src_loc_name(VALUE self)
{
	struct src_loc *l = src_loc_get(self);
	VALUE ret;

	++locating;
	ret = location_string(l);
	--locating;
	return ret;
}

static VALUE reset_locating(VALUE ign) { --locating; return Qfalse; }

/*
 * call-seq:
 *
 *	Mwrap.quiet do |depth|
 *	  # expensive sort/calculate/emitting results of Mwrap.each
 *	  # affecting statistics of the rest of the app
 *	end
 *
 * Stops allocation tracking inside the block.  This is useful for
 * monitoring code which calls other Mwrap (or ObjectSpace/GC)
 * functions which unavoidably allocate memory.
 *
 * This feature was added in mwrap 2.0.0+
 */
static VALUE mwrap_quiet(VALUE mod)
{
	size_t cur = ++locating;
	return rb_ensure(rb_yield, SIZET2NUM(cur), reset_locating, 0);
}

static VALUE total_inc(VALUE mod)
{
	return SIZET2NUM(total_bytes_inc);
}

static VALUE total_dec(VALUE mod)
{
	return SIZET2NUM(total_bytes_dec);
}

static VALUE hpb_each_yield(VALUE ignore)
{
	struct alloc_hdr *h, *next;

	cds_list_for_each_entry_safe(h, next, &hpb_stats.bodies, anode) {
		VALUE v[2]; /* [ generation, address ] */
		void *addr = hdr2ptr(h);
		assert(ptr_is_aligned(addr, HEAP_PAGE_ALIGN));
		v[0] = LONG2NUM((long)addr);
		v[1] = SIZET2NUM(h->as.live.gen);
		rb_yield_values2(2, v);
	}
	return Qnil;
}

/*
 * call-seq:
 *
 *     Mwrap::HeapPageBody.each { |gen, addr| } -> Integer
 *
 * Yields the generation (GC.count) the heap page body was created
 * and address of the heap page body as an Integer.  Returns the
 * number of allocated pages as an Integer.  This return value should
 * match the result of GC.stat(:heap_allocated_pages)
 */
static VALUE hpb_each(VALUE mod)
{
	++locating;
	return rb_ensure(hpb_each_yield, Qfalse, reset_locating, 0);
}

/*
 * call-seq:
 *
 *	Mwrap::HeapPageBody.stat -> Hash
 *	Mwrap::HeapPageBody.stat(hash) -> hash
 *
 * The maximum lifespan of a heap page body in the Ruby VM.
 * This may be Infinity if no heap page bodies were ever freed.
 */
static VALUE hpb_stat(int argc, VALUE *argv, VALUE hpb)
{
	VALUE h;

	rb_scan_args(argc, argv, "01", &h);
	if (NIL_P(h))
		h = rb_hash_new();
	else if (!RB_TYPE_P(h, T_HASH))
		rb_raise(rb_eTypeError, "not a hash %+"PRIsVALUE, h);

	++locating;
#define S(x) ID2SYM(rb_intern(#x))
	rb_hash_aset(h, S(lifespan_max), acc_max(&hpb_stats.alive));
	rb_hash_aset(h, S(lifespan_min), acc_min(&hpb_stats.alive));
	rb_hash_aset(h, S(lifespan_mean), acc_mean(&hpb_stats.alive));
	rb_hash_aset(h, S(lifespan_stddev), acc_stddev(&hpb_stats.alive));
	rb_hash_aset(h, S(deathspan_max), acc_max(&hpb_stats.reborn));
	rb_hash_aset(h, S(deathspan_min), acc_min(&hpb_stats.reborn));
	rb_hash_aset(h, S(deathspan_mean), acc_mean(&hpb_stats.reborn));
	rb_hash_aset(h, S(deathspan_stddev), acc_stddev(&hpb_stats.reborn));
	rb_hash_aset(h, S(resurrects), SIZET2NUM(hpb_stats.reborn.nr));
#undef S
	--locating;

	return h;
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
 * * dump_heap: mask of heap_page_body statistics to dump
 *
 * If both `dump_fd' and `dump_path' are specified, dump_path takes
 * precedence.
 *
 * dump_heap bitmask
 * * 0x01 - summary stats (same info as HeapPageBody.stat)
 * * 0x02 - all live heaps (similar to HeapPageBody.each)
 * * 0x04 - skip non-heap_page_body-related output
 */
void Init_mwrap(void)
{
	VALUE mod, hpb;

	++locating;
	mod = rb_define_module("Mwrap");
	id_uminus = rb_intern("-@");

	/*
	 * Represents a location in source code or library
	 * address which calls a memory allocation.  It is
	 * updated automatically as allocations are made, so
	 * there is no need to reload or reread it from Mwrap#[].
	 * This class is only available since mwrap 2.0.0+.
	 */
	cSrcLoc = rb_define_class_under(mod, "SourceLocation", rb_cObject);
	rb_define_singleton_method(mod, "dump", mwrap_dump, -1);
	rb_define_singleton_method(mod, "reset", mwrap_reset, 0);
	rb_define_singleton_method(mod, "clear", mwrap_clear, 0);
	rb_define_singleton_method(mod, "each", mwrap_each, -1);
	rb_define_singleton_method(mod, "[]", mwrap_aref, 1);
	rb_define_singleton_method(mod, "quiet", mwrap_quiet, 0);
	rb_define_singleton_method(mod, "total_bytes_allocated", total_inc, 0);
	rb_define_singleton_method(mod, "total_bytes_freed", total_dec, 0);


	rb_define_method(cSrcLoc, "each", src_loc_each, 0);
	rb_define_method(cSrcLoc, "frees", src_loc_frees, 0);
	rb_define_method(cSrcLoc, "allocations", src_loc_allocations, 0);
	rb_define_method(cSrcLoc, "total", src_loc_total, 0);
	rb_define_method(cSrcLoc, "mean_lifespan", src_loc_mean_lifespan, 0);
	rb_define_method(cSrcLoc, "max_lifespan", src_loc_max_lifespan, 0);
	rb_define_method(cSrcLoc, "name", src_loc_name, 0);

	/*
	 * Information about "struct heap_page_body" allocations from
	 * Ruby gc.c.  This can be useful for tracking fragmentation
	 * from posix_memalign(3) use in mainline Ruby:
	 *
	 *   https://sourceware.org/bugzilla/show_bug.cgi?id=14581
	 */
	hpb = rb_define_class_under(mod, "HeapPageBody", rb_cObject);
	rb_define_singleton_method(hpb, "stat", hpb_stat, -1);
	rb_define_singleton_method(hpb, "each", hpb_each, 0);

	--locating;
}

enum {
	DUMP_HPB_STATS = 0x1,
	DUMP_HPB_EACH = 0x2,
	DUMP_HPB_EXCL = 0x4,
};

static void dump_hpb(FILE *fp, unsigned flags)
{
	if (flags & DUMP_HPB_STATS) {
		fprintf(fp,
			"lifespan_max: %zu\n"
			"lifespan_min:%s%zu\n"
			"lifespan_mean: %0.3f\n"
			"lifespan_stddev: %0.3f\n"
			"deathspan_max: %zu\n"
			"deathspan_min:%s%zu\n"
			"deathspan_mean: %0.3f\n"
			"deathspan_stddev: %0.3f\n"
			"gc_count: %zu\n",
			hpb_stats.alive.max,
			hpb_stats.alive.min == SIZE_MAX ? " -" : " ",
			hpb_stats.alive.min,
			hpb_stats.alive.mean,
			acc_stddev_dbl(&hpb_stats.alive),
			hpb_stats.reborn.max,
			hpb_stats.reborn.min == SIZE_MAX ? " -" : " ",
			hpb_stats.reborn.min,
			hpb_stats.reborn.mean,
			acc_stddev_dbl(&hpb_stats.reborn),
			/* n.b.: unsafe to call rb_gc_count() in destructor */
			generation);
	}
	if (flags & DUMP_HPB_EACH) {
		struct alloc_hdr *h;

		cds_list_for_each_entry(h, &hpb_stats.bodies, anode) {
			void *addr = hdr2ptr(h);

			fprintf(fp, "%p\t%zu\n", addr, h->as.live.gen);
		}
	}
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
	struct dump_arg a = { .min = 0 };
	size_t i;
	int dump_fd;
	unsigned dump_heap = 0;
	char *dump_path;
	char *s;

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

	if ((s = strstr(opt, "dump_min:")))
		sscanf(s, "dump_min:%zu", &a.min);

	if ((s = strstr(opt, "dump_heap:")))
		sscanf(s, "dump_heap:%u", &dump_heap);

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
	if ((dump_heap & DUMP_HPB_EXCL) == 0)
		dump_to_file(&a);
	dump_hpb(a.fp, dump_heap);
out:
	--locating;
}
