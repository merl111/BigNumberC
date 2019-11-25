#ifndef HEADER_BN_H
#define HEADER_BN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <limits.h>
#include <ctype.h>


#ifdef _LP64
#undef	BN_LLONG
#define BN_ULONG	unsigned long
#define BN_LONG		long
#define BN_BITS		128
#define BN_BYTES	8
#define BN_BITS2	64
#define BN_BITS4	32
#define BN_MASK2	(0xffffffffffffffffL)
#define BN_MASK2l	(0xffffffffL)
#define BN_MASK2h	(0xffffffff00000000L)
#define BN_MASK2h1	(0xffffffff80000000L)
#define BN_TBIT		(0x8000000000000000L)
#define BN_DEC_CONV	(10000000000000000000UL)
#define BN_DEC_FMT1	"%lu"
#define BN_DEC_FMT2	"%019lu"
#define BN_DEC_NUM	19
#define BN_HEX_FMT1	"%lX"
#define BN_HEX_FMT2	"%016lX"
#else
#define BN_ULLONG	unsigned long long
#define	BN_LLONG
#define BN_ULONG	unsigned int
#define BN_LONG		int
#define BN_BITS		64
#define BN_BYTES	4
#define BN_BITS2	32
#define BN_BITS4	16
#define BN_MASK		(0xffffffffffffffffLL)
#define BN_MASK2	(0xffffffffL)
#define BN_MASK2l	(0xffff)
#define BN_MASK2h1	(0xffff8000L)
#define BN_MASK2h	(0xffff0000L)
#define BN_TBIT		(0x80000000L)
#define BN_DEC_CONV	(1000000000L)
#define BN_DEC_FMT1	"%u"
#define BN_DEC_FMT2	"%09u"
#define BN_DEC_NUM	9
#define BN_HEX_FMT1	"%X"
#define BN_HEX_FMT2	"%08X"
#endif

#define BN_FLG_MALLOCED		0x01
#define BN_FLG_STATIC_DATA	0x02
#define BN_FLG_CONSTTIME	0x04 /* avoid leaking exponent information through timing,
                                      * BN_mod_exp_mont() will call BN_mod_exp_mont_consttime,
                                      * BN_div() will call BN_div_no_branch,
                                      * BN_mod_inverse() will call BN_mod_inverse_no_branch.
                                      */
/** BN_is_negative returns 1 if the BIGNUM is negative
 * \param  a  pointer to the BIGNUM object
 * \return 1 if a < 0 and 0 otherwise
 */
#define BN_is_negative(a) ((a)->neg != 0)


struct bignum_st {
	BN_ULONG *d;	/* Pointer to an array of 'BN_BITS2' bit chunks. */
	int top;	/* Index of last used d +1. */
	/* The next are internal book keeping for bn_expand. */
	int dmax;	/* Size of the d array. */
	int neg;	/* one if the number is negative */
	int flags;
};

typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;

/* forward declerations start */
int	BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int	BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int	BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int	BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_set_word(BIGNUM *a, BN_ULONG w);
int BN_num_bits_word(BN_ULONG l);
int BN_sub_word(BIGNUM *a, BN_ULONG w);
int BN_lshift1(BIGNUM *r, const BIGNUM *a);
int BN_rshift1(BIGNUM *r, const BIGNUM *a);
int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_rshift(BIGNUM *r, const BIGNUM *a, int n);

void freezero(void *ptr, size_t sz);
void BN_free(BIGNUM *a);

BIGNUM *BN_new(void);
void BN_init(BIGNUM *a);
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
BIGNUM *bn_expand2(BIGNUM *b, int words);
BIGNUM *BN_dup(const BIGNUM *a);

BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w);
/* forward declerations end */

#ifdef BN_DEBUG

/* We only need assert() when debugging */
#include <assert.h>

#ifdef BN_DEBUG_RAND
#define bn_pollute(a) \
	do { \
		const BIGNUM *_bnum1 = (a); \
		if(_bnum1->top < _bnum1->dmax) { \
			unsigned char _tmp_char; \
			/* We cast away const without the compiler knowing, any \
			 * *genuinely* constant variables that aren't mutable \
			 * wouldn't be constructed with top!=dmax. */ \
			BN_ULONG *_not_const; \
			memcpy(&_not_const, &_bnum1->d, sizeof(BN_ULONG*)); \
			arc4random_buf(&_tmp_char, 1); \
			memset((unsigned char *)(_not_const + _bnum1->top), _tmp_char, \
				(_bnum1->dmax - _bnum1->top) * sizeof(BN_ULONG)); \
		} \
	} while(0)
#else
#define bn_pollute(a)
#endif

#define bn_check_top(a) \
	do { \
		const BIGNUM *_bnum2 = (a); \
		if (_bnum2 != NULL) { \
			assert((_bnum2->top == 0) || \
				(_bnum2->d[_bnum2->top - 1] != 0)); \
			bn_pollute(_bnum2); \
		} \
	} while(0)

#define bn_fix_top(a)		bn_check_top(a)

#define bn_check_size(bn, bits) bn_wcheck_size(bn, ((bits+BN_BITS2-1))/BN_BITS2)
#define bn_wcheck_size(bn, words) \
	do { \
		const BIGNUM *_bnum2 = (bn); \
		assert(words <= (_bnum2)->dmax && words >= (_bnum2)->top); \
	} while(0)

#else /* !BN_DEBUG */

#define bn_pollute(a)
#define bn_check_top(a)
#define bn_fix_top(a)		bn_correct_top(a)
#define bn_check_size(bn, bits)
#define bn_wcheck_size(bn, words)

#endif

#define bn_correct_top(a) \
        { \
        BN_ULONG *ftl; \
	int tmp_top = (a)->top; \
	if (tmp_top > 0) \
		{ \
		for (ftl= &((a)->d[tmp_top-1]); tmp_top > 0; tmp_top--) \
			if (*(ftl--)) break; \
		(a)->top = tmp_top; \
		} \
	bn_pollute(a); \
	}

#define BN_num_bytes(a)	((BN_num_bits(a)+7)/8)

/* Note that BN_abs_is_word didn't work reliably for w == 0 until 0.9.8 */
#define BN_abs_is_word(a,w) ((((a)->top == 1) && ((a)->d[0] == (BN_ULONG)(w))) || \
				(((w) == 0) && ((a)->top == 0)))
#define BN_is_zero(a)       ((a)->top == 0)
#define BN_is_one(a)        (BN_abs_is_word((a),1) && !(a)->neg)
#define BN_is_word(a,w)     (BN_abs_is_word((a),(w)) && (!(w) || !(a)->neg))
#define BN_is_odd(a)	    (((a)->top > 0) && ((a)->d[0] & 1))

#define BN_one(a)	(BN_set_word((a),1))
#define BN_zero_ex(a) \
	do { \
		BIGNUM *_tmp_bn = (a); \
		_tmp_bn->top = 0; \
		_tmp_bn->neg = 0; \
	} while(0)

#ifdef OPENSSL_NO_DEPRECATED
#define BN_zero(a)	BN_zero_ex(a)
#else
#define BN_zero(a)	(BN_set_word((a),0))
#endif

#define BN_set_flags(b,n)	((b)->flags|=(n))
#define BN_get_flags(b,n)	((b)->flags&(n))

#define bn_wexpand(a,words) (((words) <= (a)->dmax)?(a):bn_expand2((a),(words)))

/* maybe needs to be ported to ARM */
/* ASM start */
#define mul_add(r,a,word,carry) do {	\
	BN_ULONG high,low;	\
	asm ("mulq %3"			\
		: "=a"(low),"=d"(high)	\
		: "a"(word),"m"(a)	\
		: "cc");		\
	asm ("addq %2,%0; adcq %3,%1"	\
		: "+r"(carry),"+d"(high)\
		: "a"(low),"g"(0)	\
		: "cc");		\
	asm ("addq %2,%0; adcq %3,%1"	\
		: "+m"(r),"+d"(high)	\
		: "r"(carry),"g"(0)	\
		: "cc");		\
	carry=high;			\
	} while (0)

#define mul(r,a,word,carry) do {	\
	BN_ULONG high,low;	\
	asm ("mulq %3"			\
		: "=a"(low),"=d"(high)	\
		: "a"(word),"g"(a)	\
		: "cc");		\
	asm ("addq %2,%0; adcq %3,%1"	\
		: "+r"(carry),"+d"(high)\
		: "a"(low),"g"(0)	\
		: "cc");		\
	(r)=carry, carry=high;		\
	} while (0)

#define sqr(r0,r1,a)			\
	asm ("mulq %2"			\
		: "=a"(r0),"=d"(r1)	\
		: "a"(a)		\
		: "cc");

/* ASM end*/

/* internal functions start */

/* Divide h,l by d and return the result. */
/* I need to test this some more :-(  <- from libress */
BN_ULONG bn_div_words(BN_ULONG h, BN_ULONG l, BN_ULONG d)
{
	BN_ULONG dh, dl, q,ret = 0, th, tl, t;
	int i, count = 2;

	if (d == 0)
		return (BN_MASK2);

	i = BN_num_bits_word(d);
	//assert((i == BN_BITS2) || (h <= (BN_ULONG)1 << i));

	i = BN_BITS2 - i;
	if (h >= d)
		h -= d;

	if (i) {
		d <<= i;
		h = (h << i) | (l >> (BN_BITS2 - i));
		l <<= i;
	}
	dh = (d & BN_MASK2h) >> BN_BITS4;
	dl = (d & BN_MASK2l);
	for (;;) {
		if ((h >> BN_BITS4) == dh)
			q = BN_MASK2l;
		else
			q = h / dh;

		th = q * dh;
		tl = dl * q;
		for (;;) {
			t = h - th;
			if ((t & BN_MASK2h) ||
			    ((tl) <= (
			    (t << BN_BITS4) |
			    ((l & BN_MASK2h) >> BN_BITS4))))
				break;
			q--;
			th -= dh;
			tl -= dl;
		}
		t = (tl >> BN_BITS4);
		tl = (tl << BN_BITS4) & BN_MASK2h;
		th += t;

		if (l < tl)
			th++;
		l -= tl;
		if (h < th) {
			h += d;
			q--;
		}
		h -= th;

		if (--count == 0)
			break;

		ret = q << BN_BITS4;
		h = ((h << BN_BITS4) | (l >> BN_BITS4)) & BN_MASK2;
		l = (l & BN_MASK2l) << BN_BITS4;
	}
	ret |= q;
	return (ret);
}

void BN_set_negative(BIGNUM *a, int b)
{
	if (b && !BN_is_zero(a))
		a->neg = 1;
	else
		a->neg = 0;
}

BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
{
    BN_ULONG c1=0;

	if (num <= 0) return(c1);

	while (num&~3)
		{
		mul(rp[0],ap[0],w,c1);
		mul(rp[1],ap[1],w,c1);
		mul(rp[2],ap[2],w,c1);
		mul(rp[3],ap[3],w,c1);
		ap+=4; rp+=4; num-=4;
		}
	if (num)
		{
		mul(rp[0],ap[0],w,c1); if (--num == 0) return c1;
		mul(rp[1],ap[1],w,c1); if (--num == 0) return c1;
		mul(rp[2],ap[2],w,c1);
		}
	return(c1);
}


BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w)
{
#ifndef BN_LLONG
	BN_ULONG ret = 0;
#else
	BN_ULLONG ret = 0;
#endif
	int i;

	if (w == 0)
		return (BN_ULONG) - 1;

#ifndef BN_ULLONG
	/* If |w| is too long and we don't have |BN_ULLONG| then we need to fall back
	* to using |BN_div_word|. */
	if (w > ((BN_ULONG)1 << BN_BITS4)) {
		BIGNUM *tmp = BN_dup(a);
		if (tmp == NULL) {
			return (BN_ULONG)-1;
		}
		ret = BN_div_word(tmp, w);
		BN_free(tmp);
		return ret;
	}
#endif

	bn_check_top(a);
	w &= BN_MASK2;
	for (i = a->top - 1; i >= 0; i--) {
#ifndef BN_LLONG
		ret = ((ret << BN_BITS4) | ((a->d[i] >> BN_BITS4) &
		    BN_MASK2l)) % w;
		ret = ((ret << BN_BITS4) | (a->d[i] & BN_MASK2l)) % w;
#else
		ret = (BN_ULLONG)(((ret << (BN_ULLONG)BN_BITS2) |
		    a->d[i]) % (BN_ULLONG)w);
#endif
	}
	return ((BN_ULONG)ret);
}

BN_ULONG BN_div_word(BIGNUM *a, BN_ULONG w)
{
	BN_ULONG ret = 0;
	int i, j;

	bn_check_top(a);
	w &= BN_MASK2;

	if (!w)
		/* actually this an error (division by zero) */
		return (BN_ULONG) - 1;
	if (a->top == 0)
		return 0;

	/* normalize input (so bn_div_words doesn't complain) */
	j = BN_BITS2 - BN_num_bits_word(w);
	w <<= j;
	if (!BN_lshift(a, a, j))
		return (BN_ULONG) - 1;

	for (i = a->top - 1; i >= 0; i--) {
		BN_ULONG l, d;

		l = a->d[i];
		d = bn_div_words(ret, l, w);
		ret = (l - ((d*w)&BN_MASK2))&BN_MASK2;
		a->d[i] = d;
	}
	if ((a->top > 0) && (a->d[a->top - 1] == 0))
		a->top--;
	ret >>= j;
	bn_check_top(a);
	return (ret);
}

int BN_add_word(BIGNUM *a, BN_ULONG w)
{
	BN_ULONG l;
	int i;

	bn_check_top(a);
	w &= BN_MASK2;

	/* degenerate case: w is zero */
	if (!w)
		return 1;
	/* degenerate case: a is zero */
	if (BN_is_zero(a))
		return BN_set_word(a, w);
	/* handle 'a' when negative */
	if (a->neg) {
		a->neg = 0;
		i = BN_sub_word(a, w);
		if (!BN_is_zero(a))
			a->neg=!(a->neg);
		return (i);
	}
	for (i = 0; w != 0 && i < a->top; i++) {
		a->d[i] = l = (a->d[i] + w) & BN_MASK2;
		w = (w > l) ? 1 : 0;
	}
	if (w && i == a->top) {
		if (bn_wexpand(a, a->top + 1) == NULL)
			return 0;
		a->top++;
		a->d[i] = w;
	}
	bn_check_top(a);
	return (1);
}

int BN_sub_word(BIGNUM *a, BN_ULONG w)
{
	int i;

	bn_check_top(a);
	w &= BN_MASK2;

	/* degenerate case: w is zero */
	if (!w)
		return 1;
	/* degenerate case: a is zero */
	if (BN_is_zero(a)) {
		i = BN_set_word(a, w);
		if (i != 0)
			BN_set_negative(a, 1);
		return i;
	}
	/* handle 'a' when negative */
	if (a->neg) {
		a->neg = 0;
		i = BN_add_word(a, w);
		a->neg = 1;
		return (i);
	}

	if ((a->top == 1) && (a->d[0] < w)) {
		a->d[0] = w - a->d[0];
		a->neg = 1;
		return (1);
	}
	i = 0;
	for (;;) {
		if (a->d[i] >= w) {
			a->d[i] -= w;
			break;
		} else {
			a->d[i] = (a->d[i] - w) & BN_MASK2;
			i++;
			w = 1;
		}
	}
	if ((a->d[i] == 0) && (i == (a->top - 1)))
		a->top--;
	bn_check_top(a);
	return (1);
}

int BN_mul_word(BIGNUM *a, BN_ULONG w)
{
	BN_ULONG ll;

	bn_check_top(a);
	w &= BN_MASK2;
	if (a->top) {
		if (w == 0)
			BN_zero(a);
		else {
			ll = bn_mul_words(a->d, a->d, a->top, w);
			if (ll) {
				if (bn_wexpand(a, a->top + 1) == NULL)
					return (0);
				a->d[a->top++] = ll;
			}
		}
	}
	bn_check_top(a);
	return (1);
}

void BN_clear_free(BIGNUM *a)
{
	int i;

	if (a == NULL)
		return;
	bn_check_top(a);
	if (a->d != NULL && !(BN_get_flags(a, BN_FLG_STATIC_DATA)))
		freezero(a->d, a->dmax * sizeof(a->d[0]));
	i = BN_get_flags(a, BN_FLG_MALLOCED);
	explicit_bzero(a, sizeof(BIGNUM));
	if (i)
		free(a);
}

#ifdef BN_LLONG
BN_ULONG bn_add_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n)
{
	BN_ULLONG ll = 0;

	assert(n >= 0);
	if (n <= 0)
		return ((BN_ULONG)0);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (n & ~3) {
		ll += (BN_ULLONG)a[0] + b[0];
		r[0] = (BN_ULONG)ll & BN_MASK2;
		ll >>= BN_BITS2;
		ll += (BN_ULLONG)a[1] + b[1];
		r[1] = (BN_ULONG)ll & BN_MASK2;
		ll >>= BN_BITS2;
		ll += (BN_ULLONG)a[2] + b[2];
		r[2] = (BN_ULONG)ll & BN_MASK2;
		ll >>= BN_BITS2;
		ll += (BN_ULLONG)a[3] + b[3];
		r[3] = (BN_ULONG)ll & BN_MASK2;
		ll >>= BN_BITS2;
		a += 4;
		b += 4;
		r += 4;
		n -= 4;
	}
#endif
	while (n) {
		ll += (BN_ULLONG)a[0] + b[0];
		r[0] = (BN_ULONG)ll & BN_MASK2;
		ll >>= BN_BITS2;
		a++;
		b++;
		r++;
		n--;
	}
	return ((BN_ULONG)ll);
}
#else /* !BN_LLONG */
BN_ULONG bn_add_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n)
{
	BN_ULONG c, l, t;

	if (n <= 0)
		return ((BN_ULONG)0);

	c = 0;
#ifndef OPENSSL_SMALL_FOOTPRINT
	while (n & ~3) {
		t = a[0];
		t = (t + c) & BN_MASK2;
		c = (t < c);
		l = (t + b[0]) & BN_MASK2;
		c += (l < t);
		r[0] = l;
		t = a[1];
		t = (t + c) & BN_MASK2;
		c = (t < c);
		l = (t + b[1]) & BN_MASK2;
		c += (l < t);
		r[1] = l;
		t = a[2];
		t = (t + c) & BN_MASK2;
		c = (t < c);
		l = (t + b[2]) & BN_MASK2;
		c += (l < t);
		r[2] = l;
		t = a[3];
		t = (t + c) & BN_MASK2;
		c = (t < c);
		l = (t + b[3]) & BN_MASK2;
		c += (l < t);
		r[3] = l;
		a += 4;
		b += 4;
		r += 4;
		n -= 4;
	}
#endif
	while (n) {
		t = a[0];
		t = (t + c) & BN_MASK2;
		c = (t < c);
		l = (t + b[0]) & BN_MASK2;
		c += (l < t);
		r[0] = l;
		a++;
		b++;
		r++;
		n--;
	}
	return ((BN_ULONG)c);
}
#endif /* !BN_LLONG */

BN_ULONG bn_sub_words(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b, int n)
{
	BN_ULONG t1, t2;
	int c = 0;

	if (n <= 0)
		return ((BN_ULONG)0);

#ifndef OPENSSL_SMALL_FOOTPRINT
	while (n&~3) {
		t1 = a[0];
		t2 = b[0];
		r[0] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2)
			c = (t1 < t2);
		t1 = a[1];
		t2 = b[1];
		r[1] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2)
			c = (t1 < t2);
		t1 = a[2];
		t2 = b[2];
		r[2] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2)
			c = (t1 < t2);
		t1 = a[3];
		t2 = b[3];
		r[3] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2)
			c = (t1 < t2);
		a += 4;
		b += 4;
		r += 4;
		n -= 4;
	}
#endif
	while (n) {
		t1 = a[0];
		t2 = b[0];
		r[0] = (t1 - t2 - c) & BN_MASK2;
		if (t1 != t2)
			c = (t1 < t2);
		a++;
		b++;
		r++;
		n--;
	}
	return (c);
}

void freezero(void *ptr, size_t sz)
{
	if (ptr == NULL)
		return;
	explicit_bzero(ptr, sz);
	free(ptr);
}

static BN_ULONG *bn_expand_internal(const BIGNUM *b, int words)
{
	BN_ULONG *A, *a = NULL;
	const BN_ULONG *B;
	int i;

	bn_check_top(b);

	if (words > (INT_MAX/(4*BN_BITS2))) {
		//BNerror(BN_R_BIGNUM_TOO_LONG);
		return NULL;
	}
	if (BN_get_flags(b, BN_FLG_STATIC_DATA)) {
		//BNerror(BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
		return (NULL);
	}
	a = A = (BN_ULONG*) reallocarray(NULL, words, sizeof(BN_ULONG));
	if (A == NULL) {
		//BNerror(ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
#if 1
	B = b->d;
	/* Check if the previous number needs to be copied */
	if (B != NULL) {
		for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
			/*
			 * The fact that the loop is unrolled
			 * 4-wise is a tribute to Intel. It's
			 * the one that doesn't have enough
			 * registers to accommodate more data.
			 * I'd unroll it 8-wise otherwise:-)
			 *
			 *		<appro@fy.chalmers.se>
			 */
			BN_ULONG a0, a1, a2, a3;
			a0 = B[0];
			a1 = B[1];
			a2 = B[2];
			a3 = B[3];
			A[0] = a0;
			A[1] = a1;
			A[2] = a2;
			A[3] = a3;
		}
		switch (b->top & 3) {
		case 3:
			A[2] = B[2];
		case 2:
			A[1] = B[1];
		case 1:
			A[0] = B[0];
		}
	}

#else
	memset(A, 0, sizeof(BN_ULONG) * words);
	memcpy(A, b->d, sizeof(b->d[0]) * b->top);
#endif

	return (a);
}

BIGNUM *bn_expand2(BIGNUM *b, int words)
{
	bn_check_top(b);

	if (words > b->dmax) {
		BN_ULONG *a = bn_expand_internal(b, words);
		if (!a)
			return NULL;
		if (b->d)
			freezero(b->d, b->dmax * sizeof(b->d[0]));
		b->d = a;
		b->dmax = words;
	}

	bn_check_top(b);
	return b;
}

BIGNUM *bn_expand(BIGNUM *a, int bits)
{
	if (bits > (INT_MAX - BN_BITS2 + 1))
		return (NULL);

	if (((bits + BN_BITS2 - 1) / BN_BITS2) <= a->dmax)
		return (a);

	return bn_expand2(a, (bits + BN_BITS2 - 1) / BN_BITS2);
}

int BN_set_word(BIGNUM *a, BN_ULONG w)
{
	bn_check_top(a);
	if (bn_expand(a, (int)sizeof(BN_ULONG) * 8) == NULL)
		return (0);
	a->neg = 0;
	a->d[0] = w;
	a->top = (w ? 1 : 0);
	bn_check_top(a);
	return (1);
}

int BN_ucmp(const BIGNUM *a, const BIGNUM *b)
{
	int i;
	BN_ULONG t1, t2, *ap, *bp;

	bn_check_top(a);
	bn_check_top(b);

	i = a->top - b->top;
	if (i != 0)
		return (i);
	ap = a->d;
	bp = b->d;
	for (i = a->top - 1; i >= 0; i--) {
		t1 = ap[i];
		t2 = bp[i];
		if (t1 != t2)
			return ((t1 > t2) ? 1 : -1);
	}
	return (0);
}

int BN_num_bits_word(BN_ULONG l)
{
	BN_ULONG x, mask;
	int bits;
	unsigned int shift;

	/* Constant time calculation of floor(log2(l)) + 1. */
	bits = (l != 0);
	shift = BN_BITS4;	/* On _LP64 this is 32, otherwise 16. */
	do {
		x = l >> shift;
		/* If x is 0, set mask to 0, otherwise set it to all 1s. */
		mask = ((~x & (x - 1)) >> (BN_BITS2 - 1)) - 1;
		bits += shift & mask;
		/* If x is 0, leave l alone, otherwise set l = x. */
		l ^= (x ^ l) & mask;
	} while ((shift /= 2) != 0);

	return bits;
}

int BN_num_bits(const BIGNUM *a)
{
	int i = a->top - 1;

	bn_check_top(a);

	if (BN_is_zero(a))
		return 0;
	return ((i * BN_BITS2) + BN_num_bits_word(a->d[i]));
}


/* internal functions end*/

/* public functions start */
int BN_lshift1(BIGNUM *r, const BIGNUM *a)
{
	BN_ULONG *ap, *rp, t, c;
	int i;

	bn_check_top(r);
	bn_check_top(a);

	if (r != a) {
		r->neg = a->neg;
		if (bn_wexpand(r, a->top + 1) == NULL)
			return (0);
		r->top = a->top;
	} else {
		if (bn_wexpand(r, a->top + 1) == NULL)
			return (0);
	}
	ap = a->d;
	rp = r->d;
	c = 0;
	for (i = 0; i < a->top; i++) {
		t= *(ap++);
		*(rp++) = ((t << 1) | c) & BN_MASK2;
		c = (t & BN_TBIT) ? 1 : 0;
	}
	if (c) {
		*rp = 1;
		r->top++;
	}
	bn_check_top(r);
	return (1);
}

int BN_rshift1(BIGNUM *r, const BIGNUM *a)
{
	BN_ULONG *ap, *rp, t, c;
	int i, j;

	bn_check_top(r);
	bn_check_top(a);

	if (BN_is_zero(a)) {
		BN_zero(r);
		return (1);
	}
	i = a->top;
	ap = a->d;
	j = i - (ap[i - 1]==1);
	if (a != r) {
		if (bn_wexpand(r, j) == NULL)
			return (0);
		r->neg = a->neg;
	}
	rp = r->d;
	t = ap[--i];
	c = (t & 1) ? BN_TBIT : 0;
	if (t >>= 1)
		rp[i] = t;
	while (i > 0) {
		t = ap[--i];
		rp[i] = ((t >> 1) & BN_MASK2) | c;
		c = (t & 1) ? BN_TBIT : 0;
	}
	r->top = j;
	bn_check_top(r);
	return (1);
}

int BN_lshift(BIGNUM *r, const BIGNUM *a, int n)
{
	int i, nw, lb, rb;
	BN_ULONG *t, *f;
	BN_ULONG l;

	bn_check_top(r);
	bn_check_top(a);

	r->neg = a->neg;
	nw = n / BN_BITS2;
	if (bn_wexpand(r, a->top + nw + 1) == NULL)
		return (0);
	lb = n % BN_BITS2;
	rb = BN_BITS2 - lb;
	f = a->d;
	t = r->d;
	t[a->top + nw] = 0;
	if (lb == 0)
		for (i = a->top - 1; i >= 0; i--)
			t[nw + i] = f[i];
	else
		for (i = a->top - 1; i >= 0; i--) {
			l = f[i];
			t[nw + i + 1] |= (l >> rb) & BN_MASK2;
			t[nw + i] = (l << lb) & BN_MASK2;
		}
	memset(t, 0, nw * sizeof(t[0]));
/*	for (i=0; i<nw; i++)
		t[i]=0;*/
	r->top = a->top + nw + 1;
	bn_correct_top(r);
	bn_check_top(r);
	return (1);
}

int BN_rshift(BIGNUM *r, const BIGNUM *a, int n)
{
	int i, j, nw, lb, rb;
	BN_ULONG *t, *f;
	BN_ULONG l, tmp;

	bn_check_top(r);
	bn_check_top(a);

	nw = n / BN_BITS2;
	rb = n % BN_BITS2;
	lb = BN_BITS2 - rb;
	if (nw >= a->top || a->top == 0) {
		BN_zero(r);
		return (1);
	}
	i = (BN_num_bits(a) - n + (BN_BITS2 - 1)) / BN_BITS2;
	if (r != a) {
		r->neg = a->neg;
		if (bn_wexpand(r, i) == NULL)
			return (0);
	} else {
		if (n == 0)
			return 1; /* or the copying loop will go berserk */
	}

	f = &(a->d[nw]);
	t = r->d;
	j = a->top - nw;
	r->top = i;

	if (rb == 0) {
		for (i = j; i != 0; i--)
			*(t++) = *(f++);
	} else {
		l = *(f++);
		for (i = j - 1; i != 0; i--) {
			tmp = (l >> rb) & BN_MASK2;
			l = *(f++);
			*(t++) = (tmp|(l << lb)) & BN_MASK2;
		}
		if ((l = (l >> rb) & BN_MASK2))
			*(t) = l;
	}
	bn_check_top(r);
	return (1);
}

BIGNUM *BN_dup(const BIGNUM *a)
{
	BIGNUM *t;

	if (a == NULL)
		return NULL;
	bn_check_top(a);

	t = BN_new();
	if (t == NULL)
		return NULL;
	if (!BN_copy(t, a)) {
		BN_free(t);
		return NULL;
	}
	bn_check_top(t);
	return t;
}

BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
{
	int i;
	BN_ULONG *A;
	const BN_ULONG *B;

	bn_check_top(b);

	if (a == b)
		return (a);
	if (bn_wexpand(a, b->top) == NULL)
		return (NULL);

#if 1
	A = a->d;
	B = b->d;
	for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
		BN_ULONG a0, a1, a2, a3;
		a0 = B[0];
		a1 = B[1];
		a2 = B[2];
		a3 = B[3];
		A[0] = a0;
		A[1] = a1;
		A[2] = a2;
		A[3] = a3;
	}
	switch (b->top & 3) {
	case 3:
		A[2] = B[2];
	case 2:
		A[1] = B[1];
	case 1:
		A[0] = B[0];
	}
#else
	memcpy(a->d, b->d, sizeof(b->d[0]) * b->top);
#endif

	a->top = b->top;
	a->neg = b->neg;
	bn_check_top(a);
	return (a);
}

void
BN_swap(BIGNUM *a, BIGNUM *b)
{
	int flags_old_a, flags_old_b;
	BN_ULONG *tmp_d;
	int tmp_top, tmp_dmax, tmp_neg;

	bn_check_top(a);
	bn_check_top(b);

	flags_old_a = a->flags;
	flags_old_b = b->flags;

	tmp_d = a->d;
	tmp_top = a->top;
	tmp_dmax = a->dmax;
	tmp_neg = a->neg;

	a->d = b->d;
	a->top = b->top;
	a->dmax = b->dmax;
	a->neg = b->neg;

	b->d = tmp_d;
	b->top = tmp_top;
	b->dmax = tmp_dmax;
	b->neg = tmp_neg;

	a->flags = (flags_old_a & BN_FLG_MALLOCED) |
	    (flags_old_b & BN_FLG_STATIC_DATA);
	b->flags = (flags_old_b & BN_FLG_MALLOCED) |
	    (flags_old_a & BN_FLG_STATIC_DATA);
	bn_check_top(a);
	bn_check_top(b);
}

void
BN_clear(BIGNUM *a)
{
	bn_check_top(a);
	if (a->d != NULL)
		explicit_bzero(a->d, a->dmax * sizeof(a->d[0]));
	a->top = 0;
	a->neg = 0;
}

char *BN_bn2dec(const BIGNUM *a)
{
	int i = 0, num, bn_data_num, ok = 0;
	char *buf = NULL;
	char *p;
	BIGNUM *t = NULL;
	BN_ULONG *bn_data = NULL, *lp;

	if (BN_is_zero(a)) {
		buf = (char*)malloc(BN_is_negative(a) + 2);
		if (buf == NULL) {
			//BNerror(ERR_R_MALLOC_FAILURE);
			goto err;
		}
		p = buf;
		if (BN_is_negative(a))
			*p++ = '-';
		*p++ = '0';
		*p++ = '\0';
		return (buf);
	}

	/* get an upper bound for the length of the decimal integer
	 * num <= (BN_num_bits(a) + 1) * log(2)
	 *     <= 3 * BN_num_bits(a) * 0.1001 + log(2) + 1     (rounding error)
	 *     <= BN_num_bits(a)/10 + BN_num_bits/1000 + 1 + 1
	 */
	i = BN_num_bits(a) * 3;
	num = (i / 10 + i / 1000 + 1) + 1;
	bn_data_num = num / BN_DEC_NUM + 1;
	bn_data = (BN_ULONG*)reallocarray(NULL, bn_data_num, sizeof(BN_ULONG));
	buf = (char*)malloc(num + 3);
	if ((buf == NULL) || (bn_data == NULL)) {
		//BNerror(ERR_R_MALLOC_FAILURE);
		goto err;
	}
	if ((t = BN_dup(a)) == NULL)
		goto err;

#define BUF_REMAIN (num+3 - (size_t)(p - buf))
	p = buf;
	lp = bn_data;
	if (BN_is_negative(t))
		*p++ = '-';

	while (!BN_is_zero(t)) {
		if (lp - bn_data >= bn_data_num)
			goto err;
		*lp = BN_div_word(t, BN_DEC_CONV);
		if (*lp == (BN_ULONG)-1)
			goto err;
		lp++;
	}
	lp--;
	/* We now have a series of blocks, BN_DEC_NUM chars
	 * in length, where the last one needs truncation.
	 * The blocks need to be reversed in order. */
	snprintf(p, BUF_REMAIN, BN_DEC_FMT1, *lp);
	while (*p)
		p++;
	while (lp != bn_data) {
		lp--;
		snprintf(p, BUF_REMAIN, BN_DEC_FMT2, *lp);
		while (*p)
			p++;
	}
	ok = 1;

err:
	free(bn_data);
	BN_free(t);
	if (!ok && buf) {
		free(buf);
		buf = NULL;
	}

	return (buf);
}

int BN_hex2bn(BIGNUM **bn, const char *a)
{
	BIGNUM *ret = NULL;
	BN_ULONG l = 0;
	int neg = 0, h, m, i,j, k, c;
	int num;

	if ((a == NULL) || (*a == '\0'))
		return (0);

	if (*a == '-') {
		neg = 1;
		a++;
	}

	for (i = 0; i <= (INT_MAX / 4) && isxdigit((unsigned char)a[i]); i++)
		;
	if (i > INT_MAX / 4)
		goto err;

	num = i + neg;
	if (bn == NULL)
		return (num);

	/* a is the start of the hex digits, and it is 'i' long */
	if (*bn == NULL) {
		if ((ret = BN_new()) == NULL)
			return (0);
	} else {
		ret= *bn;
		BN_zero(ret);
	}

	/* i is the number of hex digits */
	if (bn_expand(ret, i * 4) == NULL)
		goto err;

	j = i; /* least significant 'hex' */
	m = 0;
	h = 0;
	while (j > 0) {
		m = ((BN_BYTES*2) <= j) ? (BN_BYTES * 2) : j;
		l = 0;
		for (;;) {
			c = a[j - m];
			if ((c >= '0') && (c <= '9'))
				k = c - '0';
			else if ((c >= 'a') && (c <= 'f'))
				k = c - 'a' + 10;
			else if ((c >= 'A') && (c <= 'F'))
				k = c - 'A' + 10;
			else
				k = 0; /* paranoia */
			l = (l << 4) | k;

			if (--m <= 0) {
				ret->d[h++] = l;
				break;
			}
		}
		j -= (BN_BYTES * 2);
	}
	ret->top = h;
	bn_correct_top(ret);
	ret->neg = neg;

	*bn = ret;
	bn_check_top(ret);
	return (num);

err:
	if (*bn == NULL)
		BN_free(ret);
	return (0);
}

int BN_dec2bn(BIGNUM **bn, const char *a)
{
	BIGNUM *ret = NULL;
	BN_ULONG l = 0;
	int neg = 0, i, j;
	int num;

	if ((a == NULL) || (*a == '\0'))
		return (0);
	if (*a == '-') {
		neg = 1;
		a++;
	}

	for (i = 0; i <= (INT_MAX / 4) && isdigit((unsigned char)a[i]); i++)
		;
	if (i > INT_MAX / 4)
		goto err;

	num = i + neg;
	if (bn == NULL)
		return (num);

	/* a is the start of the digits, and it is 'i' long.
	 * We chop it into BN_DEC_NUM digits at a time */
	if (*bn == NULL) {
		if ((ret = BN_new()) == NULL)
			return (0);
	} else {
		ret = *bn;
		BN_zero(ret);
	}

	/* i is the number of digits, a bit of an over expand */
	if (bn_expand(ret, i * 4) == NULL)
		goto err;

	j = BN_DEC_NUM - (i % BN_DEC_NUM);
	if (j == BN_DEC_NUM)
		j = 0;
	l = 0;
	while (*a) {
		l *= 10;
		l += *a - '0';
		a++;
		if (++j == BN_DEC_NUM) {
			BN_mul_word(ret, BN_DEC_CONV);
			BN_add_word(ret, l);
			l = 0;
			j = 0;
		}
	}
	ret->neg = neg;

	bn_correct_top(ret);
	*bn = ret;
	bn_check_top(ret);
	return (num);

err:
	if (*bn == NULL)
		BN_free(ret);
	return (0);
}

int BN_asc2bn(BIGNUM **bn, const char *a)
{
	const char *p = a;
	if (*p == '-')
		p++;

	if (p[0] == '0' && (p[1] == 'X' || p[1] == 'x')) {
		if (!BN_hex2bn(bn, p + 2))
			return 0;
	} else {
		if (!BN_dec2bn(bn, p))
			return 0;
	}
	if (*a == '-')
		(*bn)->neg = 1;
	return 1;
}

void BN_free(BIGNUM *a)
{
	BN_clear_free(a);
}

void BN_init(BIGNUM *a)
{
	memset(a, 0, sizeof(BIGNUM));
	bn_check_top(a);
}

BIGNUM *BN_create(void)
{
    BIGNUM *a = BN_new();
    BN_init(a);

    return a;

}

BIGNUM *BN_new(void)
{
	BIGNUM *ret;

	if ((ret = (BIGNUM*)malloc(sizeof(BIGNUM))) == NULL) {
		//BNerror(ERR_R_MALLOC_FAILURE);
		return (NULL);
	}
	ret->flags = BN_FLG_MALLOCED;
	ret->top = 0;
	ret->neg = 0;
	ret->dmax = 0;
	ret->d = NULL;
	bn_check_top(ret);
	return (ret);
}

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
	unsigned int i, m;
	unsigned int n;
	BN_ULONG l;
	BIGNUM *bn = NULL;

	if (len < 0)
		return (NULL);
	if (ret == NULL)
		ret = bn = BN_new();
	if (ret == NULL)
		return (NULL);
	bn_check_top(ret);
	l = 0;
	n = len;
	if (n == 0) {
		ret->top = 0;
		return (ret);
	}
	i = ((n - 1) / BN_BYTES) + 1;
	m = ((n - 1) % (BN_BYTES));
	if (bn_wexpand(ret, (int)i) == NULL) {
		BN_free(bn);
		return NULL;
	}
	ret->top = i;
	ret->neg = 0;
	while (n--) {
		l = (l << 8L) | *(s++);
		if (m-- == 0) {
			ret->d[--i] = l;
			l = 0;
			m = BN_BYTES - 1;
		}
	}
	/* need to call this due to clear byte at top if avoiding
	 * having the top bit set (-ve number) */
	bn_correct_top(ret);
	return (ret);
}

/* ignore negative */
int BN_bn2bin(const BIGNUM *a, unsigned char *to)
{
	int n, i;
	BN_ULONG l;

	bn_check_top(a);
	n = i=BN_num_bytes(a);
	while (i--) {
		l = a->d[i / BN_BYTES];
		*(to++) = (unsigned char)(l >> (8 * (i % BN_BYTES))) & 0xff;
	}
	return (n);
}

int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	int ret, r_neg;

	bn_check_top(a);
	bn_check_top(b);

	if (a->neg == b->neg) {
		r_neg = a->neg;
		ret = BN_uadd(r, a, b);
	} else {
		int cmp = BN_ucmp(a, b);

		if (cmp > 0) {
			r_neg = a->neg;
			ret = BN_usub(r, a, b);
		} else if (cmp < 0) {
			r_neg = b->neg;
			ret = BN_usub(r, b, a);
		} else {
			r_neg = 0;
			BN_zero(r);
			ret = 1;
		}
	}

	r->neg = r_neg;
	bn_check_top(r);
	return ret;
}

int BN_uadd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	int max, min, dif;
	const BN_ULONG *ap, *bp;
	BN_ULONG *rp, carry, t1, t2;

	bn_check_top(a);
	bn_check_top(b);

	if (a->top < b->top) {
		const BIGNUM *tmp;

		tmp = a;
		a = b;
		b = tmp;
	}
	max = a->top;
	min = b->top;
	dif = max - min;

	if (bn_wexpand(r, max + 1) == NULL)
		return 0;

	r->top = max;

	ap = a->d;
	bp = b->d;
	rp = r->d;

	carry = bn_add_words(rp, ap, bp, min);
	rp += min;
	ap += min;

	while (dif) {
		dif--;
		t1 = *(ap++);
		t2 = (t1 + carry) & BN_MASK2;
		*(rp++) = t2;
		carry &= (t2 == 0);
	}
	*rp = carry;
	r->top += carry;

	r->neg = 0;
	bn_check_top(r);
	return 1;
}

int BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	int max, min, dif;
	const BN_ULONG *ap, *bp;
	BN_ULONG t1, t2, borrow, *rp;

	bn_check_top(a);
	bn_check_top(b);

	max = a->top;
	min = b->top;
	dif = max - min;

	if (dif < 0) {
		//BNerror(BN_R_ARG2_LT_ARG3);
		return 0;
	}

	if (bn_wexpand(r, max) == NULL)
		return 0;

	ap = a->d;
	bp = b->d;
	rp = r->d;

	borrow = bn_sub_words(rp, ap, bp, min);
	ap += min;
	rp += min;

	while (dif) {
		dif--;
		t1 = *(ap++);
		t2 = (t1 - borrow) & BN_MASK2;
		*(rp++) = t2;
		borrow &= (t1 == 0);
	}

	while (max > 0 && *--rp == 0)
		max--;

	r->top = max;
	r->neg = 0;
	bn_correct_top(r);
	return 1;
}

int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b)
{
	int ret, r_neg;

	bn_check_top(a);
	bn_check_top(b);

	if (a->neg != b->neg) {
		r_neg = a->neg;
		ret = BN_uadd(r, a, b);
	} else {
		int cmp = BN_ucmp(a, b);

		if (cmp > 0) {
			r_neg = a->neg;
			ret = BN_usub(r, a, b);
		} else if (cmp < 0) {
			r_neg = !b->neg;
			ret = BN_usub(r, b, a);
		} else {
			r_neg = 0;
			BN_zero(r);
			ret = 1;
		}
	}

	r->neg = r_neg;
	bn_check_top(r);
	return ret;
}
/* public functions end */
#endif
