/* An implementation of in-memory hash tables:
 * Copyright (c) 2000-2004 Salvatore Sanfilippo <antirez@invece.org>
 *
 * -- VERSION 2004.05.22 --
 *
 * COPYRIGHT AND PERMISSION NOTICE
 * -------------------------------
 *
 * Copyright (c) 2000 Salvatore Sanfilippo <antirez@invece.org>
 * Copyright (c) 2001 Salvatore Sanfilippo <antirez@invece.org>
 * Copyright (c) 2002 Salvatore Sanfilippo <antirez@invece.org>
 * Copyright (c) 2003 Salvatore Sanfilippo <antirez@invece.org>
 * Copyright (c) 2004 Salvatore Sanfilippo <antirez@invece.org>
 *
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, and/or sell copies of the Software, and to permit persons
 * to whom the Software is furnished to do so, provided that the above
 * copyright notice(s) and this permission notice appear in all copies of
 * the Software and that both the above copyright notice(s) and this
 * permission notice appear in supporting documentation.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
 * OF THIRD PARTY RIGHTS. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * HOLDERS INCLUDED IN THIS NOTICE BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL
 * INDIRECT OR CONSEQUENTIAL DAMAGES, OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Except as contained in this notice, the name of a copyright holder
 * shall not be used in advertising or otherwise to promote the sale, use
 * or other dealings in this Software without prior written authorization
 * of the copyright holder.
 *
 * CHANGELOG
 * ---------
 *
 * 22May2004 - Fixed a but in ht_destroy(). Now after this call the
 * hashtable is really ready to be reused. Fixed also a memory leak
 * in the same function. Luckly this function is only called at exit
 * in many programs.
 *
 * OVERVIEW
 * --------
 *
 * AHT is an implementation of a dictionary with support for
 * INSERT, DELETE and SEARCH operations. It uses the hash table
 * as base data structure to provide almost constant times for
 * the three operations. AHT also automatically care about the
 * size of the current key-values set increasing the hash table
 * as needed.
 *
 * DESIGN PRINCIPLE
 * ----------------
 *
 * - AHT try to resist to attacker-induced worst-case behaviour
 *   trought the randomization of the hash-function. This is
 *   optional.
 *
 * - AHT take care of the hash table expansion when needed.
 *   The hash table load ranges from 0 to 0.5, the hash table
 *   size is a power of two.
 *
 * - A simple implementation. The collisions resolution used
 *   is a simple linear probing, that takes advantage of
 *   the modern CPU caches, the low hash table max load and
 *   the use of a strong hash function provided with this library
 *   (ht_strong_hash), should mitigate the primary clustering
 *   enough. Experimental results shown that double hashing
 *   was a performance lost with common key types in modern
 *   CPUs.
 *
 * - Moderatly method oriented, it is possible to define the hash
 *   function, key/value destructors, key compare function, for a
 *   given hash table, but not with a per-element base.
 *
 * === WARNING ===
 * =    Before to use this library, think about the -fact- that the
 * =    worst case is O(N). Like for the quick sort algorithm, it may
 * =    be a bad idea to use this library in medical software, or other
 * =    software for wich the worst case should be taken in account
 * =    even if not likely to happen.
 * =    Good alternatives are red-black trees, and other trees with
 * =    a good worst-case behavior.
 * ===============
 *
 * TODO
 * ----
 *
 * - Write the documentation
 * - ht_copy() to copy an element between hash tables
 * - ht_dup() to duplicate an entire hash table
 * - ht_merge() to add the content of one hash table to another
 * - disk operations, the ability to save an hashtable from the
 *   memory to the disk and the reverse operation.
 *
 * Most of this features needs additional methods, like one
 * to copy an object, and should return an error if such methods
 * are not defined.
 *
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "aht.h"

/* -------------------------- private prototypes ---------------------------- */
static int ht_expand_if_needed(struct hashtable *t);
static unsigned int next_power(unsigned int size);
static int ht_insert(struct hashtable *t, void *key, unsigned int *avail_index);

/* The special ht_free_element pointer is used to mark
 * a freed element in the hash table (note that the elements
 * neven used are just NULL pointers) */
static struct ht_ele *ht_free_element = (void*) -1;

/* -------------------------- hash functions -------------------------------- */
/* The djb hash function, that's under public domain */
u_int32_t djb_hash(unsigned char *buf, size_t len)
{
	u_int32_t h = 5381;
	while(len--)
		h = (h + (h << 5)) ^ *buf++;
	return h;
}

u_int32_t djb_hashR(unsigned char *buf, size_t len)
{
	u_int32_t h = 5381;
	buf += len-1;
	while(len--)
		h = (h + (h << 5)) ^ *buf--;
	return h;
}

/* Another trivial hash function */
#define ROT32R(x,n) (((x)>>n)|(x<<(32-n)))
u_int32_t trivial_hash(unsigned char *buf, size_t len)
{
	u_int32_t h = 0;
	while(len--) {
		h = h + *buf++;
		h = ROT32R(h, 3);
	}
	return h;
}

u_int32_t trivial_hashR(unsigned char *buf, size_t len)
{
	u_int32_t h = 0;
	buf += len-1;
	while(len--) {
		h = h + *buf--;
		h = ROT32R(h, 3);
	}
	return h;
}

/* A strong hash function that should be the default with this
 * hashtable implementation. Our hash tables does not support
 * double hashing for design: the idea is to avoid double
 * hashing and use a bit slower but very strong hash function like
 * this. This should provide quite good performances with
 * all the kinds of keys if you take the default max load of 50%.
 *
 * For more information see: http://burtleburtle.net/bob/hash/evahash.html */

/* The mixing step */
#define mix(a,b,c) \
{ \
  a=a-b;  a=a-c;  a=a^(c>>13); \
  b=b-c;  b=b-a;  b=b^(a<<8);  \
  c=c-a;  c=c-b;  c=c^(b>>13); \
  a=a-b;  a=a-c;  a=a^(c>>12); \
  b=b-c;  b=b-a;  b=b^(a<<16); \
  c=c-a;  c=c-b;  c=c^(b>>5);  \
  a=a-b;  a=a-c;  a=a^(c>>3);  \
  b=b-c;  b=b-a;  b=b^(a<<10); \
  c=c-a;  c=c-b;  c=c^(b>>15); \
}

/* The whole new hash function */
u_int32_t __ht_strong_hash(u_int8_t *k, u_int32_t length, u_int32_t initval)
{
	u_int32_t a,b,c;	/* the internal state */
	u_int32_t len;		/* how many key bytes still need mixing */

	/* Set up the internal state */
	len = length;
	a = b = 0x9e3779b9;  /* the golden ratio; an arbitrary value */
	c = initval;         /* variable initialization of internal state */

	/*---------------------------------------- handle most of the key */
	while (len >= 12)
	{
		a=a+(k[0]+((u_int32_t)k[1]<<8)+((u_int32_t)k[2]<<16)+
					       ((u_int32_t)k[3]<<24));
		b=b+(k[4]+((u_int32_t)k[5]<<8)+((u_int32_t)k[6]<<16)+
					       ((u_int32_t)k[7]<<24));
		c=c+(k[8]+((u_int32_t)k[9]<<8)+((u_int32_t)k[10]<<16)+
					       ((u_int32_t)k[11]<<24));
		mix(a,b,c);
		k = k+12; len = len-12;
	}

	/*------------------------------------- handle the last 11 bytes */
	c = c+length;
	switch(len)              /* all the case statements fall through */
	{
		case 11: c=c+((u_int32_t)k[10]<<24);
		case 10: c=c+((u_int32_t)k[9]<<16);
		case 9 : c=c+((u_int32_t)k[8]<<8);
		/* the first byte of c is reserved for the length */
		case 8 : b=b+((u_int32_t)k[7]<<24);
		case 7 : b=b+((u_int32_t)k[6]<<16);
		case 6 : b=b+((u_int32_t)k[5]<<8);
		case 5 : b=b+k[4];
		case 4 : a=a+((u_int32_t)k[3]<<24);
		case 3 : a=a+((u_int32_t)k[2]<<16);
		case 2 : a=a+((u_int32_t)k[1]<<8);
		case 1 : a=a+k[0];
		/* case 0: nothing left to add */
	}
	mix(a,b,c);
	/*-------------------------------------------- report the result */
	return c;
}

/* ----------------------------- API implementation ------------------------- */
/* reset an hashtable already initialized with ht_init().
 * NOTE: This function should only called by ht_destroy(). */
static void ht_reset(struct hashtable *t)
{
	t->table = NULL;
	t->size = 0;
	t->sizemask = 0;
	t->used = 0;
	t->collisions = 0;
}

/* Initialize the hash table */
int ht_init(struct hashtable *t)
{
	ht_reset(t);
	t->hashf = ht_hash_pointer;
	t->key_destructor = ht_no_destructor;
	t->val_destructor = ht_no_destructor;
	t->key_compare = ht_compare_ptr;
	return HT_OK;
}

/* Resize the table to the minimal size that contains all the elements */
int ht_resize(struct hashtable *t)
{
	int minimal = (t->used * 2)+1;

	if (minimal < HT_INITIAL_SIZE)
		minimal = HT_INITIAL_SIZE;
	return ht_expand(t, minimal);
}

/* Move an element accross hash tables */
int ht_move(struct hashtable *orig, struct hashtable *dest, unsigned int index)
{
	int ret;
	unsigned int new_index;

	/* If the element isn't in the table ht_search will store
	 * the index of the free ht_ele in the integer pointer by *index */
	ret = ht_insert(dest, orig->table[index]->key, &new_index);
	if (ret != HT_OK)
		return ret;

	/* Move the element */
	dest->table[new_index] = orig->table[index];
	orig->table[index] = ht_free_element;
	orig->used--;
	dest->used++;
	return HT_OK;
}

/* Expand or create the hashtable */
int ht_expand(struct hashtable *t, size_t size)
{
	struct hashtable n; /* the new hashtable */
	unsigned int realsize = next_power(size), i;

	/* the size is invalid if it is smaller than the number of
	 * elements already inside the hashtable */
	if (t->used >= size)
		return HT_INVALID;

	ht_init(&n);
	n.size = realsize;
	n.sizemask = realsize-1;
	n.table = malloc(realsize*sizeof(struct ht_ele*));
	if (n.table == NULL)
		return HT_NOMEM;
	/* Copy methods */
	n.hashf = t->hashf;
	n.key_destructor = t->key_destructor;
	n.val_destructor = t->val_destructor;
	n.key_compare= t->key_compare;

	/* Initialize all the pointers to NULL */
	memset(n.table, 0, realsize*sizeof(struct ht_ele*));

	/* Copy all the elements from the old to the new table:
	 * note that if the old hash table is empty t->size is zero,
	 * so ht_expand() acts like an ht_create() */
	n.used = t->used;
	for (i = 0; i < t->size && t->used > 0; i++) {
		if (t->table[i] != NULL && t->table[i] != ht_free_element) {
			u_int32_t h;

			/* Get the new element index: note that we
			 * know that there aren't freed elements in 'n' */
			h = n.hashf(t->table[i]->key) & n.sizemask;
			if (n.table[h]) {
				n.collisions++;
				while(1) {
					h = (h+1) & n.sizemask;
					if (!n.table[h])
						break;
					n.collisions++;
				}
			}
			/* Move the element */
			n.table[h] = t->table[i];
			t->used--;
		}
	}
	assert(t->used == 0);
	free(t->table);

	/* Remap the new hashtable in the old */
	*t = n;
	return HT_OK;
}

/* Add an element, discarding the old if the key already exists */
int ht_replace(struct hashtable *t, void *key, void *data)
{
	int ret;
	unsigned int index;

	/* Try to add the element */
	ret = ht_add(t, key, data);
	if (ret == HT_OK || ret != HT_BUSY)
		return ret;
	/* It already exists, get the index */
	ret = ht_search(t, key, &index);
	assert(ret == HT_FOUND);
	/* Remove the old */
	ret = ht_free(t, index);
	assert(ret == HT_OK);
	/* And add the new */
	return ht_add(t, key, data);
}

/* Add an element to the target hash table */
int ht_add(struct hashtable *t, void *key, void *data)
{
	int ret;
	unsigned int index;

	/* If the element isn't in the table ht_insert() will store
	 * the index of the free ht_ele in the integer pointer by *index */
	ret = ht_insert(t, key, &index);
	if (ret != HT_OK)
		return ret;

	/* Allocates the memory and stores key */
	if ((t->table[index] = malloc(sizeof(struct ht_ele))) == NULL)
		return HT_NOMEM;
	/* Store the pointers */
	t->table[index]->key = key;
	t->table[index]->data = data;
	t->used++;
	return HT_OK;
}

/* search and remove an element */
int ht_rm(struct hashtable *t, void *key)
{
	int ret;
	unsigned int index;

	if ((ret = ht_search(t, key, &index)) != HT_FOUND)
		return ret;
	return ht_free(t, index);
}

/* Destroy an entire hash table */
int ht_destroy(struct hashtable *t)
{
	unsigned int i;

	/* Free all the elements */
	for (i = 0; i < t->size && t->used > 0; i++) {
		if (t->table[i] != NULL && t->table[i] != ht_free_element) {
			if (t->key_destructor)
				t->key_destructor(t->table[i]->key);
			if (t->val_destructor)
				t->val_destructor(t->table[i]->data);
			free(t->table[i]);
			t->used--;
		}
	}
	/* Free the table and the allocated cache structure */
	free(t->table);
	/* Re-initialize the table */
	ht_reset(t);
	return HT_OK; /* Actually ht_destroy never fails */
}

/* Free an element in the hash table */
int ht_free(struct hashtable *t, unsigned int index)
{
	if (index >= t->size)
		return HT_IOVERFLOW; /* Index overflow */
	/* ht_free() calls against non-existent elements are ignored */
	if (t->table[index] != NULL && t->table[index] != ht_free_element) {
		/* release the key */
		if (t->key_destructor)
			t->key_destructor(t->table[index]->key);
		/* release the value */
		if (t->val_destructor)
			t->val_destructor(t->table[index]->data);
		/* free the element structure */
		free(t->table[index]);
		/* mark the element as freed */
		t->table[index] = ht_free_element;
		t->used--;
	}
	return HT_OK;
}

/* Search the element with the given key */
int ht_search(struct hashtable *t, void *key, unsigned int *found_index)
{
	int ret;
	u_int32_t h;

	/* Expand the hashtable if needed */
	if (t->size == 0) {
		if ((ret = ht_expand_if_needed(t)) != HT_OK)
			return ret;
	}

	/* Try using the first hash functions */
	h = t->hashf(key) & t->sizemask;
	/* this handles the removed elements */
	if (!t->table[h])
		return HT_NOTFOUND;
	if (t->table[h] != ht_free_element &&
	    t->key_compare(key, t->table[h]->key))
	{
		*found_index = h;
		return HT_FOUND;
	}

	while(1) {
		h = (h+1) & t->sizemask;
		/* this handles the removed elements */
		if (t->table[h] == ht_free_element)
			continue;
		if (!t->table[h])
			return HT_NOTFOUND;
		if (t->key_compare(key, t->table[h]->key)) {
			*found_index = h;
			return HT_FOUND;
		}
	}
}

/* This function is used to run the entire hash table,
 * it returns:
 * 1  if the element with the given index is valid
 * 0  if the element with the given index is empty or marked free
 * -1 if the element if out of the range */
int ht_get_byindex(struct hashtable *t, unsigned int index)
{
	if (index >= t->size)
		return -1;
	if (t->table[index] == NULL || t->table[index] == ht_free_element)
		return 0;
	return 1;
}

/* Returns the hash table as an array of paris of key/value void* pointers.
 * The array is allocated with malloc() and should be freed when no
 * longer useful. The key and value pointers should not be freed or
 * altered in any way, they will be handled by the hash table structure.
 *
 * This function is mainly useful to sort the hashtable's content
 * without to alter the hashtable itself.
 *
 * Returns NULL on out of memory. */
void **ht_get_array(struct hashtable *t)
{
	int used = ht_used(t);
	void **table, **tptr;
	long idx;

	if ((table = (void**) malloc(sizeof(void*)*(used*2))) == NULL)
		return NULL;
	tptr = table;
	for (idx = 0; ;idx++) {
		int type = ht_get_byindex(t, idx);
		if (type == -1) break;
		if (type == 0) continue;
		*tptr++ = ht_key(t, idx);
		*tptr++ = ht_value(t, idx);
	}
	return table;
}
/* ------------------------- private functions ------------------------------ */

/* Expand the hash table if needed */
static int ht_expand_if_needed(struct hashtable *t)
{
	/* If the hash table is empty expand it to the intial size,
	 * if the table is half-full redobule its size. */
	if (t->size == 0)
		return ht_expand(t, HT_INITIAL_SIZE);
	if (t->size <= t->used*2)
		return ht_expand(t, t->size * 2);
	return HT_OK;
}

/* Our hash table capability is a power of two */
static unsigned int next_power(unsigned int size)
{
	unsigned int i = 256;

	if (size >= 2147483648U)
		return 2147483648U;
	while(1) {
		if (i >= size)
			return i;
		i *= 2;
	}
}

/* the insert function to add elements out of ht expansion */
static int ht_insert(struct hashtable *t, void *key, unsigned int *avail_index)
{
	int ret;
	u_int32_t h;

	/* Expand the hashtable if needed */
	if ((ret = ht_expand_if_needed(t)) != HT_OK)
		return ret;

	/* Try using the first hash functions */
	h = t->hashf(key) & t->sizemask;
	/* this handles the removed elements */
	if (!t->table[h] || t->table[h] == ht_free_element) {
		*avail_index = h;
		return HT_OK;
	}
	t->collisions++;
	if (t->key_compare(key, t->table[h]->key))
		return HT_BUSY;

	while(1) {
		h = (h+1) & t->sizemask;
		/* this handles the removed elements */
		if (!t->table[h] || t->table[h] == ht_free_element) {
			*avail_index = h;
			return HT_OK;
		}
		t->collisions++;
		if (t->key_compare(key, t->table[h]->key))
			return HT_BUSY;
	}
}

/* ------------------------- provided destructors --------------------------- */

/* destructor for heap allocated keys/values */
void ht_destructor_free(void *obj)
{
	free(obj);
}

/* ------------------------- provided comparators --------------------------- */

/* default key_compare method */
int ht_compare_ptr(void *key1, void *key2)
{
	return (key1 == key2);
}

/* key compare for nul-terminated strings */
int ht_compare_string(void *key1, void *key2)
{
	return (strcmp(key1, key2) == 0) ? 1 : 0;
}

/* -------------------- hash functions for common data types --------------- */

/* We make this global to allow hash function randomization,
 * as security measure against attacker-induced worst case behaviuor.
 *
 * Note that being H_i the strong hash function with init value of i
 * and H_i' the same hash function with init value of i' than:
 *
 * if H_i(StringOne) is equal to H_i(CollidingStringTwo)
 *
 *    it is NOT true that
 *
 *  H_i'(StringOne) is equal to H_i''(CollidingStringTwo)
 */
static u_int32_t strong_hash_init_val = 0xF937A21;

/* Set the secret initialization value. It should be set from
 * a secure PRNG like /dev/urandom at program initialization time */
void ht_set_strong_hash_init_val(u_int32_t secret)
{
	strong_hash_init_val = secret;
}

/* __ht_strong_hash wrapper that mix a user-provided initval
 * with the global strong_hash_init_val. __ht_strong_hash is
 * even exported directly. */
u_int32_t ht_strong_hash(u_int8_t *k, u_int32_t length, u_int32_t initval)
{
	return __ht_strong_hash(k, length, initval^strong_hash_init_val);
}

/* Hash function suitable for C strings and other data types using
 * a 0-byte as terminator */
u_int32_t ht_hash_string(void *key)
{
	return __ht_strong_hash(key, strlen(key), strong_hash_init_val);
}

/* This one is to hash the value of the pointer itself. */
u_int32_t ht_hash_pointer(void *key)
{
	return __ht_strong_hash((void*)&key, sizeof(void*), strong_hash_init_val);
}
