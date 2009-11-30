/* An implementation of hash tables:
 * Copyright(C) 2000-2004 by Salvatore Sanfilippo <antirez@invece.org>
 *
 * This software is under the BSD license
 */

#include <sys/types.h>

#ifndef _AHT_H
#define _AHT_H

/* Fix to compile under WIN32/MINGW and SunOS */
#if defined(WIN32) || defined(__sun__)
#ifndef u_int8_t
#define u_int8_t unsigned char
#define u_int16_t unsigned short
#define u_int32_t unsigned int
#endif
#endif

/* ------------------------------ exit codes -------------------------------- */
#define HT_OK		0		/* Success */
#define HT_FOUND	1		/* Key found */
#define HT_NOTFOUND	2		/* Key not found */
#define HT_BUSY		3		/* Key already exist */
#define HT_NOMEM	4		/* Out of memory */
#define HT_IOVERFLOW	5		/* Index overflow */
#define HT_INVALID	6		/* Invalid argument */

#define HT_INITIAL_SIZE	256

/* ----------------------- hash table structures -----------------------------*/
struct ht_ele {
	void *key;
	void *data;
};

struct hashtable {
	struct ht_ele **table;
	unsigned int size;
	unsigned int sizemask;
	unsigned int used;
	unsigned int collisions;
	u_int32_t (*hashf)(void *key);
	int (*key_compare)(void *key1, void *key2);
	void (*key_destructor)(void *key);
	void (*val_destructor)(void *obj);
};

/* ----------------------------- Prototypes ----------------------------------*/
int ht_init(struct hashtable *t);
int ht_move(struct hashtable *orig, struct hashtable *dest, unsigned int index);
int ht_expand(struct hashtable *t, size_t size);
int ht_add(struct hashtable *t, void *key, void *data);
int ht_replace(struct hashtable *t, void *key, void *data);
int ht_rm(struct hashtable *t, void *key);
int ht_destroy(struct hashtable *t);
int ht_free(struct hashtable *t, unsigned int index);
int ht_search(struct hashtable *t, void *key, unsigned int *found_index);
int ht_get_byindex(struct hashtable *t, unsigned int index);
int ht_resize(struct hashtable *t);
void **ht_get_array(struct hashtable *t);

/* provided destructors */
void ht_destructor_free(void *obj);
#define ht_no_destructor NULL

/* provided compare functions */
int ht_compare_ptr(void *key1, void *key2);
int ht_compare_string(void *key1, void *key2);

/* ------------------------ The hash functions ------------------------------ */
u_int32_t djb_hash(unsigned char *buf, size_t len);
u_int32_t djb_hashR(unsigned char *buf, size_t len);
u_int32_t trivial_hash(unsigned char *buf, size_t len);
u_int32_t trivial_hashR(unsigned char *buf, size_t len);
u_int32_t ht_strong_hash(u_int8_t *k, u_int32_t length, u_int32_t initval);
u_int32_t __ht_strong_hash(u_int8_t *k, u_int32_t length, u_int32_t initval);

/* ----------------- hash functions for common data types ------------------- */
u_int32_t ht_hash_string(void *key);
u_int32_t ht_hash_pointer(void *key);

/* ----------------------------- macros --------------------------------------*/
#define ht_set_hash(t,f) ((t)->hashf = (f))
#define ht_set_key_destructor(t,f) ((t)->key_destructor = (f))
#define ht_set_val_destructor(t,f) ((t)->val_destructor = (f))
#define ht_set_key_compare(t,f) ((t)->key_compare = (f))
#define ht_collisions(t) ((t)->collisions)
#define ht_size(t) ((t)->size)
#define ht_used(t) ((t)->used)
#define ht_key(t, i) ((t)->table[(i)]->key)
#define ht_value(t, i) ((t)->table[(i)]->data)

#endif /* _AHT_H */
