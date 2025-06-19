// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025  Ammar Faizi <ammarfaizi2@gnuweeb.org>
 *
 * gwchat - Super simple chat app.
 *
 * Server and client are implemented in a single binary.
 */
#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

typedef void hash_table_t;

hash_table_t *ht_alloc(void);
void ht_free(hash_table_t *ht);
int ht_insert(hash_table_t *ht, const void *k, size_t klen, const void *v,
	      size_t vlen);
int ht_lookup(hash_table_t *ht, const void *k, size_t klen, const void **v,
	      size_t *vlen);
int ht_remove(hash_table_t *ht, const void *k, size_t klen);
size_t ht_size(hash_table_t *ht);
void ht_clear(hash_table_t *ht);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* #ifndef HASH_TABLE_H */
