
#include <unordered_map>
#include <vector>
#include <string>
#include <span>
#include "hash_table.h"

extern "C" {

typedef std::unordered_map<std::string, std::vector<unsigned char>> ht_type_t;

hash_table_t *ht_alloc(void)
{
	try {
		return new ht_type_t();
	} catch (...) {
		return nullptr;
	}
}

void ht_free(hash_table_t *ht)
{
	try {
		delete static_cast<ht_type_t *>(ht);
	} catch (...) {
	}
}

int ht_insert(hash_table_t *ht, const void *k, size_t klen, const void *v,
	      size_t vlen)
{
	try {
		auto m = static_cast<ht_type_t *>(ht);
		auto key = std::string(static_cast<const char *>(k), klen);
		(*m)[key] = std::vector<unsigned char>(
			static_cast<const unsigned char *>(v),
			static_cast<const unsigned char *>(v) + vlen
		);
		return 0;
	} catch (...) {
		return -1;
	}
}

int ht_lookup(hash_table_t *ht, const void *k, size_t klen, const void **v,
	      size_t *vlen)
{
	try {
		auto m = static_cast<ht_type_t *>(ht);
		auto key = std::string(static_cast<const char *>(k), klen);
		auto it = m->find(key);
		if (it != m->end()) {
			*v = const_cast<unsigned char *>(it->second.data());
			*vlen = it->second.size();
			return 0;
		}
		return -1;
	} catch (...) {
		return -1;
	}
}

int ht_remove(hash_table_t *ht, const void *k, size_t klen)
{
	try {
		auto m = static_cast<ht_type_t *>(ht);
		auto key = std::string(static_cast<const char *>(k), klen);
		auto it = m->find(key);
		if (it != m->end()) {
			m->erase(it);
			return 0;
		}
		return -1;
	} catch (...) {
		return -1;
	}
}

size_t ht_size(hash_table_t *ht)
{
	try {
		auto m = static_cast<ht_type_t *>(ht);
		return m->size();
	} catch (...) {
		return 0;
	}
}

void ht_clear(hash_table_t *ht)
{
	try {
		auto m = static_cast<ht_type_t *>(ht);
		m->clear();
	} catch (...) {
	}
}

} /* extern "C" */
