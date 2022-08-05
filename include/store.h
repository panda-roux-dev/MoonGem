#ifndef STORE_T
#define STORE_T

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define INITIAL_STORE_SIZE 32

typedef struct cell_t {
  uint64_t key;
  size_t length;
  char* data;
  bool deleted;
} cell_t;

typedef struct store_t {
  uint64_t secret[4];
  size_t cell_count;
  size_t stored_count;
  cell_t* cells;
} store_t;

store_t* create_store(size_t size);

void destroy_store(store_t* store);

void insert_into_store(store_t* store, char* key, char* data);

bool delete_from_store(store_t* store, char* key);

const char* get_from_store(store_t* store, char* key);

#endif
