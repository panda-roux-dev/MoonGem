#include "store.h"

#include <stdlib.h>
#include <time.h>
#include <wyhash.h>

#include "log.h"

#define MAX_LOAD_FACTOR 0.5f

static void insert_by_keyhash(store_t* store, uint64_t key, char* data);

static inline float compute_load_factor(store_t* store) {
  return (float)store->stored_count / (float)store->cell_count;
}

static void rebuild_expanded(store_t* store) {
  // creating an entirely separate table on the heap is not the most efficient
  // way of doing this, but this method is only called periodically so I don't
  // really care
  store_t* replacement = create_store(store->cell_count * 2);

  // copy the wyhash secret to ensure that keys hash the same as before
  memcpy(&replacement->secret[0], &store->secret[0], sizeof(store->secret));

  for (size_t i = 0; i < store->cell_count; ++i) {
    cell_t* cell = &store->cells[i];
    if (cell->key == 0 || cell->deleted) {
      continue;
    }

    // cell->data is already heap-allocated, so it doesn't need to be copied
    // or free'd upon changing tables
    insert_by_keyhash(replacement, cell->key, cell->data);
  }

  LOG_DEBUG("New table size is %zu (previously %zu)", replacement->cell_count,
            store->cell_count);

  // free the initial store's buffer prior to overwriting its pointer
  free(store->cells);

  // copy everything from the replacement to the initial store, then free the
  // replacmement as it's no longer needed
  memcpy(store, replacement, sizeof(store_t));
  free(replacement);
}

static void insert_by_keyhash(store_t* store, uint64_t key, char* data) {
  // if this insertion would cause the load factor to exceed the acceptable
  // level, then move all data to a new store with a greater capacity
  if (compute_load_factor(store) >= MAX_LOAD_FACTOR) {
    rebuild_expanded(store);
  }

  ++(store->stored_count);

  // use linear probing to find a valid index
  size_t index = key % (uint64_t)store->cell_count;
  cell_t* cell;
  do {
    cell = &store->cells[index];
    ++index;
    index %= store->cell_count;
  } while (!cell->deleted && cell->key != 0 && cell->key != key);

  cell->key = key;
  cell->data = data;
  cell->deleted = false;
}

static cell_t* find_by_keyhash(store_t* store, uint64_t key) {
  size_t index = key % (uint64_t)store->cell_count;
  cell_t* cell;
  do {
    cell = &store->cells[index];
    ++index;
    index %= store->cell_count;
  } while (cell->key != 0 && cell->key != key);

  if (cell->key == 0) {
    LOG_DEBUG("Key %zu was not found!", key);
  }

  return cell->key == 0 ? NULL : cell;
}

store_t* create_store(size_t size) {
  store_t* store = malloc(sizeof(store_t));
  store->cell_count = size;
  store->stored_count = 0;
  store->cells = calloc(store->cell_count, sizeof(cell_t));

  // set wyhash secret value (prevents against certain kinds of hash-table
  // attacks)
  make_secret(time(NULL), &store->secret[0]);

  return store;
}

void destroy_store(store_t* store) {
  if (store == NULL) {
    return;
  }

  if (store->cells != NULL) {
    for (size_t i = 0; i < store->cell_count; ++i) {
      if (store->cells[i].data != NULL) {
        free(store->cells[i].data);
      }
    }

    free(store->cells);
  }

  free(store);
}

void insert_into_store(store_t* store, char* key, char* data) {
  uint64_t keyhash = wyhash(key, strlen(key), 0, &store->secret[0]);
  insert_by_keyhash(store, keyhash, strdup(data));
}

bool delete_from_store(store_t* store, char* key) {
  if (store->stored_count == 0) {
    return false;
  }

  uint64_t keyhash = wyhash(key, strlen(key), 0, &store->secret[0]);
  cell_t* target = find_by_keyhash(store, keyhash);
  if (target == NULL || target->deleted) {
    LOG_DEBUG("The key \"%s\" was not found!", key);
    return false;
  }

  target->deleted = true;
  if (target->data != NULL) {
    free(target->data);
    target->data = NULL;
  }

  --(store->stored_count);

  return true;
}

const char* get_from_store(store_t* store, char* key) {
  uint64_t keyhash = wyhash(key, strlen(key), 0, &store->secret[0]);
  cell_t* target = find_by_keyhash(store, keyhash);
  return target == NULL ? NULL : target->data;
}

