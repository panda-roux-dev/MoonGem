#include "store.h"

#include <stdlib.h>
#include <time.h>
#include <wyhash.h>

#include "log.h"

#define MAX_LOAD_FRACTION 2

static void insert_by_keyhash(store_t* store, uint64_t key, char* data);

static bool is_max_load(size_t stored, size_t total) {
  return total == 0 || stored / total > total / MAX_LOAD_FRACTION;
}

static void rebuild_expanded(store_t* store) {
  store_t* replacement = create_store(store->cell_count * 2);
  for (size_t i = 0; i < store->cell_count; ++i) {
    cell_t* cell = &store->cells[i];
    if (cell->key != 0) {
      insert_by_keyhash(replacement, cell->key, cell->data);
    }
  }

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
  if (is_max_load(store->stored_count + 1, store->cell_count)) {
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
  } while (cell->key != 0 && cell->key != key);

  cell->key = key;
  cell->data = data;
}

static cell_t* find_by_keyhash(store_t* store, uint64_t key) {
  LOG_DEBUG("Attemping to find key %zu in the key/value store...", key);

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
  LOG_DEBUG("Inserted key \"%s\" into the key/value store", key);
}

bool delete_from_store(store_t* store, char* key) {
  LOG_DEBUG("Attempting to delete \"%s\" from the key/value store...", key);

  uint64_t keyhash = wyhash(key, strlen(key), 0, &store->secret[0]);
  cell_t* target = find_by_keyhash(store, keyhash);
  if (target == NULL) {
    LOG_DEBUG("The key \"%s\" was not found!", key);
    return false;
  }

  target->key = 0;
  if (target->data != NULL) {
    free(target->data);
    target->data = NULL;
  }

  size_t index = ((size_t)(target - store->cells) + 1) % store->cell_count;
  cell_t* substitute = &store->cells[index];
  if (substitute->key != 0) {
    cell_t* next;
    do {
      ++index;
      index %= store->cell_count;
      substitute = &store->cells[index];
      next = &store->cells[(index + 1) % store->cell_count];
    } while (next->key != 0);

    memcpy(target, substitute, sizeof(cell_t));
    substitute->key = 0;
    substitute->data = NULL;

    LOG_DEBUG("Re-located key %zu to compensate for deletion", substitute->key);
  }

  LOG_DEBUG("Deleted key \"%s\" from the key/value store", key);

  return true;
}

const char* get_from_store(store_t* store, char* key) {
  uint64_t keyhash = wyhash(key, strlen(key), 0, &store->secret[0]);
  cell_t* target = find_by_keyhash(store, keyhash);
  return target == NULL ? NULL : target->data;
}

