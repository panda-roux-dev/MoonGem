#include "store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"

#define KEY_MAX_LENGTH 24
#define KEY_MIN_LENGTH 3

#define DATA_MAX_LENGTH 512
#define DATA_MIN_LENGTH 3

#define TEST_COUNT 14

static const char VALID_CHARS[] = "abcdefghijklmnopqrstuvwxyz1234567890";

int main(void) {
  srand(time(NULL));
  store_t *store = create_store(INITIAL_STORE_SIZE);
  for (int i = 0; i < TEST_COUNT; ++i) {
    size_t entries = 1 << i;
    LOG("Inserting, fetching, and deleting %zu entries", entries);

    // build random key/value tables
    char **keys = malloc(entries * sizeof(char *));
    char **data = malloc(entries * sizeof(char *));
    for (size_t j = 0; j < entries; ++j) {
      char key[64];
      sprintf(&key[0], "key_%d_%zu", i, j);
      keys[j] = strdup(&key[0]);

      size_t data_len = (rand() % DATA_MAX_LENGTH) + DATA_MIN_LENGTH;
      data[j] = calloc(data_len, sizeof(char));
      for (size_t k = 0; k < data_len - 1; ++k) {
        data[j][k] = VALID_CHARS[rand() % sizeof(VALID_CHARS)];
      }
    }

    // create a store and insert everything into it
    for (int j = 0; j < entries; ++j) {
      insert_into_store(store, keys[j], data[j]);
    }

    // read everything and ensure it matches
    for (int j = 0; j < entries; ++j) {
      const char *retrieved = get_from_store(store, keys[j]);
      if (retrieved == NULL) {
        LOG_ERROR("Failed to fetch value for key %s", keys[j]);
        exit(EXIT_FAILURE);
      } else if (strcmp(retrieved, data[j]) != 0) {
        LOG_ERROR(
            "Invalid result fetched for key %s.  Expected \"%s\", but found "
            "\"%s\"",
            keys[j], data[j], retrieved);
        exit(EXIT_FAILURE);
        break;
      }
    }

    // delete everything
    for (int j = 0; j < entries; ++j) {
      if (!delete_from_store(store, keys[j])) {
        LOG_ERROR("Failed to delete key %s", keys[j]);
        exit(EXIT_FAILURE);
      }
    }

    for (int j = 0; j < entries; ++j) {
      free(keys[j]);
      free(data[j]);
    }

    free(keys);
    free(data);
  }

  destroy_store(store);

  return EXIT_SUCCESS;
}
