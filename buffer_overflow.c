#include <stddef.h>
#include <stdio.h>
#include <string.h>

struct Session {
  char name[16];
  unsigned int access_flag;
  char padding[4];
};

/* Keep the teaching example's layout explicit. */
_Static_assert(offsetof(struct Session, access_flag) == 16,
               "This demo needs the access flag directly after the buffer.");
_Static_assert(sizeof(unsigned int) == 4 && sizeof(struct Session) == 24,
               "This demo needs a four-byte unsigned int and a 24-byte struct.");

void copy_unchecked(struct Session *session, const char *input,
                    size_t input_length) {
  /* Intentional bug: the loop can write past the 16-byte name buffer. */
  for (size_t i = 0; i <= input_length; i++) {
    session->name[i] = input[i];
  }
}

int main(int argc, char **argv) {
  if (argc != 3 || (strcmp(argv[1], "vulnerable") != 0 &&
                    strcmp(argv[1], "fixed") != 0)) {
    fprintf(stderr, "Usage: %s vulnerable|fixed TEXT\n", argv[0]);
    return 1;
  }

  struct Session session = {0}; /* Local variable stored on the stack. */
  size_t input_length = strlen(argv[2]);
  printf("MODE=%s\nINPUT_BYTES=%zu\nACCESS_BEFORE=%u\n", argv[1],
         input_length, session.access_flag);

  if (strcmp(argv[1], "fixed") == 0) {
    if (input_length >= sizeof(session.name)) {
      puts("ACCESS_AFTER=0\nRESULT=REJECTED");
      return 0;
    }
    memcpy(session.name, argv[2], input_length + 1);
  } else {
    /* Lab limit: reserve space inside the struct for the final zero byte.
       The copy below STILL overflows the name member and is undefined C. */
    if (input_length >= sizeof(session)) {
      puts("ACCESS_AFTER=0\nRESULT=DEMO_LIMIT");
      return 0;
    }
    copy_unchecked(&session, argv[2], input_length);
  }

  printf("ACCESS_AFTER=%u\nRESULT=%s\n", session.access_flag,
         session.access_flag != 0 ? "GRANTED" : "DENIED");
  return 0;
}
