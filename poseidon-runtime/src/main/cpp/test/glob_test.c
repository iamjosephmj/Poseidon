/* Requires a host C toolchain (gcc/clang) or on-device NDK run — cannot be compiled
   in environments with only an Android NDK cross-compiler and no host CRT/glibc-dev. */
#include <stdio.h>
#include <string.h>
#include "../host_match.h"

int main(int argc, char** argv) {
    FILE* f = fopen(argc > 1 ? argv[1] : "glob_vectors.txt", "r");
    if (!f) { perror("open vectors"); return 2; }
    char line[512]; int failures = 0;
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char* nl = strchr(line, '\n'); if (nl) *nl = 0;
        char* pat = strtok(line, "|");
        char* val = strtok(NULL, "|");
        char* exp = strtok(NULL, "|");
        if (!pat || !val || !exp) continue;
        int got = poseidon_host_match(pat, val) ? 1 : 0;
        if (got != (exp[0] - '0')) { printf("MISMATCH %s|%s exp=%s got=%d\n", pat, val, exp, got); failures++; }
    }
    fclose(f);
    printf(failures ? "FAIL %d\n" : "OK\n", failures);
    return failures ? 1 : 0;
}
