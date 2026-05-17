/*
 * vuln_demo.c — Intentionally vulnerable binary for testing BinIdentifier.
 *
 * Compile:
 *   gcc -o vuln_demo vuln_demo.c -fno-stack-protector -no-pie -z execstack
 *
 * This binary has:
 *   - No stack canary (-fno-stack-protector)
 *   - No PIE (-no-pie)
 *   - Executable stack (-z execstack)  →  NX disabled
 *   - gets() usage (classic stack overflow)
 *   - printf(user_input) (format string)
 *   - A "win" function
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void win(void) {
    printf("FLAG{you_found_the_win_function}\n");
}

void vuln(void) {
    char buf[64];

    printf("Enter your name: ");
    read(0, buf, 256);  /* Stack buffer overflow — reads up to 256 into 64-byte buf */

    printf("Hello, ");
    printf(buf);  /* Format string vulnerability */
    printf("\n");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("=== Vulnerable Demo Binary ===\n");
    vuln();
    return 0;
}
