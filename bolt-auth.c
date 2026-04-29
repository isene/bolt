/*
 * bolt-auth — privileged password verifier for the bolt screen locker.
 *
 * Reads a password from stdin (terminated by '\n' or EOF), looks up the
 * shadow entry of the *real* uid (the user who invoked us), and runs
 * crypt() to compare. Exits 0 on match, 1 on no-match or any error.
 *
 * Why a separate binary: the locker itself (bolt) is pure x86_64 asm
 * with zero libc, which would make crypt-yescrypt / sha512-crypt / pam
 * a 2k-line distraction. This file is ~50 lines of C, owned root with
 * mode 4755 (`make install` sets the suid bit). Keep it boring,
 * audit-able, and never write the password anywhere it can be paged.
 *
 * Build: cc -O2 -static bolt-auth.c -o bolt-auth -lcrypt
 *
 * Reads stdin, writes nothing, exits 0/1. No argv/env trust.
 */

#define _GNU_SOURCE
#include <crypt.h>
#include <pwd.h>
#include <shadow.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* Lock the password buffer into RAM so it never hits swap. */
#define PW_MAX 256

int main(void) {
    char password[PW_MAX];

    /* Best-effort: don't page-out the password. Ignore failures —
     * mlock requires CAP_IPC_LOCK on most systems but we're suid root
     * during this call, so it usually works. */
    mlock(password, sizeof password);

    /* Drop any leaked privileged file descriptors above stderr. */
    for (int fd = 3; fd < 64; fd++) close(fd);

    ssize_t total = 0;
    while (total < (ssize_t)(sizeof password - 1)) {
        ssize_t n = read(0, password + total, sizeof password - 1 - total);
        if (n <= 0) break;
        total += n;
    }
    if (total <= 0) {
        memset(password, 0, sizeof password);
        return 1;
    }
    password[total] = '\0';
    /* Strip trailing newline if present. */
    if (total > 0 && password[total - 1] == '\n') {
        password[total - 1] = '\0';
        total--;
    }

    struct passwd *pw = getpwuid(getuid());
    if (!pw) {
        memset(password, 0, sizeof password);
        return 1;
    }

    struct spwd *sp = getspnam(pw->pw_name);
    if (!sp || !sp->sp_pwdp) {
        memset(password, 0, sizeof password);
        return 1;
    }

    char *enc = crypt(password, sp->sp_pwdp);
    /* Zero the password buffer the moment we no longer need the
     * cleartext, even before we know the verdict. */
    memset(password, 0, sizeof password);

    if (!enc) return 1;
    /* Constant-time-ish compare: we don't have a true CT memcmp here,
     * but the shadow hash is the same length on every iteration of a
     * given algorithm, so strcmp's early-out is bounded by the hash
     * length, not by user input. Good enough for a console attacker.
     */
    if (strcmp(enc, sp->sp_pwdp) != 0) return 1;
    return 0;
}
