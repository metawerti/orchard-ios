#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int pipe2(int pipefd[2], int flags)
{
    const int supported = O_CLOEXEC | O_NONBLOCK;

    if (flags & ~supported) {
        errno = EINVAL;
        return -1;
    }

    if (pipe(pipefd) < 0) {
        return -1;
    }

    for (int i = 0; i < 2; i++) {
        if (flags & O_CLOEXEC) {
            int fdflags = fcntl(pipefd[i], F_GETFD);
            if (fdflags < 0 ||
                fcntl(pipefd[i], F_SETFD, fdflags | FD_CLOEXEC) < 0) {
                goto fail;
            }
        }

        if (flags & O_NONBLOCK) {
            int flflags = fcntl(pipefd[i], F_GETFL);
            if (flflags < 0 ||
                fcntl(pipefd[i], F_SETFL, flflags | O_NONBLOCK) < 0) {
                goto fail;
            }
        }
    }

    return 0;

fail:
    {
        int saved_errno = errno;
        close(pipefd[0]);
        close(pipefd[1]);
        errno = saved_errno;
        return -1;
    }
}
