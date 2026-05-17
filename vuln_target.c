/* Setuid target that opens /etc/shadow before dropping. Install as
 * setuid root; exploit with exploit_vuln_target.c. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
	fprintf(stderr, "starting vuln_target: uid=%d euid=%d argc=%d\n",
		getuid(), geteuid(), argc);

	if (geteuid() != 0) {
		fprintf(stderr,
			"failed elevating to root: euid=%d uid=%d\n",
			geteuid(), getuid());
		return 1;
	}

	int fd = open("/etc/shadow", O_RDONLY);
	if (fd < 0) { perror("open"); return 1; }
	fprintf(stderr, "opened /etc/shadow on fd %d\n", fd);

	if (setuid(getuid()) < 0) { perror("setuid"); return 1; }
	fprintf(stderr, "dropped privileges: uid=%d euid=%d\n", getuid(), geteuid());

	if (argc > 1 && !strcmp(argv[1], "exit-now"))
		return 0;
	fprintf(stderr, "entering pause()\n");
	pause();
	perror("pause");
	return 0;
}
