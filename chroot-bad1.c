/*PLOVER:CP.UPATH.ELEMENT*/

/*
Description: A chroot() is performed without a chdir().
Keywords: Size0 Complex0 Api Chroot
*/

#include <fcntl.h>
#include <unistd.h>

#define DIR	"/tmp"
#define FILE	"/etc/passwd"



void test(char *str)
{
	int fd;
	if(chroot(DIR) < 0)
		return;
	fd = open(FILE, O_RDONLY);		/* BAD */
	if(fd >= 0) {
		if(close(fd) < 0)
			;
	}
}

int main(int argc, char **argv)
{
	char *userstr;
	if(argc > 1) {
		userstr = argv[1];
		test(userstr);
	}
	return 0;
}
