/* Diagnostic only: set/read class D on a caller-created test path. */
extern int open(const char *, int, ...), close(int), fcntl(int, int, ...);
extern int printf(const char *, ...);

#define O_RDONLY 0
#define O_RDWR 2
#define O_CREAT 0x0200
#define O_TRUNC 0x0400
#define F_GETPROTECTIONCLASS 63
#define F_SETPROTECTIONCLASS 64

int main(int argc, char **argv) {
    if (argc != 3 || (argv[1][0] != 'd' && argv[1][0] != 'f') || argv[1][1])
        return 2;
    int flags = argv[1][0] == 'd' ? O_RDONLY : O_RDWR | O_CREAT | O_TRUNC;
    int fd = open(argv[2], flags, 0600);
    if (fd < 0) { printf("open failed\n"); return 3; }
    int before = fcntl(fd, F_GETPROTECTIONCLASS);
    int changed = fcntl(fd, F_SETPROTECTIONCLASS, 4);
    int after = fcntl(fd, F_GETPROTECTIONCLASS);
    printf("class before=%d set=%d after=%d\n", before, changed, after);
    close(fd);
    return changed == 0 && after == 4 ? 0 : 4;
}
