/* Non-forced unmounts of explicit rescue mount points, in RAM only. */
extern int sysctlbyname(const char *, void *, unsigned int *, void *, unsigned int);
extern int strcmp(const char *, const char *);
extern char *strstr(const char *, const char *);
extern int unmount(const char *, int);
extern void perror(const char *);

int main(int argc, char **argv) {
    char build[32] = {0}, args[1024] = {0};
    unsigned int build_size = sizeof(build) - 1, args_size = sizeof(args) - 1;
    if (argc != 2 ||
        sysctlbyname("kern.osversion", build, &build_size, 0, 0) ||
        sysctlbyname("kern.bootargs", args, &args_size, 0, 0) ||
        (strcmp(build, "12H321") && strcmp(build, "10B329"))) return 90;
    char *root = strstr(args, "rd=md0");
    if (!root || (root != args && root[-1] != ' ') ||
        (root[6] && root[6] != ' ')) return 90;
    const char *allowed[] = {"/mnt1", "/mnt2", "/mnt3", "/mnt4", "/mnt1/private/var"};
    int permitted = 0;
    for (unsigned int i = 0; i < sizeof(allowed)/sizeof(allowed[0]); i++)
        if (!strcmp(argv[1], allowed[i])) permitted = 1;
    if (!permitted) return 91;
    if (unmount(argv[1], 0)) { perror("unmount"); return 1; }
    return 0;
}
