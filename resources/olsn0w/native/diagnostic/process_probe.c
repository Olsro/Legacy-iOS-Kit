#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/arm/thread_status.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

struct boot_identity { long seconds; int microseconds; };

static int release_services(void) {
    struct boot_identity boot = {0, 0};
    size_t size = sizeof(boot);
    if (sysctlbyname("kern.boottime", &boot, &size, 0, 0) ||
        size != sizeof(boot)) {
        perror("kern.boottime");
        return 70;
    }
    int fd = open("/var/run/olsn0w-services-ready",
                  O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror("olsn0w-services-ready");
        return 71;
    }
    ssize_t count = write(fd, &boot, sizeof(boot));
    close(fd);
    printf("released boot=%ld.%06d bytes=%ld\n", boot.seconds,
           boot.microseconds, (long)count);
    return count == sizeof(boot) ? 0 : 72;
}

static void dump_words(task_t task, vm_address_t address,
                       vm_size_t byte_count) {
    uint32_t words[128] = {0};
    if (byte_count > sizeof(words)) byte_count = sizeof(words);
    vm_size_t copied = 0;
    kern_return_t status = vm_read_overwrite(
        task, address, byte_count, (vm_address_t)words, &copied);
    printf("memory=0x%08x requested=%u copied=%u status=%d\n",
           address, byte_count, copied, status);
    if (status != KERN_SUCCESS) return;
    for (vm_size_t i = 0; i + sizeof(uint32_t) <= copied;
         i += sizeof(uint32_t)) {
        printf("  0x%08x: 0x%08x\n", address + i,
               words[i / sizeof(uint32_t)]);
    }
}

static const char *run_state_name(int state) {
    switch (state) {
        case TH_STATE_RUNNING: return "running";
        case TH_STATE_STOPPED: return "stopped";
        case TH_STATE_WAITING: return "waiting";
        case TH_STATE_UNINTERRUPTIBLE: return "uninterruptible";
        case TH_STATE_HALTED: return "halted";
        default: return "unknown";
    }
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--release-services"))
        return release_services();
    if (argc != 2) {
        fprintf(stderr, "usage: process_probe PID | --release-services\n");
        return 64;
    }
    char *end = 0;
    long selected = strtol(argv[1], &end, 10);
    if (!end || *end || selected <= 0 || selected > 999999) return 64;

    task_t task = MACH_PORT_NULL;
    kern_return_t status = task_for_pid(mach_task_self(), (int)selected, &task);
    if (status != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid=%d errno=%d\n", status, errno);
        return 65;
    }
    thread_act_array_t threads = 0;
    mach_msg_type_number_t count = 0;
    status = task_threads(task, &threads, &count);
    if (status != KERN_SUCCESS) {
        fprintf(stderr, "task_threads=%d\n", status);
        return 66;
    }
    printf("pid=%ld task=0x%x threads=%u\n", selected, task, count);
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        arm_thread_state_t arm = {0};
        mach_msg_type_number_t arm_count = ARM_THREAD_STATE_COUNT;
        thread_basic_info_data_t basic = {0};
        mach_msg_type_number_t basic_count = THREAD_BASIC_INFO_COUNT;
        kern_return_t a = thread_get_state(threads[i], ARM_THREAD_STATE,
                                            (thread_state_t)&arm, &arm_count);
        kern_return_t b = thread_info(threads[i], THREAD_BASIC_INFO,
                                      (thread_info_t)&basic, &basic_count);
        printf("thread[%u]=0x%x arm=%d basic=%d state=%s flags=0x%x "
               "pc=0x%08x lr=0x%08x sp=0x%08x cpsr=0x%08x "
               "r0=0x%08x r1=0x%08x r2=0x%08x r3=0x%08x "
               "r4=0x%08x r5=0x%08x r6=0x%08x r7=0x%08x "
               "r8=0x%08x r9=0x%08x r10=0x%08x r11=0x%08x r12=0x%08x\n",
               i, threads[i], a, b, run_state_name(basic.run_state), basic.flags,
               arm.__pc, arm.__lr, arm.__sp, arm.__cpsr,
               arm.__r[0], arm.__r[1], arm.__r[2], arm.__r[3],
               arm.__r[4], arm.__r[5], arm.__r[6], arm.__r[7],
               arm.__r[8], arm.__r[9], arm.__r[10], arm.__r[11], arm.__r[12]);
        if (a == KERN_SUCCESS) dump_words(task, arm.__sp, 256);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads,
                  count * sizeof(thread_t));
    mach_port_deallocate(mach_task_self(), task);
    return 0;
}
