/*
 * Linux Process Resource Monitor
 * ------------------------------
 * Shows PID, name, state, parent PID, CPU usage and memory usage for the
 * running processes by reading the /proc filesystem. The user can search,
 * view details, refresh the list, and send SIGTERM to a permitted process.
 *
 * Build:  gcc process_monitor.c -o process_monitor
 * Run:    ./process_monitor
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <time.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_PROCS     4096     /* most processes we can hold in memory     */
#define DISPLAY_LIMIT 30       /* rows shown in the table                  */
#define SAMPLE_USEC   500000   /* CPU is measured over 0.5 seconds         */
#define MAX_PID       4194304  /* largest PID Linux allows by default      */

struct proc_info {
    int           pid;
    int           ppid;       /* parent PID                      */
    char          name[64];
    char          state;      /* R, S, D, Z, T ...               */
    unsigned long ticks;      /* CPU time used (utime + stime)   */
    long          threads;
    long          rss_kb;     /* memory in use, in kB            */
    double        cpu;        /* CPU percentage                  */
    unsigned      uid;        /* owner's user ID (-1 = unknown)  */
};

static struct proc_info procs[MAX_PROCS];   /* current list                */
static int prev_pids[MAX_PROCS];            /* PIDs from the previous list */
static int prev_count = -1;                 /* -1 = no list loaded yet     */

/* =====================================================================
 *  Helpers: reading files and user input (with error handling)
 * ===================================================================== */

/* Reads a whole small file into buf. Returns bytes read, or -1 with errno set. */
static ssize_t read_file(const char *path, char *buf, size_t size)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    ssize_t n = read(fd, buf, size - 1);
    int saved = errno;                 /* close() could overwrite errno */
    close(fd);
    if (n < 0) {
        errno = saved;
        return -1;
    }
    buf[n] = '\0';
    return n;
}

static int is_number(const char *s)
{
    if (*s == '\0')
        return 0;
    for (; *s; s++)
        if (!isdigit((unsigned char)*s))
            return 0;
    return 1;
}

static const char *state_text(char s)
{
    switch (s) {
    case 'R': return "Running";
    case 'S': return "Sleeping";
    case 'D': return "Disk wait";
    case 'Z': return "Zombie";
    case 'T': return "Stopped";
    case 't': return "Traced";
    case 'I': return "Idle";
    case 'X': return "Dead";
    default:  return "Unknown";
    }
}

/* Shows a prompt and reads one line. Returns 0 on success, -1 on EOF (Ctrl+D). */
static int read_line(const char *prompt, char *buf, size_t size)
{
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buf, size, stdin))
        return -1;

    char *nl = strchr(buf, '\n');
    if (nl)
        *nl = '\0';
    else {                              /* line was too long: throw away the rest */
        int c;
        while ((c = getchar()) != '\n' && c != EOF)
            ;
    }
    return 0;
}

/* Reads a whole number. Returns 1 = ok, 0 = not a valid number, -1 = EOF. */
static int read_long(const char *prompt, long *out)
{
    char buf[64], *end;
    if (read_line(prompt, buf, sizeof buf) < 0)
        return -1;

    errno = 0;
    long v = strtol(buf, &end, 10);
    if (end == buf || errno != 0)       /* no digits, or number too big */
        return 0;
    while (isspace((unsigned char)*end))
        end++;
    if (*end != '\0')                   /* extra characters like "12abc" */
        return 0;

    *out = v;
    return 1;
}

/* Asks for a PID and checks it. Returns 1 if the PID is usable, else prints why and returns 0. */
static int ask_pid(const char *prompt, int *pid)
{
    long v;
    int r = read_long(prompt, &v);

    if (r < 0)
        return 0;                       /* EOF: main() will exit on its next read */
    if (r == 0) {
        printf("\nInvalid PID: enter a whole number using digits only.\n");
        return 0;
    }
    if (v < 1 || v > MAX_PID) {
        printf("\nInvalid PID: it must be between 1 and %d.\n", MAX_PID);
        return 0;
    }
    *pid = (int)v;
    return 1;
}

static void pause_for_enter(void)
{
    char buf[16];
    read_line("\nPress Enter to continue...", buf, sizeof buf);
}

/* Turns an error code into a clear message about one process. */
static void print_proc_error(int pid, int err)
{
    switch (err) {
    case ENOENT:
    case ESRCH:
        printf("Process %d does not exist (it may have just exited).\n", pid);
        break;
    case EACCES:
    case EPERM:
        printf("Permission denied: you are not allowed to read process %d.\n", pid);
        break;
    case EINVAL:
        printf("Could not understand the /proc data of process %d (unexpected format).\n", pid);
        break;
    default:
        printf("Cannot read process %d: %s\n", pid, strerror(err));
    }
}

/* =====================================================================
 *  Reading process information from /proc
 * ===================================================================== */

/* Fills p using /proc/<pid>/stat and /proc/<pid>/status.
   Returns 0 on success, otherwise an error code (ENOENT, EACCES, EINVAL ...). */
static int read_proc(int pid, struct proc_info *p)
{
    char path[64], buf[4096], status[8192];

    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    ssize_t n = read_file(path, buf, sizeof buf);
    if (n < 0)
        return errno;                   /* process gone, or no permission */
    if (n == 0)
        return ENOENT;

    /* The name is inside ( ) and may contain spaces or ')' itself,
       so we look for the first '(' and the LAST ')'. */
    char *lp = strchr(buf, '(');
    char *rp = strrchr(buf, ')');
    if (!lp || !rp || rp < lp)
        return EINVAL;

    size_t len = (size_t)(rp - lp - 1);
    if (len >= sizeof p->name)
        len = sizeof p->name - 1;
    memcpy(p->name, lp + 1, len);
    p->name[len] = '\0';

    unsigned long ut, st;
    long threads;
    /* fields after the name: state ppid pgrp session tty tpgid flags minflt
       cminflt majflt cmajflt utime stime cutime cstime priority nice threads */
    if (sscanf(rp + 2,
               "%c %d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu %*d %*d %*d %*d %ld",
               &p->state, &p->ppid, &ut, &st, &threads) < 5)
        return EINVAL;

    p->pid     = pid;
    p->ticks   = ut + st;
    p->threads = threads;
    p->cpu     = 0.0;
    p->rss_kb  = 0;
    p->uid     = (unsigned)-1;          /* unknown until we read it */

    /* Memory and owner come from the status file.
       Memory is optional: kernel threads have no VmRSS line. */
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    if (read_file(path, status, sizeof status) > 0) {
        char *m = strstr(status, "VmRSS:");
        if (m)
            sscanf(m, "VmRSS: %ld", &p->rss_kb);
        m = strstr(status, "Uid:");
        if (m)
            sscanf(m, "Uid: %u", &p->uid);
    }
    return 0;
}

/* Goes through /proc and reads every numeric folder (each one is a process).
   Returns the number of processes read, or -1 if /proc cannot be opened. */
static int snapshot(struct proc_info *list, int max)
{
    DIR *d = opendir("/proc");
    if (!d) {
        printf("Error: cannot open /proc (%s).\n", strerror(errno));
        printf("This program only works on Linux.\n");
        return -1;
    }

    struct dirent *e;
    int n = 0, truncated = 0;

    while (1) {
        errno = 0;                      /* so we can tell "end" from "error" */
        e = readdir(d);
        if (!e)
            break;
        if (!is_number(e->d_name))
            continue;
        if (n >= max) {
            truncated = 1;
            break;
        }
        if (read_proc(atoi(e->d_name), &list[n]) == 0)
            n++;                        /* skip any process that exited mid-scan */
    }

    if (errno != 0)
        printf("Warning: error while reading /proc: %s\n", strerror(errno));
    closedir(d);
    if (truncated)
        printf("Warning: more than %d processes found; the list was cut short.\n", max);
    return n;
}

/* Reads the CPU time again after a short wait; the difference gives CPU %. */
static void measure_cpu(struct proc_info *list, int n)
{
    struct timespec t0, t1;
    long hz = sysconf(_SC_CLK_TCK);

    if (clock_gettime(CLOCK_MONOTONIC, &t0) != 0 || hz <= 0) {
        for (int i = 0; i < n; i++)
            list[i].cpu = 0.0;
        printf("Warning: could not measure CPU usage (%s).\n", strerror(errno));
        return;
    }
    usleep(SAMPLE_USEC);
    if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0) {
        for (int i = 0; i < n; i++)
            list[i].cpu = 0.0;
        return;
    }

    double dt = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    for (int i = 0; i < n; i++) {
        struct proc_info q;
        if (dt > 0 && read_proc(list[i].pid, &q) == 0 && q.ticks >= list[i].ticks) {
            list[i].cpu    = (double)(q.ticks - list[i].ticks) / (hz * dt) * 100.0;
            list[i].rss_kb = q.rss_kb;
            list[i].state  = q.state;
        } else {
            list[i].cpu = 0.0;          /* process ended during the 0.5 s wait */
        }
    }
}

/* =====================================================================
 *  Showing the table
 * ===================================================================== */

static int cmp_cpu_then_mem(const void *a, const void *b)
{
    const struct proc_info *x = a, *y = b;
    if (x->cpu != y->cpu)
        return (y->cpu > x->cpu) ? 1 : -1;
    if (x->rss_kb != y->rss_kb)
        return (y->rss_kb > x->rss_kb) ? 1 : -1;
    return x->pid - y->pid;
}

/* Turns a user ID into a name like "root" or "boomika". */
static const char *user_name(unsigned uid, char *buf, size_t size)
{
    if (uid == (unsigned)-1) {
        snprintf(buf, size, "?");
        return buf;
    }
    struct passwd *pw = getpwuid(uid);
    if (pw)
        snprintf(buf, size, "%s", pw->pw_name);
    else
        snprintf(buf, size, "%u", uid);     /* no name found: show the number */
    return buf;
}

static void print_header(void)
{
    printf("%-7s %-7s %-10s %-22s %-6s %7s %11s\n",
           "PID", "PPID", "USER", "NAME", "STATE", "CPU%", "MEM (MB)");
    printf("------------------------------------------------------------------------------\n");
}

static void print_row(const struct proc_info *p)
{
    char user[32];
    printf("%-7d %-7d %-10.10s %-22.22s %-6c %6.1f%% %11.1f\n",
           p->pid, p->ppid, user_name(p->uid, user, sizeof user),
           p->name, p->state, p->cpu, p->rss_kb / 1024.0);
}

/* Reads /proc, measures CPU, sorts. Returns the count, or -1 on error. */
static int load_process_list(void)
{
    int n = snapshot(procs, MAX_PROCS);
    if (n < 0)
        return -1;
    if (n == 0) {
        printf("No processes could be read.\n");
        return -1;
    }
    measure_cpu(procs, n);
    qsort(procs, n, sizeof procs[0], cmp_cpu_then_mem);
    return n;
}

static void print_table(int n)
{
    print_header();
    for (int i = 0; i < n && i < DISPLAY_LIMIT; i++)
        print_row(&procs[i]);
    printf("\nShowing top %d of %d processes (sorted by CPU, then memory).\n",
           n < DISPLAY_LIMIT ? n : DISPLAY_LIMIT, n);
}

/* Saves the PIDs so the next refresh can tell what changed. */
static void remember_pids(int n)
{
    for (int i = 0; i < n; i++)
        prev_pids[i] = procs[i].pid;
    prev_count = n;
}

/* Option 1 */
static void display_processes(void)
{
    printf("\nReading /proc and sampling CPU usage...\n\n");
    int n = load_process_list();
    if (n < 0)
        return;
    print_table(n);
    remember_pids(n);
}

/* Option 4: reload everything and report what changed since the last list. */
static void refresh_process_list(void)
{
    if (prev_count < 0) {
        printf("\nNo earlier list to compare with. Loading a fresh list instead.\n");
        display_processes();
        return;
    }

    printf("\nRefreshing process list...\n\n");
    int n = load_process_list();
    if (n < 0)
        return;
    print_table(n);

    int added = 0, ended = 0;
    for (int i = 0; i < n; i++) {
        int found = 0;
        for (int j = 0; j < prev_count; j++)
            if (prev_pids[j] == procs[i].pid) { found = 1; break; }
        if (!found)
            added++;
    }
    for (int j = 0; j < prev_count; j++) {
        int found = 0;
        for (int i = 0; i < n; i++)
            if (procs[i].pid == prev_pids[j]) { found = 1; break; }
        if (!found)
            ended++;
    }
    printf("Since the last list: %d new process(es), %d process(es) ended.\n", added, ended);
    remember_pids(n);
}

/* =====================================================================
 *  Search and details
 * ===================================================================== */

static void search_by_pid(void)
{
    int pid;
    if (!ask_pid("Enter PID: ", &pid))
        return;

    struct proc_info p;
    int err = read_proc(pid, &p);
    if (err) {
        printf("\n");
        print_proc_error(pid, err);
        return;
    }
    measure_cpu(&p, 1);
    printf("\n");
    print_header();
    print_row(&p);
}

static void search_by_name(void)
{
    char term[64];
    if (read_line("Enter process name (or part of it): ", term, sizeof term) < 0)
        return;
    if (term[0] == '\0') {
        printf("\nSearch term is empty. Please type a name.\n");
        return;
    }

    int n = snapshot(procs, MAX_PROCS);
    if (n < 0)
        return;
    measure_cpu(procs, n);

    int found = 0;
    printf("\n");
    for (int i = 0; i < n; i++) {
        if (strcasestr(procs[i].name, term)) {      /* ignores upper/lower case */
            if (!found)
                print_header();
            print_row(&procs[i]);
            found++;
        }
    }
    if (found == 0)
        printf("No process matching \"%s\" was found.\n", term);
    else
        printf("\n%d match(es) found.\n", found);
}

/* Option 2 */
static void search_process(void)
{
    long choice;
    printf("\n  1. Search by PID\n");
    printf("  2. Search by name\n");
    int r = read_long("Choose: ", &choice);
    if (r < 0)
        return;
    if (r == 0 || (choice != 1 && choice != 2)) {
        printf("\nInvalid option. Please choose 1 or 2.\n");
        return;
    }
    if (choice == 1)
        search_by_pid();
    else
        search_by_name();
}

/* Option 3: everything we know about one process. */
static void view_details(void)
{
    int pid;
    if (!ask_pid("\nEnter PID: ", &pid))
        return;

    struct proc_info p;
    int err = read_proc(pid, &p);
    if (err) {
        printf("\n");
        print_proc_error(pid, err);
        return;
    }
    measure_cpu(&p, 1);

    char path[64], status[8192], cmd[1024];
    long vmsize = 0;
    unsigned uid = 0;
    int have_vm = 0, have_uid = 0;

    snprintf(path, sizeof path, "/proc/%d/status", pid);
    if (read_file(path, status, sizeof status) > 0) {
        char *m = strstr(status, "VmSize:");
        if (m && sscanf(m, "VmSize: %ld", &vmsize) == 1)
            have_vm = 1;
        m = strstr(status, "Uid:");
        if (m && sscanf(m, "Uid: %u", &uid) == 1)
            have_uid = 1;
    }

    /* /proc/<pid>/cmdline holds the command, with 0-bytes between words */
    snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
    ssize_t n = read_file(path, cmd, sizeof cmd);
    if (n > 0) {
        for (ssize_t i = 0; i < n - 1; i++)
            if (cmd[i] == '\0')
                cmd[i] = ' ';
    } else if (n == 0) {
        snprintf(cmd, sizeof cmd, "(none - kernel thread or zombie)");
    } else {
        snprintf(cmd, sizeof cmd, "(cannot read: %s)", strerror(errno));
    }

    printf("\n========== Process %d ==========\n", pid);
    printf("Name           : %s\n", p.name);
    printf("State          : %c (%s)\n", p.state, state_text(p.state));
    printf("Parent PID     : %d\n", p.ppid);
    printf("Threads        : %ld\n", p.threads);
    printf("CPU usage      : %.1f%%\n", p.cpu);
    printf("Resident mem   : %.1f MB\n", p.rss_kb / 1024.0);
    if (have_vm)
        printf("Virtual mem    : %.1f MB\n", vmsize / 1024.0);
    else
        printf("Virtual mem    : (not available)\n");
    if (have_uid) {
        struct passwd *pw = getpwuid(uid);
        printf("Owner          : %s (uid %u)\n", pw ? pw->pw_name : "unknown", uid);
    } else {
        printf("Owner          : (not available)\n");
    }
    printf("Command line   : %s\n", cmd);
}

/* =====================================================================
 *  Sending SIGTERM
 * ===================================================================== */

/* Option 5 */
static void terminate_process(void)
{
    int pid;
    if (!ask_pid("\nEnter PID to send SIGTERM to: ", &pid))
        return;

    /* Safety checks: never signal these */
    if (pid == 1) {
        printf("\nRefused: PID 1 is the init/systemd process.\n");
        return;
    }
    if (pid == (int)getpid()) {
        printf("\nRefused: that is this monitor program itself.\n");
        return;
    }
    if (pid == (int)getppid()) {
        printf("\nRefused: that is the shell that started this program.\n");
        return;
    }

    /* Signal 0 sends nothing; it only checks that the process exists
       and that we are allowed to signal it. */
    if (kill((pid_t)pid, 0) == -1) {
        if (errno == ESRCH)
            printf("\nNo such process: %d\n", pid);
        else if (errno == EPERM)
            printf("\nPermission denied: process %d belongs to another user.\n", pid);
        else
            printf("\nCannot access process %d: %s\n", pid, strerror(errno));
        return;
    }

    struct proc_info p;
    if (read_proc(pid, &p) == 0) {
        char owner[32];
        printf("\nTarget: PID %d (%s), owned by %s\n",
               pid, p.name, user_name(p.uid, owner, sizeof owner));
        if (p.state == 'Z') {
            printf("This process is a zombie: it has already finished.\n");
            printf("SIGTERM has no effect on it; its parent must collect it.\n");
            return;
        }
    }

    char answer[16];
    if (read_line("Send SIGTERM? (y/N): ", answer, sizeof answer) < 0 ||
        (answer[0] != 'y' && answer[0] != 'Y')) {
        printf("Cancelled. No signal was sent.\n");
        return;
    }

    /* A child process sends the signal; the parent waits for the result. */
    pid_t child = fork();
    if (child < 0) {
        printf("Error: could not create a child process (%s).\n", strerror(errno));
        return;
    }
    if (child == 0) {
        if (kill((pid_t)pid, SIGTERM) == 0)
            _exit(0);
        _exit(errno & 0xFF);            /* pass the error code to the parent */
    }

    int status;
    if (waitpid(child, &status, 0) < 0) {
        printf("Error: waiting for the child process failed (%s).\n", strerror(errno));
        return;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        printf("SIGTERM sent to process %d.\n", pid);
        sleep(1);                       /* give it a moment to react */
        if (kill((pid_t)pid, 0) == -1 && errno == ESRCH)
            printf("Process %d has terminated.\n", pid);
        else
            printf("Process %d is still running (it may be handling or ignoring SIGTERM).\n", pid);
    } else if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == ESRCH)
            printf("Failed: process %d ended before the signal arrived.\n", pid);
        else if (code == EPERM)
            printf("Failed: permission denied for process %d.\n", pid);
        else
            printf("Failed to send signal: %s\n", strerror(code));
    } else {
        printf("Error: the signal-sending child ended abnormally.\n");
    }
}

/* =====================================================================
 *  Main menu
 * ===================================================================== */

int main(void)
{
    long choice;

    while (1) {
        printf("\n============================================\n");
        printf("       LINUX PROCESS RESOURCE MONITOR\n");
        printf("============================================\n");
        printf("1. Display Processes\n");
        printf("2. Search Process (by PID or name)\n");
        printf("3. View Detailed Process Info\n");
        printf("4. Refresh Process List\n");
        printf("5. Send SIGTERM to Process\n");
        printf("6. Exit\n");
        printf("--------------------------------------------\n");

        int r = read_long("Enter your choice: ", &choice);
        if (r < 0) {                    /* EOF (Ctrl+D) */
            printf("\nExiting Process Monitor...\n");
            return 0;
        }
        if (r == 0) {
            printf("\nInvalid input. Please enter a number from 1 to 6.\n");
            continue;
        }

        switch (choice) {
        case 1:
            display_processes();
            break;
        case 2:
            search_process();
            break;
        case 3:
            view_details();
            break;
        case 4:
            refresh_process_list();
            break;
        case 5:
            terminate_process();
            break;
        case 6:
            printf("\nExiting Process Monitor...\n");
            return 0;
        default:
            printf("\nInvalid choice. Please enter a number from 1 to 6.\n");
            continue;
        }
        pause_for_enter();
    }
}
