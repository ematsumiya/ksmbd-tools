// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *   Copyright (C) 2018 Samsung Electronics Co., Ltd.
 *   Copyright (C) 2021 SUSE LLC
 *
 *   linux-cifsd-devel@lists.sourceforge.net
 */

#include "ksmbdtools.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <signal.h>

#include "ipc.h"
#include "rpc.h"
#include "worker.h"
#include "daemon.h"
#include "config_parser.h"
#include "management/user.h"
#include "management/share.h"
#include "management/session.h"
#include "management/tree_conn.h"
#include "management/spnego.h"
#include "version.h"

int ksmbd_health_status;
static pid_t worker_pid;
static int lock_fd = -1;

typedef int (*worker_fn)(void *);

static ksmbd_daemon_cmd ksmbd_daemon_get_cmd(char *cmd)
{
	int i;

	if (!cmd)
		return KSMBD_CMD_DAEMON_NONE;

	for (i = 0; i < KSMBD_CMD_DAEMON_MAX; i++)
		if (!strcmp(cmd, ksmbd_daemon_cmds_str[i]))
			return (ksmbd_daemon_cmd)i;

	return KSMBD_CMD_DAEMON_NONE;
}

static const char *ksmbd_daemon_get_cmd_str(ksmbd_daemon_cmd cmd)
{
	if (cmd > KSMBD_CMD_DAEMON_MAX)
		return ksmbd_daemon_cmds_str[KSMBD_CMD_DAEMON_NONE];

	return ksmbd_daemon_cmds_str[(int)cmd];
}

void daemon_usage(ksmbd_daemon_cmd cmd)
{
	const char *cmd_str = ksmbd_daemon_get_cmd_str(cmd);
	int i;

	switch(cmd) {
	case KSMBD_CMD_DAEMON_START:
		pr_out("Usage: ksmbdctl daemon start [options]\n");
		pr_out("Start ksmbd userspace and kernel daemon.\n\n");
		pr_out("%-30s%s", "  -p, --port=<num>", "TCP port number to listen on\n");
		pr_out("%-30s%s", "  -c, --config=<config>", "Use specified smb.conf file\n");
		pr_out("%-30s%s", "  -u, --usersdb=<config>", "Use specified users DB file\n");
		pr_out("%-30s%s", "  -n, --nodetach", "Don't detach\n");
		pr_out("%-30s%s", "  -s, --systemd", "Start daemon in systemd service mode\n");
		pr_out("%-30s%s", "  -h, --help", "Show this help menu\n\n");
		break;
	case KSMBD_CMD_DAEMON_SHUTDOWN:
		pr_out("Usage: ksmbdctl daemon shutdown\n");
		pr_out("Shuts down the userspace daemon and the kernel server.\n\n");
		break;
	case KSMBD_CMD_DAEMON_DEBUG:
		pr_out("Usage: ksmbdctl daemon debug <type>\n");
		pr_out("Enable/disable debugging modules for ksmbd.\n\n");
		pr_out("List of available types:\n");
		for (i = 0; i < ARRAY_SIZE(debug_type_strings); i++)
			pr_out("%s ", debug_type_strings[i]);
		pr_out("\n\n");
		break;
	default:
		pr_out("Usage: ksmbdctl daemon <subcommand> <args> [options]\n");
		pr_out("ksmbd daemon management.\n\n");
		pr_out("List of available subcommands:\n");
		pr_out("%-20s%s", "start", "Start ksmbd userspace daemon\n");
		pr_out("%-20s%s", "shutdown", "Shutdown ksmbd userspace daemon\n");
		pr_out("%-20s%s", "debug", "Enable/disable debugging for ksmbd components\n\n");
		break;
	}

	exit(EXIT_FAILURE);
}

static int handle_orphaned_lock_file(void)
{
	char proc_ent[64] = { 0 };
	pid_t pid;
	int fd;

	pid = get_running_pid();
	if (pid < 0)
		return -EINVAL;

	snprintf(proc_ent, sizeof(proc_ent), "/proc/%d", pid);
	fd = open(proc_ent, O_RDONLY);
	if (fd < 0) {
		pr_info("Unlink orphaned '%s'\n", KSMBD_LOCK_FILE);
		return unlink(KSMBD_LOCK_FILE);
	}

	close(fd);
	pr_info("File '%s' belongs to pid %d\n", KSMBD_LOCK_FILE, pid);

	return -EINVAL;
}

static int create_lock_file(void)
{
	char daemon_pid[10];
	size_t len;

retry:
	lock_fd = open(KSMBD_LOCK_FILE, O_CREAT | O_EXCL | O_WRONLY,
			S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);

	if (lock_fd < 0) {
		if (handle_orphaned_lock_file())
			return -EINVAL;
		goto retry;
	}

	if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0)
		return -EINVAL;

	len = snprintf(daemon_pid, sizeof(daemon_pid), "%d", getpid());
	if (write(lock_fd, daemon_pid, len) == -1)
		pr_err("Unable to record main PID: %m\n");

	return 0;
}

/*
 * Write to file safely; by using a tmp and atomic rename.
 * Avoids a corrupt file if the write would be interrupted due
 * to a power failure.
 */
static int write_file_safe(char *path, char *buf, size_t len, int mode)
{
	int fd, ret = -1;
	char *path_tmp = g_strdup_printf("%s.tmp", path);

	if (g_file_test(path_tmp, G_FILE_TEST_EXISTS))
		unlink(path_tmp);

	fd = open(path_tmp, O_CREAT | O_EXCL | O_WRONLY, mode);
	if (fd < 0) {
		pr_err("Unable to create %s: %m\n", path_tmp);
		goto err_out;
	}

	if (write(fd, buf, len) == -1) {
		pr_err("Unable to write to %s: %m\n", path_tmp);
		close(fd);
		goto err_out;
	}

	fsync(fd);
	close(fd);

	if (rename(path_tmp, path)) {
		pr_err("Unable to rename to %s: %m\n", path);
		goto err_out;
	}
	ret = 0;

err_out:
	g_free(path_tmp);
	return ret;
}

static int create_subauth_file(void)
{
	char *subauth_buf;
	GRand *rnd;
	int ret;

	rnd = g_rand_new();
	subauth_buf = g_strdup_printf("%d:%d:%d\n",
				      g_rand_int_range(rnd, 0, INT_MAX),
				      g_rand_int_range(rnd, 0, INT_MAX),
				      g_rand_int_range(rnd, 0, INT_MAX));

	ret = write_file_safe(PATH_SUBAUTH, subauth_buf, strlen(subauth_buf),
		S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
	g_free(subauth_buf);

	return ret;
}

static int generate_sub_auth(void)
{
	int ret = -EINVAL;

retry:
	if (g_file_test(PATH_SUBAUTH, G_FILE_TEST_EXISTS))
		ret = cp_parse_subauth();

	if (ret) {
		ret = create_subauth_file();
		if (ret)
			return ret;
		goto retry;
	}

	return ret;
}

static void delete_lock_file(void)
{
	if (lock_fd == -1)
		return;

	flock(lock_fd, LOCK_UN);
	close(lock_fd);
	lock_fd = -1;
	remove(KSMBD_LOCK_FILE);
}

static int wait_group_kill(int signo)
{
	pid_t pid;
	int status;

	if (kill(worker_pid, signo) != 0)
		pr_warn("can't execute kill %d: %m\n", worker_pid);

	while (1) {
		pid = waitpid(-1, &status, 0);
		if (pid != 0) {
			pr_debug("Detected pid %d termination\n", pid);
			break;
		}
		sleep(1);
	}
	return 0;
}

static int setup_signal_handler(int signo, sighandler_t handler)
{
	int status;
	sigset_t full_set;
	struct sigaction act = {};

	sigfillset(&full_set);

	act.sa_handler = handler;
	act.sa_mask = full_set;

	status = sigaction(signo, &act, NULL);
	if (status != 0)
		pr_err("Unable to register %s signal handler: %m",
				strsignal(signo));
	return status;
}

static int setup_signals(sighandler_t handler)
{
	if (setup_signal_handler(SIGINT, handler) != 0)
		return -EINVAL;

	if (setup_signal_handler(SIGTERM, handler) != 0)
		return -EINVAL;

	if (setup_signal_handler(SIGABRT, handler) != 0)
		return -EINVAL;

	if (setup_signal_handler(SIGQUIT, handler) != 0)
		return -EINVAL;

	if (setup_signal_handler(SIGHUP, handler) != 0)
		return -EINVAL;

	return 0;
}

static int parse_configs(char *db, char *smbconf)
{
	int ret;

	ret = cp_parse_db(db);
	if (ret == -ENOENT) {
		pr_warn("User database file does not exist. "
			"Only guest sessions (if permitted) will work.\n");
	} else if (ret) {
		pr_err("Unable to parse user database %s\n", db);
		return ret;
	}

	ret = cp_parse_smbconf(smbconf);
	if (ret) {
		pr_err("Unable to parse configuration file '%s'\n", smbconf);
		return ret;
	}
	return 0;
}

static void worker_process_free(void)
{
	/*
	 * NOTE, this is the final release, we don't look at ref_count
	 * values. User management should be destroyed last.
	 */
	spnego_destroy();
	ipc_destroy();
	rpc_destroy();
	wp_destroy();
	sm_destroy();
	shm_destroy();
	usm_destroy();
}

static void child_sig_handler(int signo)
{
	static volatile int fatal_delivered = 0;

	if (signo == SIGHUP) {
		/*
		 * This is a signal handler, we can't take any locks, set
		 * a flag and wait for normal execution context to re-read
		 * the configs.
		 */
		ksmbd_health_status |= KSMBD_SHOULD_RELOAD_CONFIG;
		pr_debug("Scheduled a config reload action.\n");
		return;
	}

	pr_info("Child received signal: %d (%s)\n",
		signo, strsignal(signo));

	if (!g_atomic_int_compare_and_exchange(&fatal_delivered, 0, 1))
		return;

	ksmbd_health_status &= ~KSMBD_HEALTH_RUNNING;
	worker_process_free();
	exit(EXIT_SUCCESS);
}

static void daemon_sig_handler(int signo)
{
	/*
	 * Pass SIGHUP to worker, so it will reload configs
	 */
	if (signo == SIGHUP) {
		if (!worker_pid)
			return;

		ksmbd_health_status |= KSMBD_SHOULD_RELOAD_CONFIG;
		if (kill(worker_pid, signo))
			pr_err("Unable to send SIGHUP to %d: %m\n",
				worker_pid);
		return;
	}

	setup_signals(SIG_DFL);
	wait_group_kill(signo);
	pr_info("Exiting. Bye!\n");
	delete_lock_file();
	kill(0, SIGINT);
}

static int worker_process_init(void *data)
{
	int ret;

	setup_signals(child_sig_handler);
	set_logger_app_name("ksmbd-worker");

	ret = usm_init();
	if (ret) {
		pr_err("Failed to init user management\n");
		goto out;
	}

	ret = shm_init();
	if (ret) {
		pr_err("Failed to init net share management\n");
		goto out;
	}

	ret = parse_configs(global_conf.users_db, global_conf.smbconf);
	if (ret) {
		pr_err("Failed to parse configuration files\n");
		goto out;
	}

	ret = sm_init();
	if (ret) {
		pr_err("Failed to init user session management\n");
		goto out;
	}

	ret = wp_init();
	if (ret) {
		pr_err("Failed to init worker threads pool\n");
		goto out;
	}

	ret = rpc_init();
	if (ret) {
		pr_err("Failed to init RPC subsystem\n");
		goto out;
	}

	ret = ipc_init();
	if (ret) {
		pr_err("Failed to init IPC subsystem\n");
		goto out;
	}

	ret = spnego_init();
	if (ret) {
		pr_err("Failed to init spnego subsystem\n");
		ret = KSMBD_STATUS_IPC_FATAL_ERROR;
		goto out;
	}

	while (ksmbd_health_status & KSMBD_HEALTH_RUNNING) {
		ret = ipc_process_event();
		if (ret == -KSMBD_STATUS_IPC_FATAL_ERROR) {
			ret = KSMBD_STATUS_IPC_FATAL_ERROR;
			break;
		}
	}
out:
	worker_process_free();
	return ret;
}

static pid_t start_worker_process(worker_fn fn, void *data)
{
	int status = 0;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		pr_err("Can't fork child process: %m\n");
		return -EINVAL;
	}
	if (pid == 0) {
		status = fn(data);
		exit(status);
	}

	return pid;
}

static int daemon_process_start(void *data)
{
	int no_detach;
	/*
	 * Do not chdir() daemon()'d process to '/'.
	 */
	int nochdir = 1;

	if(prctl(PR_SET_NAME, "ksmbd-daemon\0", 0, 0, 0))
		pr_info("Can't set program name: %m\n");

	if (data)
		no_detach = *(int *)data;

	setup_signals(daemon_sig_handler);
	if (!no_detach) {
		pr_logger_init(PR_LOGGER_SYSLOG);
		if (daemon(nochdir, 0) != 0) {
			pr_err("Daemonization failed\n");
			goto out;
		}
	} else if (no_detach == 1)
		setpgid(0, 0);

	if (create_lock_file()) {
		pr_err("Failed to create lock file: %m\n");
		goto out;
	}

	if (generate_sub_auth())
		pr_debug("Failed to generate subauth for domain sid: %m\n");

	worker_pid = start_worker_process(worker_process_init, NULL);
	if (worker_pid < 0)
		goto out;

	while (1) {
		int status;
		pid_t child;

		child = waitpid(-1, &status, 0);
		if (ksmbd_health_status & KSMBD_SHOULD_RELOAD_CONFIG &&
				errno == EINTR) {
			ksmbd_health_status &= ~KSMBD_SHOULD_RELOAD_CONFIG;
			continue;
		}

		pr_warn("child process exited abnormally: %d\n", child);
		if (child == -1) {
			pr_err("waitpid() returned error code: %m\n");
			goto out;
		}

		if (WIFEXITED(status) &&
			WEXITSTATUS(status) == KSMBD_STATUS_IPC_FATAL_ERROR) {
			pr_err("Fatal IPC error. Terminating. Check dmesg.\n");
			goto out;
		}

		/* Ratelimit automatic restarts */
		sleep(1);
		worker_pid = start_worker_process(worker_process_init, NULL);
		if (worker_pid < 0)
			goto out;
	}
out:
	delete_lock_file();
	kill(0, SIGTERM);
	return 0;
}

int daemon_start_cmd(int no_detach, int systemd_service)
{
	pid_t pid;
	int ret = -EINVAL;

	/* Check if process is already running */
	pid = get_running_pid();
	if (pid > 1) {
		pr_err("ksmbd-daemon already running (%d)\n", pid);
		exit(EXIT_FAILURE);
	}

	if (!systemd_service)
		return daemon_process_start((void *)&no_detach);

	pid = start_worker_process(daemon_process_start, (void *)&no_detach);
	if (pid < 0)
		return -EINVAL;

	return 0;
}

int daemon_shutdown_cmd(void)
{
	int fd, ret;

	if (get_running_pid() == -ENOENT) {
		pr_out("Server is not running.\n");
		exit(EXIT_FAILURE);
	}

	terminate_ksmbd_daemon();

	fd = open(KSMBD_SYSFS_KILL_SERVER, O_WRONLY);
	if (fd < 0) {
		pr_debug("open failed (%d): %m\n", errno);
		return fd;
	}

	ret = write(fd, "hard", 4);
	close(fd);
	return ret;
}

int daemon_debug_cmd(char *debug_type)
{
	int i, fd, ret;
	bool valid = false;
	char buf[255] = { 0 };

	for (i = 0; i < ARRAY_SIZE(debug_type_strings); i++) {
		if (!strcmp(debug_type, debug_type_strings[i])) {
			valid = true;
			break;
		}
	}

	if (!valid)
		return -EINVAL;

	ret = fd = open(KSMBD_SYSFS_DEBUG, O_RDWR);
	if (fd < 0)
		goto err_open;

	ret = write(fd, debug_type, strlen(debug_type));
	if (ret < 0)
		goto err;

	ret = read(fd, buf, 255);
	if (ret < 0)
		goto err;

	pr_info("debug: %s\n", buf);
err:
	close(fd);
err_open:
	if (ret == -EBADF)
		pr_debug("Can't open %s. Is ksmbd kernel module loaded?\n", KSMBD_SYSFS_DEBUG);
	return ret;
}

int daemon_version_cmd(void)
{
	int fd, ret;
	char version[255] = { 0 };

	ret = fd = open(KSMBD_SYSFS_VERSION, O_RDONLY);
	if (fd < 0)
		goto err;

	ret = read(fd, version, 255);
	close(fd);

err:
	if (ret < 0)
		pr_err("%m (is kernel module loaded?)\n");
	else
		pr_out("ksmbd module version: %s\n", version);

	return ret;
}

int daemon_cmd(int argc, char *argv[])
{
	int ret = EXIT_FAILURE;
	int no_detach = 0;
	int systemd_service = 0;
	char *debug_type;
	const char *cmd_str;
	ksmbd_daemon_cmd cmd = KSMBD_CMD_DAEMON_NONE;
	int c, i;

	if (argc < 2)
		goto usage;

	set_logger_app_name("ksmbd-daemon");

	cmd = ksmbd_daemon_get_cmd(argv[1]);
	cmd_str = ksmbd_daemon_get_cmd_str(cmd);

	if (cmd == KSMBD_CMD_DAEMON_NONE)
		goto usage;

	if (cmd == KSMBD_CMD_DAEMON_VERSION ||
	    cmd == KSMBD_CMD_DAEMON_SHUTDOWN)
		goto skip_opts;

	if (cmd == KSMBD_CMD_DAEMON_DEBUG) {
		if (argc == 2)
			goto usage;

		debug_type = strdup(argv[2]);

		ret = daemon_debug_cmd(debug_type);
		if (ret == -EINVAL) {
			pr_out("Invalid debug type \"%s\"\n\n", debug_type);
			pr_out("List of available types:\n");
			for (i = 0; i < ARRAY_SIZE(debug_type_strings); i++)
				pr_out("%s ", debug_type_strings[i]);
			pr_out("\n\n");
		} else if (ret < 0) {
			pr_out("Error enabling/disabling ksmbd debug\n");
		}

		free(debug_type);
		return ret;
	}

	memset(&global_conf, 0x00, sizeof(struct smbconf_global));
	global_conf.users_db = PATH_USERS_DB;
	global_conf.smbconf = PATH_SMBCONF;

	pr_logger_init(PR_LOGGER_STDIO);

	optind = 1;
	while ((c = getopt_long(argc, argv, "-:p:c:u:nsh", daemon_opts, NULL)) != EOF)
		switch(c) {
		case 1:
			break;
		case 'p':
			global_conf.tcp_port = cp_get_group_kv_long(optarg);
			pr_info("Overriding TCP port to %hu\n", global_conf.tcp_port);
			break;
		case 'c':
			global_conf.smbconf = g_strdup(optarg);
			if (!global_conf.smbconf)
				goto oom;
			break;
		case 'u':
			global_conf.users_db = g_strdup(optarg);
			if (!global_conf.users_db)
				goto oom;
			break;
		case 'n':
			no_detach = 1;
			break;
		case 's':
			systemd_service = 1;
			break;
		case ':':
		case '?':
		case 'h':
		default:
			goto usage;
		}

skip_opts:
	switch (cmd) {
	case KSMBD_CMD_DAEMON_START:
		setup_signals(daemon_sig_handler);
		ret = daemon_start_cmd(no_detach, systemd_service);
		if (ret != 0) {
			pr_err("Error starting daemon\n");
			exit(EXIT_FAILURE);
		}
		break;
	case KSMBD_CMD_DAEMON_SHUTDOWN:
		ret = daemon_shutdown_cmd();
		if (ret < 0) {
			pr_err("Error shutting down server. Is ksmbd kernel module loaded?\n");
			exit(EXIT_FAILURE);
		}
		pr_out("Server was shut down.\n");
		break;
	case KSMBD_CMD_DAEMON_VERSION:
		ret = daemon_version_cmd();
		break;
	}

	return ret;

usage:
	daemon_usage(cmd);
	exit(EXIT_FAILURE);
oom:
	pr_err("Out of memory\n");
	return -ENOMEM;
}
