/*
 * Copyright (C) 2014-2018 Firejail Authors
 *
 * This file is part of firejail project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include "firejail.h"
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <linux/limits.h>
#include <fnmatch.h>
#include <glob.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>

static void fs_rdwr(const char *dir);



//***********************************************
// process profile file
//***********************************************
typedef enum {
	BLACKLIST_FILE,
	BLACKLIST_NOLOG,
	MOUNT_READONLY,
	MOUNT_TMPFS,
	MOUNT_NOEXEC,
	MOUNT_RDWR,
	OPERATION_MAX
} OPERATION;

typedef enum {
	UNSUCCESSFUL,
	SUCCESSFUL
} LAST_DISABLE_OPERATION;
LAST_DISABLE_OPERATION last_disable = UNSUCCESSFUL;

static void disable_file(OPERATION op, const char *filename) {
	assert(filename);
	assert(op <OPERATION_MAX);
	last_disable = UNSUCCESSFUL;

	// Resolve all symlinks
	char* fname = realpath(filename, NULL);
	if (fname == NULL && errno != EACCES) {
		return;
	}
	if (fname == NULL && errno == EACCES) {
		if (arg_debug)
			printf("Debug: no access to file %s, forcing mount\n", filename);
		// realpath and stat funtions will fail on FUSE filesystems
		// they don't seem to like a uid of 0
		// force mounting
		int rv = mount(RUN_RO_DIR, filename, "none", MS_BIND, "mode=400,gid=0");
		if (rv == 0)
			last_disable = SUCCESSFUL;
		else {
			rv = mount(RUN_RO_FILE, filename, "none", MS_BIND, "mode=400,gid=0");
			if (rv == 0)
				last_disable = SUCCESSFUL;
		}
		if (last_disable == SUCCESSFUL) {
			if (arg_debug)
				printf("Disable %s\n", filename);
			if (op == BLACKLIST_FILE)
				fs_logger2("blacklist", filename);
			else
				fs_logger2("blacklist-nolog", filename);
		}
		else {
			if (arg_debug)
				printf("Warning (blacklisting): %s is an invalid file, skipping...\n", filename);
		}

		return;
	}

	// if the file is not present, do nothing
	struct stat s;
	if (fname == NULL)
		return;
	if (stat(fname, &s) == -1) {
		if (arg_debug)
			fwarning("%s does not exist, skipping...\n", fname);
		free(fname);
		return;
	}

	// modify the file
	if (op == BLACKLIST_FILE || op == BLACKLIST_NOLOG) {
		// some distros put all executables under /usr/bin and make /bin a symbolic link
		if ((strcmp(fname, "/bin") == 0 || strcmp(fname, "/usr/bin") == 0) &&
		      is_link(filename) &&
		      S_ISDIR(s.st_mode)) {
			fwarning("%s directory link was not blacklisted\n", filename);
		}
		else {
			if (arg_debug) {
				if (strcmp(filename, fname))
					printf("Disable %s (requested %s)\n", fname, filename);
				else
					printf("Disable %s\n", fname);
			}

			if (S_ISDIR(s.st_mode)) {
				if (mount(RUN_RO_DIR, fname, "none", MS_BIND, "mode=400,gid=0") < 0)
					errExit("disable file");
			}
			else {
				if (mount(RUN_RO_FILE, fname, "none", MS_BIND, "mode=400,gid=0") < 0)
					errExit("disable file");
			}
			last_disable = SUCCESSFUL;
			if (op == BLACKLIST_FILE)
				fs_logger2("blacklist", fname);
			else
				fs_logger2("blacklist-nolog", fname);
		}
	}
	else if (op == MOUNT_READONLY) {
		if (arg_debug)
			printf("Mounting read-only %s\n", fname);
		fs_rdonly(fname);
// todo: last_disable = SUCCESSFUL;
	}
	else if (op == MOUNT_RDWR) {
		if (arg_debug)
			printf("Mounting read-only %s\n", fname);
		fs_rdwr(fname);
// todo: last_disable = SUCCESSFUL;
	}
	else if (op == MOUNT_NOEXEC) {
		if (arg_debug)
			printf("Mounting noexec %s\n", fname);
		fs_noexec(fname);
// todo: last_disable = SUCCESSFUL;
	}
	else if (op == MOUNT_TMPFS) {
		if (S_ISDIR(s.st_mode)) {
			if (arg_debug)
				printf("Mounting tmpfs on %s\n", fname);
			// preserve owner and mode for the directory
			if (mount("tmpfs", fname, "tmpfs", MS_NOSUID | MS_NODEV | MS_STRICTATIME | MS_REC,  0) < 0)
				errExit("mounting tmpfs");
			/* coverity[toctou] */
			if (chown(fname, s.st_uid, s.st_gid) == -1)
				errExit("mounting tmpfs chown");
			if (chmod(fname, s.st_mode) == -1)
				errExit("mounting tmpfs chmod");
			last_disable = SUCCESSFUL;
			fs_logger2("tmpfs", fname);
		}
		else
			fwarning("%s is not a directory; cannot mount a tmpfs on top of it.\n", fname);
	}
	else
		assert(0);

	free(fname);
}

// Treat pattern as a shell glob pattern and blacklist matching files
static void globbing(OPERATION op, const char *pattern, const char *noblacklist[], size_t noblacklist_len) {
	assert(pattern);

	glob_t globbuf;
	// Profiles contain blacklists for files that might not exist on a user's machine.
	// GLOB_NOCHECK makes that okay.
	int globerr = glob(pattern, GLOB_NOCHECK | GLOB_NOSORT | GLOB_PERIOD, NULL, &globbuf);
	if (globerr) {
		fprintf(stderr, "Error: failed to glob pattern %s\n", pattern);
		exit(1);
	}

	size_t i, j;
	for (i = 0; i < globbuf.gl_pathc; i++) {
		char *path = globbuf.gl_pathv[i];
		assert(path);
		// /home/me/.* can glob to /home/me/.. which would blacklist /home/
		const char *base = gnu_basename(path);
		if (strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
			continue;
		// noblacklist is expected to be short in normal cases, so stupid and correct brute force is okay
		bool okay_to_blacklist = true;
		for (j = 0; j < noblacklist_len; j++) {
			int result = fnmatch(noblacklist[j], path, FNM_PATHNAME);
			if (result == FNM_NOMATCH)
				continue;
			else if (result == 0) {
				okay_to_blacklist = false;
				break;
			}
			else {
				fprintf(stderr, "Error: failed to compare path %s with pattern %s\n", path, noblacklist[j]);
				exit(1);
			}
		}

		if (okay_to_blacklist)
			disable_file(op, path);
		else if (arg_debug)
			printf("Not blacklist %s\n", path);
	}
	globfree(&globbuf);
}


// blacklist files or directories by mounting empty files on top of them
void fs_blacklist(void) {
	char *homedir = cfg.homedir;
	assert(homedir);
	ProfileEntry *entry = cfg.profile;
	if (!entry)
		return;

	size_t noblacklist_c = 0;
	size_t noblacklist_m = 32;
	char **noblacklist = calloc(noblacklist_m, sizeof(*noblacklist));

	if (noblacklist == NULL)
		errExit("failed allocating memory for noblacklist entries");

	while (entry) {
		OPERATION op = OPERATION_MAX;
		char *ptr;

		// whitelist commands handled by fs_whitelist()
		if (strncmp(entry->data, "whitelist ", 10) == 0 ||
		    strncmp(entry->data, "nowhitelist ", 12) == 0 ||
		   *entry->data == '\0') {
			entry = entry->next;
			continue;
		}

		// process bind command
		if (strncmp(entry->data, "bind ", 5) == 0)  {
			struct stat s;
			char *dname1 = entry->data + 5;
			char *dname2 = split_comma(dname1);
			if (dname2 == NULL ||
			    stat(dname1, &s) == -1 ||
			    stat(dname2, &s) == -1) {
				fprintf(stderr, "Error: invalid bind command, directory missing\n");
				entry = entry->next;
				continue;
			}

			// mount --bind olddir newdir
			if (arg_debug)
				printf("Mount-bind %s on top of %s\n", dname1, dname2);
			// preserve dname2 mode and ownership
			if (mount(dname1, dname2, NULL, MS_BIND|MS_REC, NULL) < 0)
				errExit("mount bind");
			/* coverity[toctou] */
			if (set_perms(dname2,  s.st_uid, s.st_gid,s.st_mode))
				errExit("set_perms");

			entry = entry->next;
			continue;
		}

		// Process noblacklist command
		if (strncmp(entry->data, "noblacklist ", 12) == 0) {
			char **enames;
			int i;

			if (strncmp(entry->data + 12, "${PATH}", 7) == 0) {
				// expand ${PATH} macro
				char **paths = build_paths();
				unsigned int npaths = count_paths();
				enames = calloc(npaths, sizeof(char *));
				if (!enames)
					errExit("calloc");

				for (i = 0; paths[i]; i++) {
					if (asprintf(&enames[i], "%s%s", paths[i],
						entry->data + 19) == -1)
						errExit("asprintf");
				}
				assert(enames[npaths-1] == 0);

			}
			else {
				// expand ${HOME} macro if found or pass as is
				enames = calloc(2, sizeof(char *));
				if (!enames)
					errExit("calloc");
				enames[0] = expand_home(entry->data + 12, homedir);
				assert(enames[1] == 0);
			}

			for (i = 0; enames[i]; i++) {
				if (noblacklist_c >= noblacklist_m) {
					noblacklist_m *= 2;
					noblacklist = realloc(noblacklist, sizeof(*noblacklist) * noblacklist_m);
					if (noblacklist == NULL)
						errExit("failed increasing memory for noblacklist entries");
				}
				noblacklist[noblacklist_c++] = enames[i];
			}

			free(enames);

			entry = entry->next;
			continue;
		}

		// process blacklist command
		if (strncmp(entry->data, "blacklist ", 10) == 0)  {
			ptr = entry->data + 10;
			op = BLACKLIST_FILE;
		}
		else if (strncmp(entry->data, "blacklist-nolog ", 16) == 0)  {
			ptr = entry->data + 16;
			op = BLACKLIST_NOLOG;
		}
		else if (strncmp(entry->data, "read-only ", 10) == 0) {
			ptr = entry->data + 10;
			op = MOUNT_READONLY;
		}
		else if (strncmp(entry->data, "read-write ", 11) == 0) {
			ptr = entry->data + 11;
			op = MOUNT_RDWR;
		}
		else if (strncmp(entry->data, "noexec ", 7) == 0) {
			ptr = entry->data + 7;
			op = MOUNT_NOEXEC;
		}
		else if (strncmp(entry->data, "tmpfs ", 6) == 0) {
			ptr = entry->data + 6;
			op = MOUNT_TMPFS;
		}
		else if (strncmp(entry->data, "mkdir ", 6) == 0) {
			EUID_USER();
			fs_mkdir(entry->data + 6);
			EUID_ROOT();
			entry = entry->next;
			continue;
		}
		else if (strncmp(entry->data, "mkfile ", 7) == 0) {
			EUID_USER();
			fs_mkfile(entry->data + 7);
			EUID_ROOT();
			entry = entry->next;
			continue;
		}
		else {
			fprintf(stderr, "Error: invalid profile line %s\n", entry->data);
			entry = entry->next;
			continue;
		}

		// replace home macro in blacklist array
		char *new_name = expand_home(ptr, homedir);
		ptr = new_name;

		// expand path macro - look for the file in /usr/local/bin,  /usr/local/sbin, /bin, /usr/bin, /sbin and  /usr/sbin directories
		if (ptr) {
			if (strncmp(ptr, "${PATH}", 7) == 0) {
				char *fname = ptr + 7;
				size_t fname_len = strlen(fname);
				char **paths = build_paths(); //{"/usr/local/bin", "/usr/local/sbin", "/bin", "/usr/bin/", "/sbin", "/usr/sbin", NULL};
				int i = 0;
				while (paths[i] != NULL) {
					char *path = paths[i];
					i++;
					char newname[strlen(path) + fname_len + 1];
					sprintf(newname, "%s%s", path, fname);
					globbing(op, newname, (const char**)noblacklist, noblacklist_c);
				}
			}
			else
				globbing(op, ptr, (const char**)noblacklist, noblacklist_c);
		}

		if (new_name)
			free(new_name);
		entry = entry->next;
	}

	// free memory
	size_t i;
	for (i = 0; i < noblacklist_c; i++)
		free(noblacklist[i]);
	free(noblacklist);
}

static int get_mount_flags(const char *path, unsigned long *flags) {
	struct statvfs buf;

	if (statvfs(path, &buf) < 0)
		return -errno;
	*flags = buf.f_flag;
	return 0;
}

//***********************************************
// mount namespace
//***********************************************

// remount a directory read-only
void fs_rdonly(const char *dir) {
	assert(dir);
	// check directory exists
	struct stat s;
	int rv = stat(dir, &s);
	if (rv == 0) {
		unsigned long flags = 0;
		get_mount_flags(dir, &flags);
		if ((flags & MS_RDONLY) == MS_RDONLY)
			return;
		flags |= MS_RDONLY;
		// mount --bind /bin /bin
		// mount --bind -o remount,ro /bin
		if (mount(dir, dir, NULL, MS_BIND|MS_REC, NULL) < 0 ||
		    mount(NULL, dir, NULL, flags|MS_BIND|MS_REMOUNT|MS_REC, NULL) < 0)
			errExit("mount read-only");
		fs_logger2("read-only", dir);
	}
}

static void fs_rdwr(const char *dir) {
	assert(dir);
	// check directory exists
	struct stat s;
	int rv = stat(dir, &s);
	if (rv == 0) {
		// if the file is outside /home directory, allow only root user
		uid_t u = getuid();
		if (u != 0 && s.st_uid != u) {
			fwarning("you are not allowed to change %s to read-write\n", dir);
			return;
		}

		// mount --bind /bin /bin
		// mount --bind -o remount,rw /bin
		unsigned long flags = 0;
		get_mount_flags(dir, &flags);
		if ((flags & MS_RDONLY) == 0)
			return;
		flags &= ~MS_RDONLY;
		if (mount(dir, dir, NULL, MS_BIND|MS_REC, NULL) < 0 ||
		    mount(NULL, dir, NULL, flags|MS_BIND|MS_REMOUNT|MS_REC, NULL) < 0)
			errExit("mount read-write");
		fs_logger2("read-write", dir);
	}
}

void fs_noexec(const char *dir) {
	assert(dir);
	// check directory exists
	struct stat s;
	int rv = stat(dir, &s);
	if (rv == 0) {
		// mount --bind /bin /bin
		// mount --bind -o remount,ro /bin
		unsigned long flags = 0;
		get_mount_flags(dir, &flags);
		if ((flags & (MS_NOEXEC|MS_NODEV|MS_NOSUID)) == (MS_NOEXEC|MS_NODEV|MS_NOSUID))
			return;
		flags |= MS_NOEXEC|MS_NODEV|MS_NOSUID;
		if (mount(dir, dir, NULL, MS_BIND|MS_REC, NULL) < 0 ||
		    mount(NULL, dir, NULL, flags|MS_BIND|MS_REMOUNT|MS_REC, NULL) < 0)
			errExit("mount noexec");
		fs_logger2("noexec", dir);
	}
}

// Disable /mnt, /media, /run/mount and /run/media access
void fs_mnt(void) {
	disable_file(BLACKLIST_FILE, "/mnt");
	disable_file(BLACKLIST_FILE, "/media");
	disable_file(BLACKLIST_FILE, "/run/mount");
	disable_file(BLACKLIST_FILE, "//run/media");
}


// mount /proc and /sys directories
void fs_proc_sys_dev_boot(void) {
	if (arg_debug)
		printf("Remounting /proc and /proc/sys filesystems\n");
	if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_REC, NULL) < 0)
		errExit("mounting /proc");
	fs_logger("remount /proc");

	// remount /proc/sys readonly
	if (mount("/proc/sys", "/proc/sys", NULL, MS_BIND | MS_REC, NULL) < 0 ||
	    mount(NULL, "/proc/sys", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_REC, NULL) < 0)
		errExit("mounting /proc/sys");
	fs_logger("read-only /proc/sys");


	/* Mount a version of /sys that describes the network namespace */
	if (arg_debug)
		printf("Remounting /sys directory\n");
	if (umount2("/sys", MNT_DETACH) < 0)
		fwarning("failed to unmount /sys\n");
	if (mount("sysfs", "/sys", "sysfs", MS_RDONLY|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_REC, NULL) < 0)
		fwarning("failed to mount /sys\n");
	else
		fs_logger("remount /sys");

	disable_file(BLACKLIST_FILE, "/sys/firmware");
	disable_file(BLACKLIST_FILE, "/sys/hypervisor");
	{ // allow user access to /sys/fs if "--noblacklist=/sys/fs" is present on the command line
		EUID_USER();
		profile_add("blacklist /sys/fs");
		EUID_ROOT();
	}
	disable_file(BLACKLIST_FILE, "/sys/module");
	disable_file(BLACKLIST_FILE, "/sys/power");
	disable_file(BLACKLIST_FILE, "/sys/kernel/debug");
	disable_file(BLACKLIST_FILE, "/sys/kernel/vmcoreinfo");
	disable_file(BLACKLIST_FILE, "/sys/kernel/uevent_helper");

	// various /proc/sys files
	disable_file(BLACKLIST_FILE, "/proc/sys/security");
	disable_file(BLACKLIST_FILE, "/proc/sys/efi/vars");
	disable_file(BLACKLIST_FILE, "/proc/sys/fs/binfmt_misc");
	disable_file(BLACKLIST_FILE, "/proc/sys/kernel/core_pattern");
	disable_file(BLACKLIST_FILE, "/proc/sys/kernel/modprobe");
	disable_file(BLACKLIST_FILE, "/proc/sysrq-trigger");
	disable_file(BLACKLIST_FILE, "/proc/sys/kernel/hotplug");
	disable_file(BLACKLIST_FILE, "/proc/sys/vm/panic_on_oom");

	// various /proc files
	disable_file(BLACKLIST_FILE, "/proc/irq");
	disable_file(BLACKLIST_FILE, "/proc/bus");
	disable_file(BLACKLIST_FILE, "/proc/config.gz");
	disable_file(BLACKLIST_FILE, "/proc/sched_debug");
	disable_file(BLACKLIST_FILE, "/proc/timer_list");
	disable_file(BLACKLIST_FILE, "/proc/timer_stats");
	disable_file(BLACKLIST_FILE, "/proc/kcore");
	disable_file(BLACKLIST_FILE, "/proc/kallsyms");
	disable_file(BLACKLIST_FILE, "/proc/mem");
	disable_file(BLACKLIST_FILE, "/proc/kmem");

	// remove kernel symbol information
	disable_file(BLACKLIST_FILE, "/usr/src/linux");
	disable_file(BLACKLIST_FILE, "/lib/modules");
	disable_file(BLACKLIST_FILE, "/usr/lib/debug");
	disable_file(BLACKLIST_FILE, "/boot");

	// disable /selinux
	disable_file(BLACKLIST_FILE, "/selinux");

	// disable /dev/port
	disable_file(BLACKLIST_FILE, "/dev/port");



	// disable various ipc sockets in /run/user
	if (!arg_writable_run_user) {
		struct stat s;

		char *fname;
		if (asprintf(&fname, "/run/user/%d", getuid()) == -1)
			errExit("asprintf");
		if (is_dir(fname)) { // older distros don't have this directory
			// disable /run/user/{uid}/gnupg
			char *fnamegpg;
			if (asprintf(&fnamegpg, "/run/user/%d/gnupg", getuid()) == -1)
				errExit("asprintf");
			if (stat(fnamegpg, &s) == -1)
			    mkdir_attr(fnamegpg, 0700, getuid(), getgid());
			if (stat(fnamegpg, &s) == 0)
				disable_file(BLACKLIST_FILE, fnamegpg);
			free(fnamegpg);

			// disable /run/user/{uid}/systemd
			char *fnamesysd;
			if (asprintf(&fnamesysd, "/run/user/%d/systemd", getuid()) == -1)
				errExit("asprintf");
			if (stat(fnamesysd, &s) == -1)
				mkdir_attr(fnamesysd, 0755, getuid(), getgid());
			if (stat(fnamesysd, &s) == 0)
				disable_file(BLACKLIST_FILE, fnamesysd);
			free(fnamesysd);
		}
		free(fname);
	}

	if (getuid() != 0) {
		// disable /dev/kmsg and /proc/kmsg
		disable_file(BLACKLIST_FILE, "/dev/kmsg");
		disable_file(BLACKLIST_FILE, "/proc/kmsg");
	}
}

// disable firejail configuration in /etc/firejail and in ~/.config/firejail
static void disable_config(void) {
	struct stat s;

	char *fname;
	if (asprintf(&fname, "%s/.config/firejail", cfg.homedir) == -1)
		errExit("asprintf");
	if (stat(fname, &s) == 0)
		disable_file(BLACKLIST_FILE, fname);
	free(fname);

	// disable run time information
	if (stat(RUN_FIREJAIL_NETWORK_DIR, &s) == 0)
		disable_file(BLACKLIST_FILE, RUN_FIREJAIL_NETWORK_DIR);
	if (stat(RUN_FIREJAIL_BANDWIDTH_DIR, &s) == 0)
		disable_file(BLACKLIST_FILE, RUN_FIREJAIL_BANDWIDTH_DIR);
	if (stat(RUN_FIREJAIL_NAME_DIR, &s) == 0)
		disable_file(BLACKLIST_FILE, RUN_FIREJAIL_NAME_DIR);
}


// build a basic read-only filesystem
void fs_basic_fs(void) {
	uid_t uid = getuid();

	if (arg_debug)
		printf("Mounting read-only /bin, /sbin, /lib, /lib32, /lib64, /usr");
	if (!arg_writable_etc) {
		fs_rdonly("/etc");
		if (uid)
			fs_noexec("/etc");
		if (arg_debug) printf(", /etc");
	}
	if (!arg_writable_var) {
		fs_rdonly("/var");
		if (uid)
			fs_noexec("/var");
		if (arg_debug) printf(", /var");
	}
	if (arg_debug) printf("\n");
	fs_rdonly("/bin");
	fs_rdonly("/sbin");
	fs_rdonly("/lib");
	fs_rdonly("/lib64");
	fs_rdonly("/lib32");
	fs_rdonly("/libx32");
	fs_rdonly("/usr");

	// update /var directory in order to support multiple sandboxes running on the same root directory
	fs_var_lock();
	fs_var_tmp();
	if (!arg_writable_var_log)
		fs_var_log();
	else
		fs_rdwr("/var/log");

	fs_var_lib();
	fs_var_cache();
	fs_var_utmp();

	// don't leak user information
	restrict_users();

	// when starting as root, firejail config is not disabled;
	if (uid)
		disable_config();
}

// this function is called from sandbox.c before blacklist/whitelist functions
void fs_private_tmp(void) {
	// check XAUTHORITY file, KDE keeps it under /tmp
	char *xauth = getenv("XAUTHORITY");
	if (xauth) {
		char *rp = realpath(xauth, NULL);
		if (rp && strncmp(rp, "/tmp/", 5) == 0) {
			char *cmd;
			if (asprintf(&cmd, "whitelist %s", rp) == -1)
				errExit("asprintf");
			profile_add(cmd); // profile_add does not duplicate the string
		}
		if (rp)
			free(rp);
	}

	// whitelist x11 directory
	profile_add("whitelist /tmp/.X11-unix");

	// whitelist any pulse* file in /tmp directory
	// some distros use PulseAudio sockets under /tmp instead of the socket in /urn/user
	DIR *dir;
	if (!(dir = opendir("/tmp"))) {
		// sleep 2 seconds and try again
		sleep(2);
		if (!(dir = opendir("/tmp"))) {
			return;
		}
	}

	struct dirent *entry;
	while ((entry = readdir(dir))) {
		if (strncmp(entry->d_name, "pulse-", 6) == 0) {
			char *cmd;
			if (asprintf(&cmd, "whitelist /tmp/%s", entry->d_name) == -1)
				errExit("asprintf");
			profile_add(cmd); // profile_add does not duplicate the string
		}
	}
	closedir(dir);


}
