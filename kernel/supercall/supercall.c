static int anon_ksu_release(struct inode *inode, struct file *filp)
{
//	pr_info("ksu fd released\n");
	return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return ksu_supercall_handle_ioctl(cmd, (void __user *)arg);
}

// File operations structure
static const struct file_operations anon_ksu_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = anon_ksu_ioctl,
	.compat_ioctl = anon_ksu_ioctl,
	.release = anon_ksu_release,
};

// Install KSU fd to current process
int ksu_install_fd(void)
{
	struct file *filp;
	int fd;

	// Get unused fd
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("ksu_install_fd: failed to get unused fd\n");
		return fd;
	}

	// Create anonymous inode file
	filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL, O_RDWR | O_CLOEXEC);
	if (IS_ERR(filp)) {
		pr_err("ksu_install_fd: failed to create anon inode file\n");
		put_unused_fd(fd);
		return PTR_ERR(filp);
	}

	// Install fd
	fd_install(fd, filp);
#ifdef CONFIG_KSU_DEBUG
	pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);
#endif
	return fd;
}

static inline int ksu_handle_fd_request(void __user *arg4)
{
	int fd = ksu_install_fd();
#ifdef CONFIG_KSU_DEBUG
	pr_info("[%d] install ksu fd: %d\n", current->pid, fd);
#endif
	if (copy_to_user(arg4, &fd, sizeof(fd))) {
		pr_err("install ksu fd reply err\n");
		close_fd(fd);
	}

	return 0;
}

// downstream: make sure to pass arg as reference, this can allow us to extend things.
int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg)
{
	if (magic1 != KSU_INSTALL_MAGIC1)
		return 0;

#ifdef CONFIG_KSU_DEBUG
	// when ternary on fmt?
	// cold syscall, we can splurge xD
	if (magic2 == KSU_INSTALL_MAGIC2)
		pr_info("sys_reboot: magic: 0x%x id: 0x%x pid: %d comm: %s \n", magic1, magic2, current->pid, current->comm);
	else
		pr_info("sys_reboot: magic: 0x%x id: %d pid: %d pid: %s \n", magic1, magic2, current->pid, current->comm);
#endif

	// arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	// downstream: dereference arg as arg4 so we can be inline to upstream
	void __user *arg4 = (void __user *)*arg;

	// Check if this is a request to install KSU fd
	if (magic2 == KSU_INSTALL_MAGIC2) {
		return ksu_handle_fd_request(arg4);
	}

#ifdef CONFIG_KSU_TOOLKIT
	// only root is allowed for these commands
	if (current_uid().val != 0)
		return 0;

	// extensions
	u64 reply = (u64)*arg;

	if (magic2 == CHANGE_MANAGER_UID) {
		pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid()) {
			if (copy_to_user((void __user *)*arg, &reply, sizeof(reply)))
				pr_info("sys_reboot: reply fail\n");
		}

		return 0;
	}

	if (magic2 == GET_SULOG_DUMP_V2) {

		int ret = send_sulog_dump(*arg);
		if (ret)
			return 0;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}

	if (magic2 == CHANGE_KSUVER) {
		pr_info("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
		ksuver_override = cmd;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}

	// WARNING!!! triple ptr zone! ***
	// https://wiki.c2.com/?ThreeStarProgrammer
	if (magic2 == CHANGE_SPOOF_UNAME) {

		char release_buf[65];
		char version_buf[65];
		static char original_release_buf[65] = {0};
		static char original_version_buf[65] = {0};

		// basically void * void __user * void __user *arg
		void ***ppptr = (void ***)(uintptr_t)arg;

		// user pointer storage
		// init this as zero so this works on 32-on-64 compat (LE)
		uint64_t u_pptr = 0;
		uint64_t u_ptr = 0;

		pr_info("sys_reboot: ppptr: 0x%lx \n", (uintptr_t)ppptr);

		// arg here is ***, dereference to pull out **
		if (copy_from_user(&u_pptr, (void __user *)*ppptr, sizeof(u_pptr)))
			return 0;

		pr_info("sys_reboot: u_pptr: 0x%lx \n", (uintptr_t)u_pptr);

		// now we got the __user **
		// we cannot dereference this as this is __user
		// we just do another copy_from_user to get it
		if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
			return 0;

		pr_info("sys_reboot: u_ptr: 0x%lx \n", (uintptr_t)u_ptr);

		// for release
		if (strncpy_from_user(release_buf, (char __user *)u_ptr, sizeof(release_buf)) < 0)
			return 0;
		release_buf[sizeof(release_buf) - 1] = '\0'; 

		// for version
		if (strncpy_from_user(version_buf, (char __user *)(u_ptr + strlen(release_buf) + 1), sizeof(version_buf)) < 0)
			return 0;
		version_buf[sizeof(version_buf) - 1] = '\0'; 

		if (original_release_buf[0] == '\0') {
			struct new_utsname *u_curr = utsname();
			// we save current version as the original before modifying
			strncpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
			strncpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
			pr_info("sys_reboot: original uname saved: %s %s\n", original_release_buf, original_version_buf);
		}

		// so user can reset
		if (!strcmp(release_buf, "default")) {
			memcpy(release_buf, original_release_buf, sizeof(release_buf));
		}
		if (!strcmp(version_buf, "default")) {
			memcpy(version_buf, original_version_buf, sizeof(version_buf));
		}

		pr_info("sys_reboot: spoofing kernel to: %s - %s\n", release_buf, version_buf);

		struct new_utsname *u = utsname();

		down_write(&uts_sem);
		strncpy(u->release, release_buf, sizeof(u->release));
		strncpy(u->version, version_buf, sizeof(u->version));
		up_write(&uts_sem);

		// we write our confirmation on **
		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply)))
			return 0;
	}

	if (magic2 == CHANGE_KSUFLAGS) {
		pr_info("sys_reboot: ksu_change_ksuflags to: %d\n", cmd);
		ksuflags_override = cmd;

		if (copy_to_user((void __user *)*arg, &reply, sizeof(reply) ))
			return 0;
	}
#endif

	return 0;
}

void __init ksu_supercalls_init(void)
{
	ksu_supercall_dump_commands();

	tiny_sulog_init_heap(); // grab heap memory for sulog
}

void __exit ksu_supercalls_exit(void) { }
