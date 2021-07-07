/* Code for loading Linux executables.  Mostly linux kernel code.  */

#include "qemu/osdep.h"
#include "qemu.h"
#include "qapi/error.h"

#define NGROUPS 32

/* ??? This should really be somewhere else.  */
abi_long memcpy_to_target(abi_ulong dest, const void *src, unsigned long len)
{
    void *host_ptr;

    host_ptr = lock_user(VERIFY_WRITE, dest, len, 0);
    if (!host_ptr) {
        return -TARGET_EFAULT;
    }
    memcpy(host_ptr, src, len);
    unlock_user(host_ptr, dest, 1);
    return 0;
}

static int count(char **vec)
{
    int i;

    for (i = 0; *vec; i++) {
        vec++;
    }
    return i;
}

static int prepare_binprm(struct linux_binprm *bprm)
{
    struct stat st;
    int mode;
    int retval;

    if (fstat(bprm->fd, &st) < 0) {
        return -errno;
    }

    mode = st.st_mode;
    if (!S_ISREG(mode)) {   /* Must be regular file */
        return -EACCES;
    }
    if (!(mode & 0111)) {   /* Must have at least one execute bit set */
        return -EACCES;
    }

    bprm->e_uid = geteuid();
    bprm->e_gid = getegid();

    /* Set-uid? */
    if (mode & S_ISUID) {
        bprm->e_uid = st.st_uid;
    }

    /* Set-gid? */
    /*
     * If setgid is set but no group execute bit then this
     * is a candidate for mandatory locking, not a setgid
     * executable.
     */
    if ((mode & (S_ISGID | S_IXGRP)) == (S_ISGID | S_IXGRP)) {
        bprm->e_gid = st.st_gid;
    }

    retval = read(bprm->fd, bprm->buf, BPRM_BUF_SIZE);
    if (retval < 0) {
        perror("prepare_binprm");
        exit(-1);
    }
    if (retval < BPRM_BUF_SIZE) {
        /* Make sure the rest of the loader won't read garbage.  */
        memset(bprm->buf + retval, 0, BPRM_BUF_SIZE - retval);
    }

    bprm->src.cache = bprm->buf;
    bprm->src.cache_size = retval;

    return retval;
}

/* Construct the envp and argv tables on the target stack.  */
abi_ulong loader_build_argptr(int envc, int argc, abi_ulong sp,
                              abi_ulong stringp, int push_ptr)
{
    TaskState *ts = (TaskState *)thread_cpu->opaque;
    int n = sizeof(abi_ulong);
    abi_ulong envp;
    abi_ulong argv;

    sp -= (envc + 1) * n;
    envp = sp;
    sp -= (argc + 1) * n;
    argv = sp;
    if (push_ptr) {
        /* FIXME - handle put_user() failures */
        sp -= n;
        put_user_ual(envp, sp);
        sp -= n;
        put_user_ual(argv, sp);
    }
    sp -= n;
    /* FIXME - handle put_user() failures */
    put_user_ual(argc, sp);
    ts->info->arg_start = stringp;
    while (argc-- > 0) {
        /* FIXME - handle put_user() failures */
        put_user_ual(stringp, argv);
        argv += n;
        stringp += target_strlen(stringp) + 1;
    }
    ts->info->arg_end = stringp;
    /* FIXME - handle put_user() failures */
    put_user_ual(0, argv);
    while (envc-- > 0) {
        /* FIXME - handle put_user() failures */
        put_user_ual(stringp, envp);
        envp += n;
        stringp += target_strlen(stringp) + 1;
    }
    /* FIXME - handle put_user() failures */
    put_user_ual(0, envp);

    return sp;
}

int loader_exec(int fdexec, const char *filename, char **argv, char **envp,
                struct target_pt_regs *regs, struct image_info *infop,
                struct linux_binprm *bprm)
{
    int retval;

    bprm->fd = fdexec;
    bprm->src.fd = fdexec;
    bprm->filename = (char *)filename;
    bprm->argc = count(argv);
    bprm->argv = argv;
    bprm->envc = count(envp);
    bprm->envp = envp;

    retval = prepare_binprm(bprm);

    if (retval < 4) {
        return -ENOEXEC;
    }
    if (bprm->buf[0] == 0x7f
        && bprm->buf[1] == 'E'
        && bprm->buf[2] == 'L'
        && bprm->buf[3] == 'F') {
        retval = load_elf_binary(bprm, infop);
#if defined(TARGET_HAS_BFLT)
    } else if (bprm->buf[0] == 'b'
               && bprm->buf[1] == 'F'
               && bprm->buf[2] == 'L'
               && bprm->buf[3] == 'T') {
        retval = load_flt_binary(bprm, infop);
#endif
    } else {
        return -ENOEXEC;
    }
    if (retval < 0) {
        return retval;
    }

    /* Success.  Initialize important registers. */
    do_init_thread(regs, infop);
    return 0;
}

bool imgsrc_read(void *dst, off_t offset, size_t len,
                 const ImageSource *img, Error **errp)
{
    ssize_t ret;

    if (offset + len <= img->cache_size) {
        memcpy(dst, img->cache + offset, len);
        return true;
    }

    if (img->fd < 0) {
        error_setg(errp, "read past end of buffer");
        return false;
    }

    ret = pread(img->fd, dst, len, offset);
    if (ret == len) {
        return true;
    }
    if (ret < 0) {
        error_setg_errno(errp, errno, "Error reading file header");
    } else {
        error_setg(errp, "Incomplete read of file header");
    }
    return false;
}

void *imgsrc_read_alloc(off_t offset, size_t len,
                        const ImageSource *img, Error **errp)
{
    void *alloc = g_malloc(len);
    bool ok = imgsrc_read(alloc, offset, len, img, errp);

    if (!ok) {
        g_free(alloc);
        alloc = NULL;
    }
    return alloc;
}
