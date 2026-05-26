/*
 * linux/kernel/ptrace.c
 *
 * (C) Copyright 1999 Linus Torvalds
 *
 * Common interfaces for "ptrace()" which we do not want
 * to continually duplicate across every architecture.
 */

#include <linux/capability.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/coredump.h>
#include <linux/sched/task.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/ptrace.h>
#include <linux/security.h>
#include <linux/signal.h>
#include <linux/uio.h>
#include <linux/audit.h>
#include <linux/pid_namespace.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/regset.h>
#include <linux/hw_breakpoint.h>
#include <linux/cn_proc.h>
#include <linux/compat.h>

/*
 * Access another process' address space via ptrace.
 * Source/target buffer must be kernel space,
 * Do not walk the page table directly, use get_user_pages
 */
int ptrace_access_vm(struct task_struct *tsk, unsigned long addr,
		     void *buf, int len, unsigned int gup_flags)
{
	struct mm_struct *mm;
	int ret;

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	if (!tsk->ptrace ||
	    (current != tsk->parent) ||
	    ((get_dumpable(mm) != SUID_DUMP_USER) &&
	     !ptracer_capable(tsk, mm->user_ns))) {
		mmput(mm);
		return 0;
	}

	ret = __access_remote_vm(tsk, mm, addr, buf, len, gup_flags);
	mmput(mm);

	return ret;
}


void __ptrace_link(struct task_struct *child, struct task_struct *new_parent,
		   const struct cred *ptracer_cred)
{
	BUG_ON(!list_empty(&child->ptrace_entry));
	list_add(&child->ptrace_entry, &new_parent->ptraced);
	child->parent = new_parent;
	child->ptracer_cred = get_cred(ptracer_cred);
}

/*
 * ptrace a task: make the debugger its new parent and
 * move it to the ptrace list.
 *
 * Must be called with the tasklist lock write-held.
 */
static void ptrace_link(struct task_struct *child, struct task_struct *new_parent)
{
	rcu_read_lock();
	__ptrace_link(child, new_parent, __task_cred(new_parent));
	rcu_read_unlock();
}

/**
 * __ptrace_unlink - unlink ptracee and restore its execution state
 * @child: ptracee to be unlinked
 *
 * Remove @child from the ptrace list, move it back to the original parent,
 * and restore the execution state so that it conforms to the group stop
 * state.
 *
 * Unlinking can happen via two paths - explicit PTRACE_DETACH or ptracer
 * exiting.  For PTRACE_DETACH, unless the ptracee has been killed between
 * ptrace_check_attach() and here, it's guaranteed to be in TASK_TRACED.
 * If the ptracer is exiting, the ptracee can be in any state.
 *
 * After detach, the ptracee should be in a state which conforms to the
 * group stop.  If the group is stopped or in the process of stopping, the
 * ptracee should be put into TASK_STOPPED; otherwise, it should be woken
 * up from TASK_TRACED.
 *
 * If the ptracee is in TASK_TRACED and needs to be moved to TASK_STOPPED,
 * it goes through TRACED -> RUNNING -> STOPPED transition which is similar
 * to but in the opposite direction of what happens while attaching to a
 * stopped task.  However, in this direction, the intermediate RUNNING
 * state is not hidden even from the current ptracer and if it immediately
 * re-attaches and performs a WNOHANG wait(2), it may fail.
 *
 * CONTEXT:
 * write_lock_irq(tasklist_lock)
 */
void __ptrace_unlink(struct task_struct *child)
{
	const struct cred *old_cred;
	BUG_ON(!child->ptrace);

	clear_tsk_thread_flag(child, TIF_SYSCALL_TRACE);

	child->parent = child->real_parent;
	list_del_init(&child->ptrace_entry);
	old_cred = child->ptracer_cred;
	child->ptracer_cred = NULL;
	put_cred(old_cred);

	spin_lock(&child->sighand->siglock);
	child->ptrace = 0;
	/*
	 * Clear all pending traps and TRAPPING.  TRAPPING should be
	 * cleared regardless of JOBCTL_STOP_PENDING.  Do it explicitly.
	 */
	task_clear_jobctl_pending(child, JOBCTL_TRAP_MASK);
	task_clear_jobctl_trapping(child);

	/*
	 * Reinstate JOBCTL_STOP_PENDING if group stop is in effect and
	 * @child isn't dead.
	 */
	if (!(child->flags & PF_EXITING) &&
	    (child->signal->flags & SIGNAL_STOP_STOPPED ||
	     child->signal->group_stop_count)) {
		child->jobctl |= JOBCTL_STOP_PENDING;

		/*
		 * This is only possible if this thread was cloned by the
		 * traced task running in the stopped group, set the signal
		 * for the future reports.
		 * FIXME: we should change ptrace_init_task() to handle this
		 * case.
		 */
		if (!(child->jobctl & JOBCTL_STOP_SIGMASK))
			child->jobctl |= SIGSTOP;
	}

	/*
	 * If transition to TASK_STOPPED is pending or in TASK_TRACED, kick
	 * @child in the butt.  Note that @resume should be used iff @child
	 * is in TASK_TRACED; otherwise, we might unduly disrupt
	 * TASK_KILLABLE sleeps.
	 */
	if (child->jobctl & JOBCTL_STOP_PENDING || task_is_traced(child))
		ptrace_signal_wake_up(child, true);

	spin_unlock(&child->sighand->siglock);
}

/* Ensure that nothing can wake it up, even SIGKILL */
static bool ptrace_freeze_traced(struct task_struct *task)
{
	bool ret = false;

	/* Lockless, nobody but us can set this flag */
	if (task->jobctl & JOBCTL_LISTENING)
		return ret;

	spin_lock_irq(&task->sighand->siglock);
	if (task_is_traced(task) && !__fatal_signal_pending(task)) {
		task->state = __TASK_TRACED;
		ret = true;
	}
	spin_unlock_irq(&task->sighand->siglock);

	return ret;
}

static void ptrace_unfreeze_traced(struct task_struct *task)
{
	if (task->state != __TASK_TRACED)
		return;

	WARN_ON(!task->ptrace || task->parent != current);

	/*
	 * PTRACE_LISTEN can allow ptrace_trap_notify to wake us up remotely.
	 * Recheck state under the lock to close this race.
	 */
	spin_lock_irq(&task->sighand->siglock);
	if (task->state == __TASK_TRACED) {
		if (__fatal_signal_pending(task))
			wake_up_state(task, __TASK_TRACED);
		else
			task->state = TASK_TRACED;
	}
	spin_unlock_irq(&task->sighand->siglock);
}

/**
 * ptrace_check_attach - check whether ptracee is ready for ptrace operation
 * @child: ptracee to check for
 * @ignore_state: don't check whether @child is currently %TASK_TRACED
 *
 * Check whether @child is being ptraced by %current and ready for further
 * ptrace operations.  If @ignore_state is %false, @child also should be in
 * %TASK_TRACED state and on return the child is guaranteed to be traced
 * and not executing.  If @ignore_state is %true, @child can be in any
 * state.
 *
 * CONTEXT:
 * Grabs and releases tasklist_lock and @child->sighand->siglock.
 *
 * RETURNS:
 * 0 on success, -ESRCH if %child is not ready.
 */
static int ptrace_check_attach(struct task_struct *child, bool ignore_state)
{
	int ret = -ESRCH;

	/*
	 * We take the read lock around doing both checks to close a
	 * possible race where someone else was tracing our child and
	 * detached between these two checks.  After this locked check,
	 * we are sure that this is our traced child and that can only
	 * be changed by us so it's not changing right after this.
	 */
	read_lock(&tasklist_lock);
	if (child->ptrace && child->parent == current) {
		WARN_ON(child->state == __TASK_TRACED);
		/*
		 * child->sighand can't be NULL, release_task()
		 * does ptrace_unlink() before __exit_signal().
		 */
		if (ignore_state || ptrace_freeze_traced(child))
			ret = 0;
	}
	read_unlock(&tasklist_lock);

	if (!ret && !ignore_state) {
		if (!wait_task_inactive(child, __TASK_TRACED)) {
			/*
			 * This can only happen if may_ptrace_stop() fails and
			 * ptrace_stop() changes ->state back to TASK_RUNNING,
			 * so we should not worry about leaking __TASK_TRACED.
			 */
			WARN_ON(child->state == __TASK_TRACED);
			ret = -ESRCH;
		}
	}

	return ret;
}

static int ptrace_has_cap(struct user_namespace *ns, unsigned int mode)
{
	if (mode & PTRACE_MODE_NOAUDIT)
		return has_ns_capability_noaudit(current, ns, CAP_SYS_PTRACE);
	else
		return has_ns_capability(current, ns, CAP_SYS_PTRACE);
}

static bool task_still_dumpable(struct task_struct *task, unsigned int mode)
{
	struct mm_struct *mm = task->mm;
	if (mm) {
		if (get_dumpable(mm) == SUID_DUMP_USER)
			return true;
		return ptrace_has_cap(mm->user_ns, mode);
	}

	if (task->user_dumpable)
		return true;
	return ptrace_has_cap(&init_user_ns, mode);
}

/* Returns 0 on success, -errno on denial. */
static int __ptrace_may_access(struct task_struct *task, unsigned int mode)
{
	const struct cred *cred = current_cred(), *tcred;
	kuid_t caller_uid;
	kgid_t caller_gid;

	if (!(mode & PTRACE_MODE_FSCREDS) == !(mode & PTRACE_MODE_REALCREDS)) {
		WARN(1, "denying ptrace access check without PTRACE_MODE_*CREDS\n");
		return -EPERM;
	}

	/* May we inspect the given task?
	 * This check is used both for attaching with ptrace
	 * and for allowing access to sensitive information in /proc.
	 *
	 * ptrace_attach denies several cases that /proc allows
	 * because setting up the necessary parent/child relationship
	 * or halting the specified task is impossible.
	 */

	/* Don't let security modules deny introspection */
	if (same_thread_group(task, current))
		return 0;
	rcu_read_lock();
	if (mode & PTRACE_MODE_FSCREDS) {
		caller_uid = cred->fsuid;
		caller_gid = cred->fsgid;
	} else {
		/*
		 * Using the euid would make more sense here, but something
		 * in userland might rely on the old behavior, and this
		 * shouldn't be a security problem since
		 * PTRACE_MODE_REALCREDS implies that the caller explicitly
		 * used a syscall that requests access to another process
		 * (and not a filesystem syscall to procfs).
		 */
		caller_uid = cred->uid;
		caller_gid = cred->gid;
	}
	tcred = __task_cred(task);
	if (uid_eq(caller_uid, tcred->euid) &&
	    uid_eq(caller_uid, tcred->suid) &&
	    uid_eq(caller_uid, tcred->uid)  &&
	    gid_eq(caller_gid, tcred->egid) &&
	    gid_eq(caller_gid, tcred->sgid) &&
	    gid_eq(caller_gid, tcred->gid))
		goto ok;
	if (ptrace_has_cap(tcred->user_ns, mode))
		goto ok;
	rcu_read_unlock();
	return -EPERM;
ok:
	rcu_read_unlock();
	/*
	 * If a task drops privileges and becomes nondumpable (through a syscall
	 * like setresuid()) while we are trying to access it, we must ensure
	 * that the dumpability is read after the credentials; otherwise,
	 * we may be able to attach to a task that we shouldn't be able to
	 * attach to (as if the task had dropped privileges without becoming
	 * nondumpable).
	 * Pairs with a write barrier in commit_creds().
	 */
	smp_rmb();
	if (!task_still_dumpable(task, mode))
		return -EPERM;

	return security_ptrace_access_check(task, mode);
}

bool ptrace_may_access(struct task_struct *task, unsigned int mode)
{
	int err;
	task_lock(task);
	err = __ptrace_may_access(task, mode);
	task_unlock(task);
	return !err;
}

static int ptrace_attach(struct task_struct *task, long request,
			 unsigned long addr,
			 unsigned long flags)
{
	bool seize = (request == PTRACE_SEIZE);
	int retval;

	retval = -EIO;
	if (seize) {
		if (addr != 0)
			goto out;
		if (flags & ~(unsigned long)PTRACE_O_MASK)
			goto out;
		flags = PT_PTRACED | PT_SEIZED | (flags << PT_OPT_FLAG_SHIFT);
	} else {
		flags = PT_PTRACED;
	}

	audit_ptrace(task);

	retval = -EPERM;
	if (unlikely(task->flags & PF_KTHREAD))
		goto out;
	if (same_thread_group(task, current))
		goto out;

	/*
	 * Protect exec's credential calculations against our interference;
	 * SUID, SGID and LSM creds get determined differently
	 * under ptrace.
	 */
	retval = -ERESTARTNOINTR;
	if (mutex_lock_interruptible(&task->signal->cred_guard_mutex))
		goto out;

	task_lock(task);
	retval = __ptrace_may_access(task, PTRACE_MODE_ATTACH_REALCREDS);
	task_unlock(task);
	if (retval)
		goto unlock_creds;

	write_lock_irq(&tasklist_lock);
	retval = -EPERM;
	if (unlikely(task->exit_state))
		goto unlock_tasklist;
	if (task->ptrace)
		goto unlock_tasklist;

	if (seize)
		flags |= PT_SEIZED;
	task->ptrace = flags;

	ptrace_link(task, current);

	/* SEIZE doesn't trap tracee on attach */
	if (!seize)
		send_sig_info(SIGSTOP, SEND_SIG_FORCED, task);

	spin_lock(&task->sighand->siglock);

	/*
	 * If the task is already STOPPED, set JOBCTL_TRAP_STOP and
	 * TRAPPING, and kick it so that it transits to TRACED.  TRAPPING
	 * will be cleared if the child completes the transition or any
	 * event which clears the group stop states happens.  We'll wait
	 * for the transition to complete before returning from this
	 * function.
	 *
	 * This hides STOPPED -> RUNNING -> TRACED transition from the
	 * attaching thread but a different thread in the same group can
	 * still observe the transient RUNNING state.  IOW, if another
	 * thread's WNOHANG wait(2) on the stopped tracee races against
	 * ATTACH, the wait(2) may fail due to the transient RUNNING.
	 *
	 * The following task_is_stopped() test is safe as both transitions
	 * in and out of STOPPED are protected by siglock.
	 */
	if (task_is_stopped(task) &&
	    task_set_jobctl_pending(task, JOBCTL_TRAP_STOP | JOBCTL_TRAPPING))
		signal_wake_up_state(task, __TASK_STOPPED);

	spin_unlock(&task->sighand->siglock);

	retval = 0;
unlock_tasklist:
	write_unlock_irq(&tasklist_lock);
unlock_creds:
	mutex_unlock(&task->signal->cred_guard_mutex);
out:
	if (!retval) {
		/*
		 * We do not bother to change retval or clear JOBCTL_TRAPPING
		 * if wait_on_bit() was interrupted by SIGKILL. The tracer will
		 * not return to user-mode, it will exit and clear this bit in
		 * __ptrace_unlink() if it wasn't already cleared by the tracee;
		 * and until then nobody can ptrace this task.
		 */
		wait_on_bit(&task->jobctl, JOBCTL_TRAPPING_BIT, TASK_KILLABLE);
		proc_ptrace_connector(task, PTRACE_ATTACH);
	}

	return retval;
}

/**
 * ptrace_traceme  --  helper for PTRACE_TRACEME
 *
 * Performs checks and sets PT_PTRACED.
 * Should be used by all ptrace implementations for PTRACE_TRACEME.
 */
static int ptrace_traceme(void)
{
	int ret = -EPERM;

	write_lock_irq(&tasklist_lock);
	/* Are we already being traced? */
	if (!current->ptrace) {
		ret = security_ptrace_traceme(current->parent);
		/*
		 * Check PF_EXITING to ensure ->real_parent has not passed
		 * exit_ptrace(). Otherwise we don't report the error but
		 * pretend ->real_parent untraces us right after return.
		 */
		if (!ret && !(current->real_parent->flags & PF_EXITING)) {
			current->ptrace = PT_PTRACED;
			ptrace_link(current, current->real_parent);
		}
	}
	write_unlock_irq(&tasklist_lock);

	return ret;
}

/*
 * Called with irqs disabled, returns true if childs should reap themselves.
 */
static int ignoring_children(struct sighand_struct *sigh)
{
	int ret;
	spin_lock(&sigh->siglock);
	ret = (sigh->action[SIGCHLD-1].sa.sa_handler == SIG_IGN) ||
	      (sigh->action[SIGCHLD-1].sa.sa_flags & SA_NOCLDWAIT);
	spin_unlock(&sigh->siglock);
	return ret;
}

/*
 * Called with tasklist_lock held for writing.
 * Unlink a traced task, and clean it up if it was a traced zombie.
 * Return true if it needs to be reaped with release_task().
 * (We can't call release_task() here because we already hold tasklist_lock.)
 *
 * If it's a zombie, our attachedness prevented normal parent notification
 * or self-reaping.  Do notification now if it would have happened earlier.
 * If it should reap itself, return true.
 *
 * If it's our own child, there is no notification to do. But if our normal
 * children self-reap, then this child was prevented by ptrace and we must
 * reap it now, in that case we must also wake up sub-threads sleeping in
 * do_wait().
 */
static bool __ptrace_detach(struct task_struct *tracer, struct task_struct *p)
{
	bool dead;

	__ptrace_unlink(p);

	if (p->exit_state != EXIT_ZOMBIE)
		return false;

	dead = !thread_group_leader(p);

	if (!dead && thread_group_empty(p)) {
		if (!same_thread_group(p->real_parent, tracer))
			dead = do_notify_parent(p, p->exit_signal);
		else if (ignoring_children(tracer->sighand)) {
			__wake_up_parent(p, tracer);
			dead = true;
		}
	}
	/* Mark it as in the process of being reaped. */
	if (dead)
		p->exit_state = EXIT_DEAD;
	return dead;
}

static int ptrace_detach(struct task_struct *child, unsigned int data)
{
	if (!valid_signal(data))
		return -EIO;

	/* Architecture-specific hardware disable .. */
	ptrace_disable(child);

	write_lock_irq(&tasklist_lock);
	/*
	 * We rely on ptrace_freeze_traced(). It can't be killed and
	 * untraced by another thread, it can't be a zombie.
	 */
	WARN_ON(!child->ptrace || child->exit_state);
	/*
	 * tasklist_lock avoids the race with wait_task_stopped(), see
	 * the comment in ptrace_resume().
	 */
	child->exit_code = data;
	__ptrace_detach(current, child);
	write_unlock_irq(&tasklist_lock);

	proc_ptrace_connector(child, PTRACE_DETACH);

	return 0;
}

/*
 * Detach all tasks we were using ptrace on. Called with tasklist held
 * for writing.
 */
void exit_ptrace(struct task_struct *tracer, struct list_head *dead)
{
	struct task_struct *p, *n;

	list_for_each_entry_safe(p, n, &tracer->ptraced, ptrace_entry) {
		if (unlikely(p->ptrace & PT_EXITKILL))
			send_sig_info(SIGKILL, SEND_SIG_FORCED, p);

		if (__ptrace_detach(tracer, p))
			list_add(&p->ptrace_entry, dead);
	}
}

int ptrace_readdata(struct task_struct *tsk, unsigned long src, char __user *dst, int len)
{
	int copied = 0;

	while (len > 0) {
		char buf[128];
		int this_len, retval;

		this_len = (len > sizeof(buf)) ? sizeof(buf) : len;
		retval = ptrace_access_vm(tsk, src, buf, this_len, FOLL_FORCE);

		if (!retval) {
			if (copied)
				break;
			return -EIO;
		}
		if (copy_to_user(dst, buf, retval))
			return -EFAULT;
		copied += retval;
		src += retval;
		dst += retval;
		len -= retval;
	}
	return copied;
}

int ptrace_writedata(struct task_struct *tsk, char __user *src, unsigned long dst, int len)
{
	int copied = 0;

	while (len > 0) {
		char buf[128];
		int this_len, retval;

		this_len = (len > sizeof(buf)) ? sizeof(buf) : len;
		if (copy_from_user(buf, src, this_len))
			return -EFAULT;
		retval = ptrace_access_vm(tsk, dst, buf, this_len,
				FOLL_FORCE | FOLL_WRITE);
		if (!retval) {
			if (copied)
				break;
			return -EIO;
		}
		copied += retval;
		src += retval;
		dst += retval;
		len -= retval;
	}
	return copied;
}

static int ptrace_setoptions(struct task_struct *child, unsigned long data)
{
	unsigned flags;

	if (data & ~(unsigned long)PTRACE_O_MASK)
		return -EINVAL;

	if (unlikely(data & PTRACE_O_SUSPEND_SECCOMP)) {
		if (!IS_ENABLED(CONFIG_CHECKPOINT_RESTORE) ||
		    !IS_ENABLED(CONFIG_SECCOMP))
			return -EINVAL;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;

		if (seccomp_mode(&current->seccomp) != SECCOMP_MODE_DISABLED ||
		    current->ptrace & PT_SUSPEND_SECCOMP)
			return -EPERM;
	}

	/* Avoid intermediate state when all opts are cleared */
	flags = child->ptrace;
	flags &= ~(PTRACE_O_MASK << PT_OPT_FLAG_SHIFT);
	flags |= (data << PT_OPT_FLAG_SHIFT);
	child->ptrace = flags;

	return 0;
}

static int ptrace_getsiginfo(struct task_struct *child, siginfo_t *info)
{
	unsigned long flags;
	int error = -ESRCH;

	if (lock_task_sighand(child, &flags)) {
		error = -EINVAL;
		if (likely(child->last_siginfo != NULL)) {
			copy_siginfo(info, child->last_siginfo);
			error = 0;
		}
		unlock_task_sighand(child, &flags);
	}
	return error;
}

static int ptrace_setsiginfo(struct task_struct *child, const siginfo_t *info)
{
	unsigned long flags;
	int error = -ESRCH;

	if (lock_task_sighand(child, &flags)) {
		error = -EINVAL;
		if (likely(child->last_siginfo != NULL)) {
			copy_siginfo(child->last_siginfo, info);
			error = 0;
		}
		unlock_task_sighand(child, &flags);
	}
	return error;
}

static int ptrace_peek_siginfo(struct task_struct *child,
				unsigned long addr,
				unsigned long data)
{
	struct ptrace_peeksiginfo_args arg;
	struct sigpending *pending;
	struct sigqueue *q;
	int ret, i;

	ret = copy_from_user(&arg, (void __user *) addr,
				sizeof(struct ptrace_peeksiginfo_args));
	if (ret)
		return -EFAULT;

	if (arg.flags & ~PTRACE_PEEKSIGINFO_SHARED)
		return -EINVAL; /* unknown flags */

	if (arg.nr < 0)
		return -EINVAL;

	if (arg.flags & PTRACE_PEEKSIGINFO_SHARED)
		pending = &child->signal->shared_pending;
	else
		pending = &child->pending;

	for (i = 0; i < arg.nr; ) {
		siginfo_t info;
		s32 off = arg.off + i;

		spin_lock_irq(&child->sighand->siglock);
		list_for_each_entry(q, &pending->list, list) {
			if (!off--) {
				copy_siginfo(&info, &q->info);
				break;
			}
		}
		spin_unlock_irq(&child->sighand->siglock);

		if (off >= 0) /* beyond the end of the list */
			break;

#ifdef CONFIG_COMPAT
		if (unlikely(in_compat_syscall())) {
			compat_siginfo_t __user *uinfo = compat_ptr(data);

			if (copy_siginfo_to_user32(uinfo, &info)) {
				ret = -EFAULT;
				break;
			}

		} else
#endif
		{
			siginfo_t __user *uinfo = (siginfo_t __user *) data;

			if (copy_siginfo_to_user(uinfo, &info)) {
				ret = -EFAULT;
				break;
			}
		}

		data += sizeof(siginfo_t);
		i++;

		if (signal_pending(current))
			break;

		cond_resched();
	}

	if (i > 0)
		return i;

	return ret;
}

#ifdef PTRACE_SINGLESTEP
#define is_singlestep(request)		((request) == PTRACE_SINGLESTEP)
#else
#define is_singlestep(request)		0
#endif

#ifdef PTRACE_SINGLEBLOCK
#define is_singleblock(request)		((request) == PTRACE_SINGLEBLOCK)
#else
#define is_singleblock(request)		0
#endif

#ifdef PTRACE_SYSEMU
#define is_sysemu_singlestep(request)	((request) == PTRACE_SYSEMU_SINGLESTEP)
#else
#define is_sysemu_singlestep(request)	0
#endif

static int ptrace_resume(struct task_struct *child, long request,
			 unsigned long data)
{
	bool need_siglock;

	if (!valid_signal(data))
		return -EIO;

	if (request == PTRACE_SYSCALL)
		set_tsk_thread_flag(child, TIF_SYSCALL_TRACE);
	else
		clear_tsk_thread_flag(child, TIF_SYSCALL_TRACE);

#ifdef TIF_SYSCALL_EMU
	if (request == PTRACE_SYSEMU || request == PTRACE_SYSEMU_SINGLESTEP)
		set_tsk_thread_flag(child, TIF_SYSCALL_EMU);
	else
		clear_tsk_thread_flag(child, TIF_SYSCALL_EMU);
#endif

	if (is_singleblock(request)) {
		if (unlikely(!arch_has_block_step()))
			return -EIO;
		user_enable_block_step(child);
	} else if (is_singlestep(request) || is_sysemu_singlestep(request)) {
		if (unlikely(!arch_has_single_step()))
			return -EIO;
		user_enable_single_step(child);
	} else {
		user_disable_single_step(child);
	}

	/*
	 * Change ->exit_code and ->state under siglock to avoid the race
	 * with wait_task_stopped() in between; a non-zero ->exit_code will
	 * wrongly look like another report from tracee.
	 *
	 * Note that we need siglock even if ->exit_code == data and/or this
	 * status was not reported yet, the new status must not be cleared by
	 * wait_task_stopped() after resume.
	 *
	 * If data == 0 we do not care if wait_task_stopped() reports the old
	 * status and clears the code too; this can't race with the tracee, it
	 * takes siglock after resume.
	 */
	need_siglock = data && !thread_group_empty(current);
	if (need_siglock)
		spin_lock_irq(&child->sighand->siglock);
	child->exit_code = data;
	wake_up_state(child, __TASK_TRACED);
	if (need_siglock)
		spin_unlock_irq(&child->sighand->siglock);

	return 0;
}

#ifdef CONFIG_HAVE_ARCH_TRACEHOOK

static const struct user_regset *
find_regset(const struct user_regset_view *view, unsigned int type)
{
	const struct user_regset *regset;
	int n;

	for (n = 0; n < view->n; ++n) {
		regset = view->regsets + n;
		if (regset->core_note_type == type)
			return regset;
	}

	return NULL;
}

static int ptrace_regset(struct task_struct *task, int req, unsigned int type,
			 struct iovec *kiov)
{
	const struct user_regset_view *view = task_user_regset_view(task);
	const struct user_regset *regset = find_regset(view, type);
	int regset_no;

	if (!regset || (kiov->iov_len % regset->size) != 0)
		return -EINVAL;

	regset_no = regset - view->regsets;
	kiov->iov_len = min(kiov->iov_len,
			    (__kernel_size_t) (regset->n * regset->size));

	if (req == PTRACE_GETREGSET)
		return copy_regset_to_user(task, view, regset_no, 0,
					   kiov->iov_len, kiov->iov_base);
	else
		return copy_regset_from_user(task, view, regset_no, 0,
					     kiov->iov_len, kiov->iov_base);
}

/*
 * This is declared in linux/regset.h and defined in machine-dependent
 * code.  We put the export here, near the primary machine-neutral use,
 * to ensure no machine forgets it.
 */
EXPORT_SYMBOL_GPL(task_user_regset_view);
#endif

int ptrace_request(struct task_struct *child, long request,
		   unsigned long addr, unsigned long data)
{
	bool seized = child->ptrace & PT_SEIZED;
	int ret = -EIO;
	siginfo_t siginfo, *si;
	void __user *datavp = (void __user *) data;
	unsigned long __user *datalp = datavp;
	unsigned long flags;

	switch (request) {
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		return generic_ptrace_peekdata(child, addr, data);
	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
		return generic_ptrace_pokedata(child, addr, data);

#ifdef PTRACE_OLDSETOPTIONS
	case PTRACE_OLDSETOPTIONS:
#endif
	case PTRACE_SETOPTIONS:
		ret = ptrace_setoptions(child, data);
		break;
	case PTRACE_GETEVENTMSG:
		ret = put_user(child->ptrace_message, datalp);
		break;

	case PTRACE_PEEKSIGINFO:
		ret = ptrace_peek_siginfo(child, addr, data);
		break;

	case PTRACE_GETSIGINFO:
		ret = ptrace_getsiginfo(child, &siginfo);
		if (!ret)
			ret = copy_siginfo_to_user(datavp, &siginfo);
		break;

	case PTRACE_SETSIGINFO:
		if (copy_from_user(&siginfo, datavp, sizeof siginfo))
			ret = -EFAULT;
		else
			ret = ptrace_setsiginfo(child, &siginfo);
		break;

	case PTRACE_GETSIGMASK:
		if (addr != sizeof(sigset_t)) {
			ret = -EINVAL;
			break;
		}

		if (copy_to_user(datavp, &child->blocked, sizeof(sigset_t)))
			ret = -EFAULT;
		else
			ret = 0;

		break;

	case PTRACE_SETSIGMASK: {
		sigset_t new_set;

		if (addr != sizeof(sigset_t)) {
			ret = -EINVAL;
			break;
		}

		if (copy_from_user(&new_set, datavp, sizeof(sigset_t))) {
			ret = -EFAULT;
			break;
		}

		sigdelsetmask(&new_set, sigmask(SIGKILL)|sigmask(SIGSTOP));

		/*
		 * Every thread does recalc_sigpending() after resume, so
		 * retarget_shared_pending() and recalc_sigpending() are not
		 * called here.
		 */
		spin_lock_irq(&child->sighand->siglock);
		child->blocked = new_set;
		spin_unlock_irq(&child->sighand->siglock);

		ret = 0;
		break;
	}

	case PTRACE_INTERRUPT:
		/*
		 * Stop tracee without any side-effect on signal or job
		 * control.  At least one trap is guaranteed to happen
		 * after this request.  If @child is already trapped, the
		 * current trap is not disturbed and another trap will
		 * happen after the current trap is ended with PTRACE_CONT.
		 *
		 * The actual trap might not be PTRACE_EVENT_STOP trap but
		 * the pending condition is cleared regardless.
		 */
		if (unlikely(!seized || !lock_task_sighand(child, &flags)))
			break;

		/*
		 * INTERRUPT doesn't disturb existing trap sans one
		 * exception.  If ptracer issued LISTEN for the current
		 * STOP, this INTERRUPT should clear LISTEN and re-trap
		 * tracee into STOP.
		 */
		if (likely(task_set_jobctl_pending(child, JOBCTL_TRAP_STOP)))
			ptrace_signal_wake_up(child, child->jobctl & JOBCTL_LISTENING);

		unlock_task_sighand(child, &flags);
		ret = 0;
		break;

	case PTRACE_LISTEN:
		/*
		 * Listen for events.  Tracee must be in STOP.  It's not
		 * resumed per-se but is not considered to be in TRACED by
		 * wait(2) or ptrace(2).  If an async event (e.g. group
		 * stop state change) happens, tracee will enter STOP trap
		 * again.  Alternatively, ptracer can issue INTERRUPT to
		 * finish listening and re-trap tracee into STOP.
		 */
		if (unlikely(!seized || !lock_task_sighand(child, &flags)))
			break;

		si = child->last_siginfo;
		if (likely(si && (si->si_code >> 8) == PTRACE_EVENT_STOP)) {
			child->jobctl |= JOBCTL_LISTENING;
			/*
			 * If NOTIFY is set, it means event happened between
			 * start of this trap and now.  Trigger re-trap.
			 */
			if (child->jobctl & JOBCTL_TRAP_NOTIFY)
				ptrace_signal_wake_up(child, true);
			ret = 0;
		}
		unlock_task_sighand(child, &flags);
		break;

	case PTRACE_DETACH:	 /* detach a process that was attached. */
		ret = ptrace_detach(child, data);
		break;

#ifdef CONFIG_BINFMT_ELF_FDPIC
	case PTRACE_GETFDPIC: {
		struct mm_struct *mm = get_task_mm(child);
		unsigned long tmp = 0;

		ret = -ESRCH;
		if (!mm)
			break;

		switch (addr) {
		case PTRACE_GETFDPIC_EXEC:
			tmp = mm->context.exec_fdpic_loadmap;
			break;
		case PTRACE_GETFDPIC_INTERP:
			tmp = mm->context.interp_fdpic_loadmap;
			break;
		default:
			break;
		}
		mmput(mm);

		ret = put_user(tmp, datalp);
		break;
	}
#endif

#ifdef PTRACE_SINGLESTEP
	case PTRACE_SINGLESTEP:
#endif
#ifdef PTRACE_SINGLEBLOCK
	case PTRACE_SINGLEBLOCK:
#endif
#ifdef PTRACE_SYSEMU
	case PTRACE_SYSEMU:
	case PTRACE_SYSEMU_SINGLESTEP:
#endif
	case PTRACE_SYSCALL:
	case PTRACE_CONT:
		return ptrace_resume(child, request, data);

	case PTRACE_KILL:
		if (child->exit_state)	/* already dead */
			return 0;
		return ptrace_resume(child, request, SIGKILL);

#ifdef CONFIG_HAVE_ARCH_TRACEHOOK
	case PTRACE_GETREGSET:
	case PTRACE_SETREGSET: {
		struct iovec kiov;
		struct iovec __user *uiov = datavp;

		if (!access_ok(VERIFY_WRITE, uiov, sizeof(*uiov)))
			return -EFAULT;

		if (__get_user(kiov.iov_base, &uiov->iov_base) ||
		    __get_user(kiov.iov_len, &uiov->iov_len))
			return -EFAULT;

		ret = ptrace_regset(child, request, addr, &kiov);
		if (!ret)
			ret = __put_user(kiov.iov_len, &uiov->iov_len);
		break;
	}
#endif

	case PTRACE_SECCOMP_GET_FILTER:
		ret = seccomp_get_filter(child, addr, datavp);
		break;

	case PTRACE_SECCOMP_GET_METADATA:
		ret = seccomp_get_metadata(child, addr, datavp);
		break;

	default:
		break;
	}

	return ret;
}

#ifndef arch_ptrace_attach
#define arch_ptrace_attach(child)	do { } while (0)
#endif

SYSCALL_DEFINE4(ptrace, long, request, long, pid, unsigned long, addr,
		unsigned long, data)
{
	struct task_struct *child;
	long ret;

	if (request == PTRACE_TRACEME) {
		ret = ptrace_traceme();
		if (!ret)
			arch_ptrace_attach(current);
		goto out;
	}

	child = find_get_task_by_vpid(pid);
	if (!child) {
		ret = -ESRCH;
		goto out;
	}

	if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
		ret = ptrace_attach(child, request, addr, data);
		/*
		 * Some architectures need to do book-keeping after
		 * a ptrace attach.
		 */
		if (!ret)
			arch_ptrace_attach(child);
		goto out_put_task_struct;
	}

	ret = ptrace_check_attach(child, request == PTRACE_KILL ||
				  request == PTRACE_INTERRUPT);
	if (ret < 0)
		goto out_put_task_struct;

	ret = arch_ptrace(child, request, addr, data);
	if (ret || request != PTRACE_DETACH)
		ptrace_unfreeze_traced(child);

 out_put_task_struct:
	put_task_struct(child);
 out:
	return ret;
}

int generic_ptrace_peekdata(struct task_struct *tsk, unsigned long addr,
			    unsigned long data)
{
	unsigned long tmp;
	int copied;

	copied = ptrace_access_vm(tsk, addr, &tmp, sizeof(tmp), FOLL_FORCE);
	if (copied != sizeof(tmp))
		return -EIO;
	return put_user(tmp, (unsigned long __user *)data);
}

int generic_ptrace_pokedata(struct task_struct *tsk, unsigned long addr,
			    unsigned long data)
{
	int copied;

	copied = ptrace_access_vm(tsk, addr, &data, sizeof(data),
			FOLL_FORCE | FOLL_WRITE);
	return (copied == sizeof(data)) ? 0 : -EIO;
}

#if defined CONFIG_COMPAT

int compat_ptrace_request(struct task_struct *child, compat_long_t request,
			  compat_ulong_t addr, compat_ulong_t data)
{
	compat_ulong_t __user *datap = compat_ptr(data);
	compat_ulong_t word;
	siginfo_t siginfo;
	int ret;

	switch (request) {
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		ret = ptrace_access_vm(child, addr, &word, sizeof(word),
				FOLL_FORCE);
		if (ret != sizeof(word))
			ret = -EIO;
		else
			ret = put_user(word, datap);
		break;

	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
		ret = ptrace_access_vm(child, addr, &data, sizeof(data),
				FOLL_FORCE | FOLL_WRITE);
		ret = (ret != sizeof(data) ? -EIO : 0);
		break;

	case PTRACE_GETEVENTMSG:
		ret = put_user((compat_ulong_t) child->ptrace_message, datap);
		break;

	case PTRACE_GETSIGINFO:
		ret = ptrace_getsiginfo(child, &siginfo);
		if (!ret)
			ret = copy_siginfo_to_user32(
				(struct compat_siginfo __user *) datap,
				&siginfo);
		break;

	case PTRACE_SETSIGINFO:
		if (copy_siginfo_from_user32(
			    &siginfo, (struct compat_siginfo __user *) datap))
			ret = -EFAULT;
		else
			ret = ptrace_setsiginfo(child, &siginfo);
		break;
#ifdef CONFIG_HAVE_ARCH_TRACEHOOK
	case PTRACE_GETREGSET:
	case PTRACE_SETREGSET:
	{
		struct iovec kiov;
		struct compat_iovec __user *uiov =
			(struct compat_iovec __user *) datap;
		compat_uptr_t ptr;
		compat_size_t len;

		if (!access_ok(VERIFY_WRITE, uiov, sizeof(*uiov)))
			return -EFAULT;

		if (__get_user(ptr, &uiov->iov_base) ||
		    __get_user(len, &uiov->iov_len))
			return -EFAULT;

		kiov.iov_base = compat_ptr(ptr);
		kiov.iov_len = len;

		ret = ptrace_regset(child, request, addr, &kiov);
		if (!ret)
			ret = __put_user(kiov.iov_len, &uiov->iov_len);
		break;
	}
#endif

	default:
		ret = ptrace_request(child, request, addr, data);
	}

	return ret;
}

COMPAT_SYSCALL_DEFINE4(ptrace, compat_long_t, request, compat_long_t, pid,
		       compat_long_t, addr, compat_long_t, data)
{
	struct task_struct *child;
	long ret;

	if (request == PTRACE_TRACEME) {
		ret = ptrace_traceme();
		goto out;
	}

	child = find_get_task_by_vpid(pid);
	if (!child) {
		ret = -ESRCH;
		goto out;
	}

	if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
		ret = ptrace_attach(child, request, addr, data);
		/*
		 * Some architectures need to do book-keeping after
		 * a ptrace attach.
		 */
		if (!ret)
			arch_ptrace_attach(child);
		goto out_put_task_struct;
	}

	ret = ptrace_check_attach(child, request == PTRACE_KILL ||
				  request == PTRACE_INTERRUPT);
	if (!ret) {
		ret = compat_arch_ptrace(child, request, addr, data);
		if (ret || request != PTRACE_DETACH)
			ptrace_unfreeze_traced(child);
	}

 out_put_task_struct:
	put_task_struct(child);
 out:
	return ret;
}
#endif	/* CONFIG_COMPAT */

void kabi_check_task_struct_user_dumpable(void)
{
	struct old_task_struct {
#ifdef CONFIG_THREAD_INFO_IN_TASK
		/*
		 * For reasons of header soup (see current_thread_info()), this
		 * must be the first element of task_struct.
		 */
		struct thread_info		thread_info;
#endif
		/* -1 unrunnable, 0 runnable, >0 stopped: */
		volatile long			state;

		/*
		 * This begins the randomizable portion of task_struct. Only
		 * scheduling-critical items should be added above here.
		 */
		randomized_struct_fields_start

		void				*stack;
		atomic_t			usage;
		/* Per task flags (PF_*), defined further below: */
		unsigned int			flags;
		unsigned int			ptrace;

#ifdef CONFIG_SMP
		struct llist_node		wake_entry;
		int				on_cpu;
#ifdef CONFIG_THREAD_INFO_IN_TASK
		/* Current CPU: */
		unsigned int			cpu;
#endif
		unsigned int			wakee_flips;
		unsigned long			wakee_flip_decay_ts;
		struct task_struct		*last_wakee;

		/*
		 * recent_used_cpu is initially set as the last CPU used by a task
		 * that wakes affine another task. Waker/wakee relationships can
		 * push tasks around a CPU where each wakeup moves to the next one.
		 * Tracking a recently used CPU allows a quick search for a recently
		 * used CPU that may be idle.
		 */
		int				recent_used_cpu;
		int				wake_cpu;
#endif
		int				on_rq;

		int				prio;
		int				static_prio;
		int				normal_prio;
		unsigned int			rt_priority;

		const struct sched_class	*sched_class;
		struct sched_entity		se;
		struct sched_rt_entity		rt;
#ifdef CONFIG_CGROUP_SCHED
		struct task_group		*sched_task_group;
#endif
		struct sched_dl_entity		dl;

#ifdef CONFIG_PREEMPT_NOTIFIERS
		/* List of struct preempt_notifier: */
		struct hlist_head		preempt_notifiers;
#endif

#ifdef CONFIG_BLK_DEV_IO_TRACE
		unsigned int			btrace_seq;
#endif

		unsigned int			policy;
		int				nr_cpus_allowed;
		cpumask_t			cpus_allowed;

#ifdef CONFIG_PREEMPT_RCU
		int				rcu_read_lock_nesting;
		union rcu_special		rcu_read_unlock_special;
		struct list_head		rcu_node_entry;
		struct rcu_node			*rcu_blocked_node;
#endif /* #ifdef CONFIG_PREEMPT_RCU */

#ifdef CONFIG_TASKS_RCU
		unsigned long			rcu_tasks_nvcsw;
		u8				rcu_tasks_holdout;
		u8				rcu_tasks_idx;
		int				rcu_tasks_idle_cpu;
		struct list_head		rcu_tasks_holdout_list;
#endif /* #ifdef CONFIG_TASKS_RCU */

		struct sched_info		sched_info;

		struct list_head		tasks;
#ifdef CONFIG_SMP
		struct plist_node		pushable_tasks;
		struct rb_node			pushable_dl_tasks;
#endif

		struct mm_struct		*mm;
		struct mm_struct		*active_mm;

		/* Per-thread vma caching: */
		struct vmacache			vmacache;

#ifdef SPLIT_RSS_COUNTING
		struct task_rss_stat		rss_stat;
#endif
		int				exit_state;
		int				exit_code;
		int				exit_signal;
		/* The signal sent when the parent dies: */
		int				pdeath_signal;
		/* JOBCTL_*, siglock protected: */
		unsigned long			jobctl;

		/* Used for emulating ABI behavior of previous Linux versions: */
		unsigned int			personality;

		/* Scheduler bits, serialized by scheduler locks: */
		unsigned			sched_reset_on_fork:1;
		unsigned			sched_contributes_to_load:1;
		unsigned			sched_migrated:1;
		unsigned			sched_remote_wakeup:1;
		/* Force alignment to the next boundary: */
		unsigned			:0;

		/* Unserialized, strictly 'current' */

		/* Bit to tell LSMs we're in execve(): */
		unsigned			in_execve:1;
		unsigned			in_iowait:1;
#ifndef TIF_RESTORE_SIGMASK
		unsigned			restore_sigmask:1;
#endif
#ifdef CONFIG_MEMCG
		unsigned			in_user_fault:1;
#ifdef CONFIG_MEMCG_KMEM
		unsigned			memcg_kmem_skip_account:1;
#endif
#endif
#ifdef CONFIG_COMPAT_BRK
		unsigned			brk_randomized:1;
#endif
#ifdef CONFIG_CGROUPS
		/* disallow userland-initiated cgroup migration */
		unsigned			no_cgroup_migration:1;
#endif
#ifdef CONFIG_BLK_CGROUP
		/* to be used once the psi infrastructure lands upstream. */
		unsigned			use_memdelay:1;
#endif
#ifndef __GENKSYMS__
		/**
		 * 7f53dd12fb0b ("ptrace: slightly saner 'get_dumpable()' logic")
		 * added the user_dumpable field, so hide it from genksyms to avoid
		 * kABI changes.  Also move it inside a hole to avoid changing
		 * offsets of other fields.
		 */
		/* Save user-dumpable when mm goes away */
		unsigned			user_dumpable:1;
#endif

		unsigned long			atomic_flags; /* Flags requiring atomic access. */

		struct restart_block		restart_block;

		pid_t				pid;
		pid_t				tgid;

#ifdef CONFIG_STACKPROTECTOR
		/* Canary value for the -fstack-protector GCC feature: */
		unsigned long			stack_canary;
#endif
		/*
		 * Pointers to the (original) parent process, youngest child, younger sibling,
		 * older sibling, respectively.  (p->father can be replaced with
		 * p->real_parent->pid)
		 */

		/* Real parent process: */
		struct task_struct __rcu	*real_parent;

		/* Recipient of SIGCHLD, wait4() reports: */
		struct task_struct __rcu	*parent;

		/*
		 * Children/sibling form the list of natural children:
		 */
		struct list_head		children;
		struct list_head		sibling;
		struct task_struct		*group_leader;

		/*
		 * 'ptraced' is the list of tasks this task is using ptrace() on.
		 *
		 * This includes both natural children and PTRACE_ATTACH targets.
		 * 'ptrace_entry' is this task's link on the p->parent->ptraced list.
		 */
		struct list_head		ptraced;
		struct list_head		ptrace_entry;

		/* PID/PID hash table linkage. */
		struct pid			*thread_pid;
		struct hlist_node		pid_links[PIDTYPE_MAX];
		struct list_head		thread_group;
		struct list_head		thread_node;

		struct completion		*vfork_done;

		/* CLONE_CHILD_SETTID: */
		int __user			*set_child_tid;

		/* CLONE_CHILD_CLEARTID: */
		int __user			*clear_child_tid;

		u64				utime;
		u64				stime;
#ifdef CONFIG_ARCH_HAS_SCALED_CPUTIME
		u64				utimescaled;
		u64				stimescaled;
#endif
		u64				gtime;
		struct prev_cputime		prev_cputime;
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
		struct vtime			vtime;
#endif

#ifdef CONFIG_NO_HZ_FULL
		atomic_t			tick_dep_mask;
#endif
		/* Context switch counts: */
		unsigned long			nvcsw;
		unsigned long			nivcsw;

		/* Monotonic time in nsecs: */
		u64				start_time;

		/* Boot based time in nsecs: */
		u64				real_start_time;

		/* MM fault and swap info: this can arguably be seen as either mm-specific or thread-specific: */
		unsigned long			min_flt;
		unsigned long			maj_flt;

#ifdef CONFIG_POSIX_TIMERS
		struct task_cputime		cputime_expires;
		struct list_head		cpu_timers[3];
#endif

		/* Process credentials: */

		/* Tracer's credentials at attach: */
		const struct cred __rcu		*ptracer_cred;

		/* Objective and real subjective task credentials (COW): */
		const struct cred __rcu		*real_cred;

		/* Effective (overridable) subjective task credentials (COW): */
		const struct cred __rcu		*cred;

		/*
		 * executable name, excluding path.
		 *
		 * - normally initialized setup_new_exec()
		 * - access it with [gs]et_task_comm()
		 * - lock it with task_lock()
		 */
		char				comm[TASK_COMM_LEN];

		struct nameidata		*nameidata;

#ifdef CONFIG_SYSVIPC
		struct sysv_sem			sysvsem;
		struct sysv_shm			sysvshm;
#endif
#ifdef CONFIG_DETECT_HUNG_TASK
		unsigned long			last_switch_count;
		unsigned long			last_switch_time;
#endif
		/* Filesystem information: */
		struct fs_struct		*fs;

		/* Open file information: */
		struct files_struct		*files;

		/* Namespaces: */
		struct nsproxy			*nsproxy;

		/* Signal handlers: */
		struct signal_struct		*signal;
		struct sighand_struct		*sighand;
		sigset_t			blocked;
		sigset_t			real_blocked;
		/* Restored if set_restore_sigmask() was used: */
		sigset_t			saved_sigmask;
		struct sigpending		pending;
		unsigned long			sas_ss_sp;
		size_t				sas_ss_size;
		unsigned int			sas_ss_flags;

		struct callback_head		*task_works;

		struct audit_context		*audit_context;
#ifdef CONFIG_AUDITSYSCALL
		kuid_t				loginuid;
		unsigned int			sessionid;
#endif
		struct seccomp			seccomp;

		/* Thread group tracking: */
		u32				parent_exec_id;
		u32				self_exec_id;

		/* Protection against (de-)allocation: mm, files, fs, tty, keyrings, mems_allowed, mempolicy: */
		spinlock_t			alloc_lock;

		/* Protection of the PI data structures: */
		raw_spinlock_t			pi_lock;

		struct wake_q_node		wake_q;

#ifdef CONFIG_RT_MUTEXES
		/* PI waiters blocked on a rt_mutex held by this task: */
		struct rb_root_cached		pi_waiters;
		/* Updated under owner's pi_lock and rq lock */
		struct task_struct		*pi_top_task;
		/* Deadlock detection and priority inheritance handling: */
		struct rt_mutex_waiter		*pi_blocked_on;
#endif

#ifdef CONFIG_DEBUG_MUTEXES
		/* Mutex deadlock detection: */
		struct mutex_waiter		*blocked_on;
#endif

#ifdef CONFIG_TRACE_IRQFLAGS
		unsigned int			irq_events;
		unsigned long			hardirq_enable_ip;
		unsigned long			hardirq_disable_ip;
		unsigned int			hardirq_enable_event;
		unsigned int			hardirq_disable_event;
		int				hardirqs_enabled;
		int				hardirq_context;
		unsigned long			softirq_disable_ip;
		unsigned long			softirq_enable_ip;
		unsigned int			softirq_disable_event;
		unsigned int			softirq_enable_event;
		int				softirqs_enabled;
		int				softirq_context;
#endif

#ifdef CONFIG_LOCKDEP
# define MAX_LOCK_DEPTH			48UL
		u64				curr_chain_key;
		int				lockdep_depth;
		unsigned int			lockdep_recursion;
		struct held_lock		held_locks[MAX_LOCK_DEPTH];
#endif

#ifdef CONFIG_UBSAN
		unsigned int			in_ubsan;
#endif

		/* Journalling filesystem info: */
		void				*journal_info;

		/* Stacked block device info: */
		struct bio_list			*bio_list;

#ifdef CONFIG_BLOCK
		/* Stack plugging: */
		struct blk_plug			*plug;
#endif

		/* VM state: */
		struct reclaim_state		*reclaim_state;

		struct backing_dev_info		*backing_dev_info;

		struct io_context		*io_context;

		/* Ptrace state: */
		unsigned long			ptrace_message;
		siginfo_t			*last_siginfo;

		struct task_io_accounting	ioac;
#ifdef CONFIG_TASK_XACCT
		/* Accumulated RSS usage: */
		u64				acct_rss_mem1;
		/* Accumulated virtual memory usage: */
		u64				acct_vm_mem1;
		/* stime + utime since last update: */
		u64				acct_timexpd;
#endif
#ifdef CONFIG_CPUSETS
		/* Protected by ->alloc_lock: */
		nodemask_t			mems_allowed;
		/* Seqence number to catch updates: */
		seqcount_t			mems_allowed_seq;
		int				cpuset_mem_spread_rotor;
		int				cpuset_slab_spread_rotor;
#endif
#ifdef CONFIG_CGROUPS
		/* Control Group info protected by css_set_lock: */
		struct css_set __rcu		*cgroups;
		/* cg_list protected by css_set_lock and tsk->alloc_lock: */
		struct list_head		cg_list;
#endif
#ifdef CONFIG_INTEL_RDT
		u32				closid;
		u32				rmid;
#endif
#ifdef CONFIG_FUTEX
		struct robust_list_head __user	*robust_list;
#ifdef CONFIG_COMPAT
		struct compat_robust_list_head __user *compat_robust_list;
#endif
		struct list_head		pi_state_list;
		struct futex_pi_state		*pi_state_cache;
#endif
#ifdef CONFIG_PERF_EVENTS
		struct perf_event_context	*perf_event_ctxp[perf_nr_task_contexts];
		struct mutex			perf_event_mutex;
		struct list_head		perf_event_list;
#endif
#ifdef CONFIG_DEBUG_PREEMPT
		unsigned long			preempt_disable_ip;
#endif
#ifdef CONFIG_NUMA
		/* Protected by alloc_lock: */
		struct mempolicy		*mempolicy;
		short				il_prev;
		short				pref_node_fork;
#endif
#ifdef CONFIG_NUMA_BALANCING
		int				numa_scan_seq;
		unsigned int			numa_scan_period;
		unsigned int			numa_scan_period_max;
		int				numa_preferred_nid;
		unsigned long			numa_migrate_retry;
		/* Migration stamp: */
		u64				node_stamp;
		u64				last_task_numa_placement;
		u64				last_sum_exec_runtime;
		struct callback_head		numa_work;

		struct numa_group		*numa_group;

		/*
		 * numa_faults is an array split into four regions:
		 * faults_memory, faults_cpu, faults_memory_buffer, faults_cpu_buffer
		 * in this precise order.
		 *
		 * faults_memory: Exponential decaying average of faults on a per-node
		 * basis. Scheduling placement decisions are made based on these
		 * counts. The values remain static for the duration of a PTE scan.
		 * faults_cpu: Track the nodes the process was running on when a NUMA
		 * hinting fault was incurred.
		 * faults_memory_buffer and faults_cpu_buffer: Record faults per node
		 * during the current scan window. When the scan completes, the counts
		 * in faults_memory and faults_cpu decay and these values are copied.
		 */
		unsigned long			*numa_faults;
		unsigned long			total_numa_faults;

		/*
		 * numa_faults_locality tracks if faults recorded during the last
		 * scan window were remote/local or failed to migrate. The task scan
		 * period is adapted based on the locality of the faults with different
		 * weights depending on whether they were shared or private faults
		 */
		unsigned long			numa_faults_locality[3];

		unsigned long			numa_pages_migrated;
#endif /* CONFIG_NUMA_BALANCING */

#ifdef CONFIG_RSEQ
		struct rseq __user *rseq;
		u32 rseq_len;
		u32 rseq_sig;
		/*
		 * RmW on rseq_event_mask must be performed atomically
		 * with respect to preemption.
		 */
		unsigned long rseq_event_mask;
#endif

		struct tlbflush_unmap_batch	tlb_ubc;

		struct rcu_head			rcu;

		/* Cache last used pipe for splice(): */
		struct pipe_inode_info		*splice_pipe;

		struct page_frag		task_frag;

#ifdef CONFIG_TASK_DELAY_ACCT
		struct task_delay_info		*delays;
#endif

#ifdef CONFIG_FAULT_INJECTION
		int				make_it_fail;
		unsigned int			fail_nth;
#endif
		/*
		 * When (nr_dirtied >= nr_dirtied_pause), it's time to call
		 * balance_dirty_pages() for a dirty throttling pause:
		 */
		int				nr_dirtied;
		int				nr_dirtied_pause;
		/* Start of a write-and-pause period: */
		unsigned long			dirty_paused_when;

#ifdef CONFIG_LATENCYTOP
		int				latency_record_count;
		struct latency_record		latency_record[LT_SAVECOUNT];
#endif
		/*
		 * Time slack values; these are used to round up poll() and
		 * select() etc timeout values. These are in nanoseconds.
		 */
		u64				timer_slack_ns;
		u64				default_timer_slack_ns;

#ifdef CONFIG_KASAN
		unsigned int			kasan_depth;
#endif

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
		/* Index of current stored address in ret_stack: */
		int				curr_ret_stack;
		int				curr_ret_depth;

		/* Stack of return addresses for return function tracing: */
		struct ftrace_ret_stack		*ret_stack;

		/* Timestamp for last schedule: */
		unsigned long long		ftrace_timestamp;

		/*
		 * Number of functions that haven't been traced
		 * because of depth overrun:
		 */
		atomic_t			trace_overrun;

		/* Pause tracing: */
		atomic_t			tracing_graph_pause;
#endif

#ifdef CONFIG_TRACING
		/* State flags for use by tracers: */
		unsigned long			trace;

		/* Bitmask and counter of trace recursion: */
		unsigned long			trace_recursion;
#endif /* CONFIG_TRACING */

#ifdef CONFIG_KCOV
		/* Coverage collection mode enabled for this task (0 if disabled): */
		unsigned int			kcov_mode;

		/* Size of the kcov_area: */
		unsigned int			kcov_size;

		/* Buffer for coverage collection: */
		void				*kcov_area;

		/* KCOV descriptor wired with this task or NULL: */
		struct kcov			*kcov;
#endif

#ifdef CONFIG_MEMCG
		struct mem_cgroup		*memcg_in_oom;
		gfp_t				memcg_oom_gfp_mask;
		int				memcg_oom_order;

		/* Number of pages to reclaim on returning to userland: */
		unsigned int			memcg_nr_pages_over_high;

		/* Used by memcontrol for targeted memcg charge: */
		struct mem_cgroup		*active_memcg;
#endif

#ifdef CONFIG_BLK_CGROUP
		struct request_queue		*throttle_queue;
#endif

#ifdef CONFIG_UPROBES
		struct uprobe_task		*utask;
#endif
#if defined(CONFIG_BCACHE) || defined(CONFIG_BCACHE_MODULE)
		unsigned int			sequential_io;
		unsigned int			sequential_io_avg;
#endif
#ifdef CONFIG_DEBUG_ATOMIC_SLEEP
		unsigned long			task_state_change;
#endif
		int				pagefault_disabled;
#ifdef CONFIG_MMU
		struct task_struct		*oom_reaper_list;
#endif
#ifdef CONFIG_VMAP_STACK
		struct vm_struct		*stack_vm_area;
#endif
#ifdef CONFIG_THREAD_INFO_IN_TASK
		/* A live task holds one reference: */
		atomic_t			stack_refcount;
#endif
#ifdef CONFIG_LIVEPATCH
		int patch_state;
#endif
#ifdef CONFIG_SECURITY
		/* Used by LSM modules for access restriction: */
		void				*security;
#endif

		/*
		 * New fields for task_struct should be added above here, so that
		 * they are included in the randomized portion of task_struct.
		 */
		randomized_struct_fields_end

		/* CPU-specific state of this task: */
		struct thread_struct		thread;

		/*
		 * WARNING: on x86, 'thread_struct' contains a variable-sized
		 * structure.  It *MUST* be at the end of 'task_struct'.
		 *
		 * Do not put anything below here!
		 */
	};
	BUILD_BUG_ON(sizeof(struct old_task_struct) != sizeof(struct task_struct));
	BUILD_BUG_ON(offsetof(struct old_task_struct, atomic_flags) != offsetof(struct task_struct, atomic_flags));
}
