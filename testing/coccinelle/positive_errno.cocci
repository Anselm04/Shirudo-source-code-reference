// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A function returns 0 or a negative error number, and its callers test
// for a value below 0: a bare error number, or errno itself, returned or
// put in ret, alone or as a branch of a conditional, passes as success.
// errno kept in err for a message is positive by design.

virtual report

@r@
attribute name SEC;
identifier E = {E2BIG, EACCES, EADDRINUSE, EADDRNOTAVAIL, EAFNOSUPPORT, EAGAIN,
		EALREADY, EBADF, EBADMSG, EBUSY, ECANCELED, ECHILD, ECONNABORTED,
		ECONNREFUSED, ECONNRESET, EDEADLK, EDESTADDRREQ, EDOM, EDQUOT,
		EEXIST, EFAULT, EFBIG, EHOSTUNREACH, EIDRM, EILSEQ, EINPROGRESS,
		EINTR, EINVAL, EIO, EISCONN, EISDIR, EKEYEXPIRED, EKEYREJECTED,
		EKEYREVOKED, ELOOP, EMFILE, EMLINK, EMSGSIZE, ENAMETOOLONG,
		ENETDOWN, ENETRESET, ENETUNREACH, ENFILE, ENOBUFS, ENODATA, ENODEV,
		ENOENT, ENOEXEC, ENOKEY, ENOLCK, ENOMEM, ENOMSG, ENOPROTOOPT,
		ENOSPC, ENOSYS, ENOTBLK, ENOTCONN, ENOTDIR, ENOTEMPTY, ENOTSOCK,
		ENOTSUP, ENOTTY, ENXIO, EOPNOTSUPP, EOVERFLOW, EPERM, EPIPE, EPROTO,
		EPROTONOSUPPORT, ERANGE, EROFS, ESPIPE, ESRCH, ESTALE, ETIME,
		ETIMEDOUT, ETXTBSY, EUCLEAN, EWOULDBLOCK, EXDEV, EHWPOISON};
identifier ret = {ret};
expression C, X;
position p;
@@
(
  return E@p;
|
  ret = E@p
|
  return errno@p;
|
  ret = errno@p
|
  return C ? \(E@p\|errno@p\) : X;
|
  return C ? X : \(E@p\|errno@p\);
|
  ret = C ? \(E@p\|errno@p\) : X
|
  ret = C ? X : \(E@p\|errno@p\)
)

@script:python depends on report@
p << r.p;
@@
coccilib.report.print_report(p[0], "a positive error number where a negative one is returned")
