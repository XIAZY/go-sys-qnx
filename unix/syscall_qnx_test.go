// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build qnx

package unix_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestStatvfs(t *testing.T) {
	var st, fst unix.Statvfs_t
	if err := unix.Statvfs("/", &st); err != nil {
		t.Fatalf("Statvfs: %v", err)
	}
	if st.Bsize == 0 || st.Frsize == 0 || st.Blocks == 0 || st.Bfree > st.Blocks {
		t.Errorf("Statvfs(/) = %+v, want nonzero sizes and Bfree <= Blocks", st)
	}

	f, err := os.Open("/")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Fstatvfs(int(f.Fd()), &fst); err != nil {
		t.Fatalf("Fstatvfs: %v", err)
	}
	if fst.Fsid != st.Fsid || fst.Blocks != st.Blocks {
		t.Errorf("Fstatvfs(/) = %+v, Statvfs(/) = %+v, want the same file system", fst, st)
	}
}

// openPty opens a free BSD-style pseudo-terminal pair: QNX has
// /dev/ptyXY masters and /dev/ttyXY slaves, and no /dev/ptmx.
func openPty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	for _, c1 := range "pqrs" {
		for _, c2 := range "0123456789abcdef" {
			m, err := os.OpenFile(fmt.Sprintf("/dev/pty%c%c", c1, c2), os.O_RDWR, 0)
			if err != nil {
				continue
			}
			s, err := os.OpenFile(fmt.Sprintf("/dev/tty%c%c", c1, c2), os.O_RDWR, 0)
			if err != nil {
				m.Close()
				continue
			}
			t.Cleanup(func() { s.Close(); m.Close() })
			return m, s
		}
	}
	t.Skip("no free pseudo-terminal")
	return nil, nil
}

func TestIoctlWinsize(t *testing.T) {
	_, slave := openPty(t)
	fd := int(slave.Fd())
	want := unix.Winsize{Row: 24, Col: 80, Xpixel: 640, Ypixel: 480}
	if err := unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &want); err != nil {
		t.Fatalf("IoctlSetWinsize: %v", err)
	}
	got, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil {
		t.Fatalf("IoctlGetWinsize: %v", err)
	}
	if *got != want {
		t.Errorf("IoctlGetWinsize = %+v, want %+v", *got, want)
	}
}

func TestIoctlTermios(t *testing.T) {
	_, slave := openPty(t)
	fd := int(slave.Fd())
	tio, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		t.Fatalf("IoctlGetTermios: %v", err)
	}
	// Raw mode, as golang.org/x/term sets it, then back.
	raw := *tio
	raw.Lflag &^= unix.ECHO | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, &raw); err != nil {
		t.Fatalf("IoctlSetTermios: %v", err)
	}
	got, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		t.Fatalf("IoctlGetTermios: %v", err)
	}
	if got.Lflag&(unix.ECHO|unix.ICANON) != 0 {
		t.Errorf("Lflag = %#x after raw mode, want ECHO and ICANON clear", got.Lflag)
	}
	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, tio); err != nil {
		t.Fatalf("IoctlSetTermios (restore): %v", err)
	}
}

func TestIoctlNotATerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "notatty")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ); err != unix.ENOTTY {
		t.Errorf("IoctlGetWinsize on a file: %v, want ENOTTY", err)
	}
}

func TestFcntl(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "fcntl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd := f.Fd()
	flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
	if err != nil {
		t.Fatalf("F_GETFL: %v", err)
	}
	if flags&unix.O_ACCMODE != unix.O_RDWR {
		t.Errorf("F_GETFL = %#x, want O_RDWR", flags)
	}

	lk := unix.Flock_t{Type: unix.F_WRLCK, Whence: 0, Start: 0, Len: 0}
	if err := unix.FcntlFlock(fd, unix.F_SETLK, &lk); err != nil {
		t.Fatalf("F_SETLK: %v", err)
	}
	lk = unix.Flock_t{Type: unix.F_WRLCK}
	if err := unix.FcntlFlock(fd, unix.F_GETLK, &lk); err != nil {
		t.Fatalf("F_GETLK: %v", err)
	}
	// The lock is our own, so F_GETLK reports none in the way.
	if lk.Type != unix.F_UNLCK {
		t.Errorf("F_GETLK Type = %d, want F_UNLCK", lk.Type)
	}
}

func TestMmap(t *testing.T) {
	// Map at a nonzero offset, which mmap64 takes as a 64-bit argument.
	pagesize := unix.Getpagesize()
	data := make([]byte, 2*pagesize)
	for i := range data {
		data[i] = byte(i / pagesize)
	}
	name := filepath.Join(t.TempDir(), "mmap")
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := unix.Mmap(int(f.Fd()), int64(pagesize), pagesize, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	if b[0] != 1 || b[pagesize-1] != 1 {
		t.Errorf("mapped page holds %d..%d, want the second page (1)", b[0], b[pagesize-1])
	}
	if err := unix.Munmap(b); err != nil {
		t.Fatalf("Munmap: %v", err)
	}
}

func TestSeekLarge(t *testing.T) {
	// lseek64 takes and returns a 64-bit offset; check one above 4 GB
	// survives both ways. Seeking does not allocate.
	f, err := os.CreateTemp(t.TempDir(), "seek")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	const off int64 = 5<<30 + 123
	got, err := unix.Seek(int(f.Fd()), off, 0)
	if err != nil {
		t.Fatalf("Seek: %v", err)
	}
	if got != off {
		t.Errorf("Seek = %d, want %d", got, off)
	}
}

func TestPreadPwrite(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "pread")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd := int(f.Fd())
	if _, err := unix.Pwrite(fd, []byte("hello"), 100); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := unix.Pread(fd, buf, 100); err != nil {
		t.Fatalf("Pread: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("Pread = %q, want %q", buf, "hello")
	}
}

func TestSocketpairRights(t *testing.T) {
	// Passing a descriptor goes through sendmsg with control data, the
	// call bracketed against io-pkt.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	f, err := os.CreateTemp(t.TempDir(), "rights")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString("passed"); err != nil {
		t.Fatal(err)
	}

	rights := unix.UnixRights(int(f.Fd()))
	if err := unix.Sendmsg(fds[0], []byte("x"), rights, nil, 0); err != nil {
		t.Fatalf("Sendmsg: %v", err)
	}
	buf := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unix.Recvmsg(fds[1], buf, oob, 0)
	if err != nil {
		t.Fatalf("Recvmsg: %v", err)
	}
	if n != 1 || buf[0] != 'x' {
		t.Fatalf("Recvmsg data = %q, want %q", buf[:n], "x")
	}
	msgs, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		t.Fatalf("ParseSocketControlMessage: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("%d control messages, want 1", len(msgs))
	}
	got, err := unix.ParseUnixRights(&msgs[0])
	if err != nil {
		t.Fatalf("ParseUnixRights: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("%d descriptors, want 1", len(got))
	}
	defer unix.Close(got[0])
	b := make([]byte, 6)
	if _, err := unix.Pread(got[0], b, 0); err != nil {
		t.Fatalf("Pread on passed descriptor: %v", err)
	}
	if string(b) != "passed" {
		t.Errorf("passed descriptor reads %q, want %q", b, "passed")
	}
}

func TestBindInet(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatalf("Getsockname: %v", err)
	}
	in, ok := sa.(*unix.SockaddrInet4)
	if !ok || in.Port == 0 || in.Addr != [4]byte{127, 0, 0, 1} {
		t.Errorf("Getsockname = %#v, want 127.0.0.1 with a port", sa)
	}
}

// TestBindUnix binds a Unix socket to a name, the call bracketed against
// io-pkt. It runs only with GOQNX_TEST_SOCKET_NAMES=1: removing a socket
// name afterwards is what can hang QNX 6.5's io-pkt, so shared machines
// do not run it.
func TestBindUnix(t *testing.T) {
	if os.Getenv("GOQNX_TEST_SOCKET_NAMES") != "1" {
		t.Skip("set GOQNX_TEST_SOCKET_NAMES=1 to bind and remove socket names")
	}
	name := filepath.Join(t.TempDir(), "sock")
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socket: %v", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrUnix{Name: name}); err != nil {
		unix.Close(fd)
		t.Fatalf("Bind: %v", err)
	}
	sa, err := unix.Getsockname(fd)
	// Remove the name while the socket is open, the safe order.
	unix.Unlink(name)
	unix.Close(fd)
	if err != nil {
		t.Fatalf("Getsockname: %v", err)
	}
	if u, ok := sa.(*unix.SockaddrUnix); !ok || u.Name != name {
		t.Errorf("Getsockname = %#v, want %q", sa, name)
	}
}

func TestWait4(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 7")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var ws unix.WaitStatus
	pid, err := unix.Wait4(cmd.Process.Pid, &ws, 0, nil)
	if err != nil {
		t.Fatalf("Wait4: %v", err)
	}
	if pid != cmd.Process.Pid || !ws.Exited() || ws.ExitStatus() != 7 {
		t.Errorf("Wait4 = %d, status %#x (exited %v, status %d), want %d exited 7",
			pid, uint32(ws), ws.Exited(), ws.ExitStatus(), cmd.Process.Pid)
	}

	// Signal the child from here: QNX's sh, asked to kill -TERM $$,
	// signals its parent too (measured on BlackBerry 10).
	cmd = exec.Command("/bin/sh", "-c", "read x")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Kill(cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	if _, err := unix.Wait4(cmd.Process.Pid, &ws, 0, nil); err != nil {
		t.Fatalf("Wait4: %v", err)
	}
	if !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
		t.Errorf("status %#x: signaled %v, signal %v; want SIGTERM", uint32(ws), ws.Signaled(), ws.Signal())
	}
}

func TestGetwd(t *testing.T) {
	dir := t.TempDir()
	old, err := unix.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	defer unix.Chdir(old)
	if err := unix.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	got, err := unix.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got != want && got != dir {
		t.Errorf("Getwd = %q, want %q", got, want)
	}
}

func TestPipe(t *testing.T) {
	p := make([]int, 2)
	if err := unix.Pipe(p); err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])
	if _, err := unix.Write(p[1], []byte("ok")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b := make([]byte, 2)
	if _, err := unix.Read(p[0], b); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(b, []byte("ok")) {
		t.Errorf("Read = %q, want %q", b, "ok")
	}
}

func TestUtimesNano(t *testing.T) {
	name := filepath.Join(t.TempDir(), "times")
	if err := os.WriteFile(name, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	mtime := time.Date(2020, 1, 2, 3, 4, 5, 6000, time.UTC)
	ts := []unix.Timespec{
		{Nsec: unix.UTIME_OMIT},
		unix.NsecToTimespec(mtime.UnixNano()),
	}
	var before unix.Stat_t
	if err := unix.Stat(name, &before); err != nil {
		t.Fatal(err)
	}
	if err := unix.UtimesNano(name, ts); err != nil {
		t.Fatalf("UtimesNano: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Stat(name, &st); err != nil {
		t.Fatal(err)
	}
	if int64(st.Mtime) != mtime.Unix() {
		t.Errorf("Mtime = %d, want %d", st.Mtime, mtime.Unix())
	}
	if st.Atime != before.Atime {
		t.Errorf("Atime = %d, want unchanged %d (UTIME_OMIT)", st.Atime, before.Atime)
	}

	// Times QNX's unsigned 32-bit time_t cannot hold fail.
	ts = []unix.Timespec{unix.NsecToTimespec(-1e9), unix.NsecToTimespec(-1e9)}
	if err := unix.UtimesNano(name, ts); err != unix.EINVAL {
		t.Errorf("UtimesNano before 1970: %v, want EINVAL", err)
	}
}

func TestRlimit(t *testing.T) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatalf("Getrlimit: %v", err)
	}
	if lim.Cur == 0 || lim.Cur > lim.Max {
		t.Errorf("RLIMIT_NOFILE = %+v, want 0 < Cur <= Max", lim)
	}
	// RLIM_INFINITY is assignable to Rlimit's fields.
	_ = unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
	var stack unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_AS, &stack); err != nil {
		t.Fatalf("Getrlimit: %v", err)
	}
	t.Logf("RLIMIT_AS = %#x (RLIM_INFINITY %#x)", stack.Max, uint64(unix.RLIM_INFINITY))
}

func TestUname(t *testing.T) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		t.Fatalf("Uname: %v", err)
	}
	if s := unix.ByteSliceToString((*[unsafe.Sizeof(u.Sysname)]byte)(unsafe.Pointer(&u.Sysname))[:]); s != "QNX" {
		t.Errorf("Sysname = %q, want QNX", s)
	}
}

func TestSyscallTrapNumbers(t *testing.T) {
	// QNX has no system call numbers.
	if _, _, err := unix.Syscall(0, 0, 0, 0); err != unix.ENOSYS {
		t.Errorf("Syscall: %v, want ENOSYS", err)
	}
	if err := unix.Lutimes("/", nil); err != unix.ENOSYS {
		t.Errorf("Lutimes: %v, want ENOSYS", err)
	}
}
