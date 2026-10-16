// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package unix

// Lutimes sets the access and modification times tv on path. If path refers to
// a symlink, it is not dereferenced and the timestamps are set on the symlink.
// If tv is nil, the access and modification times are set to the current time.
// Otherwise tv must contain exactly 2 elements, with access time as the first
// element and modification time as the second element.
func Lutimes(path string, tv []Timeval) error {
	if tv == nil {
		return UtimesNanoAt(AT_FDCWD, path, nil, AT_SYMLINK_NOFOLLOW)
	}
	if len(tv) != 2 {
		return EINVAL
	}
	ts := []Timespec{
		NsecToTimespec(TimevalToNsec(tv[0])),
		NsecToTimespec(TimevalToNsec(tv[1])),
	}
	return UtimesNanoAt(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW)
}
