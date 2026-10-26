//===----------------------------------------------------------------------===//
//
// This source file is part of the Swift open source project
//
// Copyright (c) 2026 Apple Inc. and the Swift project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of Swift project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#ifdef __linux__

#ifndef _GNU_SOURCE
#error You must define _GNU_SOURCE
#endif

#include <SwiftNetworkLinuxShim.h>
#include <errno.h>
#include <net/if.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <unistd.h>

char * SwiftNetworkLinuxShim_if_indextoname(int index, char * name)
{
    if (index < 0) {
        return NULL;
    }
    return if_indextoname((unsigned int)index, name);
}

uint64_t SwiftNetworkLinuxShim_getFDLimit()
{
    struct rlimit existing_limit;

    if (getrlimit(RLIMIT_NOFILE, &existing_limit) == 0) {
        return (uint64_t)existing_limit.rlim_cur;
    }
    return 0;
}

int SwiftNetworkLinuxShim_epollWatchingErrors(int fd)
{
    int epollFD = epoll_create1(EPOLL_CLOEXEC);
    if (epollFD < 0) {
        return -1;
    }
    // No requested events: epoll reports EPOLLERR and EPOLLHUP regardless.
    struct epoll_event event = { .events = 0 };
    if (epoll_ctl(epollFD, EPOLL_CTL_ADD, fd, &event) != 0) {
        int savedErrno = errno;
        close(epollFD);
        errno = savedErrno;
        return -1;
    }
    return epollFD;
}

#endif
