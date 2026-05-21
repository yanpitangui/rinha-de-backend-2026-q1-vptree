const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const CTRL_SOCKETS = [2][]const u8{
    "/sockets/api1.sock",
    "/sockets/api2.sock",
};

const LISTEN_PORT: u16 = 9999;
const BACKLOG: u31 = 65535;
const CONNECT_RETRY_NS: u64 = 50 * std.time.ns_per_ms;
const CONNECT_MAX_RETRIES: u32 = 1200;
const MSG_NOSIGNAL: u32 = 0x4000;
const SCM_RIGHTS: i32 = 1;
fn checkErrno(ret: usize) !void {
    if (linux.errno(ret) != .SUCCESS) return error.Syscall;
}

fn passfd(ctrl_fd: i32, client_fd: i32) !void {
    var dummy: u8 = 0;
    var iov = posix.iovec_const{ .base = @ptrCast(&dummy), .len = 1 };

    const CMSG_BUF_LEN = 24;
    var cmsg_buf: [CMSG_BUF_LEN]u8 align(@alignOf(linux.cmsghdr)) = std.mem.zeroes([CMSG_BUF_LEN]u8);

    const cmsg: *linux.cmsghdr = @ptrCast(&cmsg_buf);
    cmsg.len = @sizeOf(linux.cmsghdr) + @sizeOf(i32);
    cmsg.level = linux.SOL.SOCKET;
    cmsg.type = SCM_RIGHTS;

    const fd_ptr: *i32 = @ptrCast(@alignCast(cmsg_buf[@sizeOf(linux.cmsghdr)..].ptr));
    fd_ptr.* = client_fd;

    const msg = linux.msghdr_const{
        .name = null,
        .namelen = 0,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = &cmsg_buf,
        .controllen = CMSG_BUF_LEN,
        .flags = 0,
    };

    const ret = linux.sendmsg(ctrl_fd, &msg, MSG_NOSIGNAL);
    if (linux.errno(ret) != .SUCCESS) return error.Syscall;
}

fn connectUnix(path: []const u8) !i32 {
    const ret = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    try checkErrno(ret);
    const sock: i32 = @intCast(ret);
    errdefer _ = linux.close(sock);

    var addr = linux.sockaddr.un{ .path = undefined };
    @memset(&addr.path, 0);
    if (path.len >= addr.path.len) return error.PathTooLong;
    @memcpy(addr.path[0..path.len], path);

    const addrlen: u32 = @intCast(@offsetOf(linux.sockaddr.un, "path") + path.len + 1);
    try checkErrno(linux.connect(sock, @ptrCast(&addr), addrlen));

    return sock;
}

fn connectWithRetry(path: []const u8) !i32 {
    var attempts: u32 = 0;
    while (attempts < CONNECT_MAX_RETRIES) : (attempts += 1) {
        if (connectUnix(path)) |fd| return fd else |_| {}
        var req = linux.timespec{ .sec = 0, .nsec = @intCast(CONNECT_RETRY_NS) };
        _ = linux.nanosleep(&req, null);
    }
    return error.ConnectTimeout;
}

fn makeListener() !i32 {
    const ret = linux.socket(
        linux.AF.INET,
        linux.SOCK.STREAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
        0,
    );
    try checkErrno(ret);
    const fd: i32 = @intCast(ret);
    errdefer _ = linux.close(fd);

    var one: i32 = 1;
    try checkErrno(linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&one), @sizeOf(i32)));
    try checkErrno(linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, @ptrCast(&one), @sizeOf(i32)));

    const addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, LISTEN_PORT),
        .addr = 0,
    };
    try checkErrno(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in)));
    try checkErrno(linux.listen(fd, BACKLOG));

    // Wake epoll only when request data has arrived, not on bare SYN.
    // Guarantees API's first recv() finds data already in socket buffer.
    var defer_secs: i32 = 1;
    _ = linux.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.DEFER_ACCEPT, @ptrCast(&defer_secs), @sizeOf(i32));

    return fd;
}

const WorkerCtx = struct { id: usize };

fn workerFn(ctx: WorkerCtx) void {
    var ctrl_fds: [CTRL_SOCKETS.len]i32 = .{-1} ** CTRL_SOCKETS.len;
    for (CTRL_SOCKETS, 0..) |path, i| {
        ctrl_fds[i] = connectWithRetry(path) catch {
            std.debug.print("worker[{}]: failed connect {s}\n", .{ ctx.id, path });
            return;
        };
    }
    defer for (ctrl_fds) |fd| {
        if (fd >= 0) _ = linux.close(fd);
    };

    const server_fd = makeListener() catch |err| {
        std.debug.print("worker[{}]: makeListener: {}\n", .{ ctx.id, err });
        return;
    };
    defer _ = linux.close(server_fd);

    const epfd_ret = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    if (linux.errno(epfd_ret) != .SUCCESS) {
        std.debug.print("worker[{}]: epoll_create1 failed\n", .{ctx.id});
        return;
    }
    const epfd: i32 = @intCast(epfd_ret);
    defer _ = linux.close(epfd);

    var ev = linux.epoll_event{
        .events = linux.EPOLL.IN,
        .data = .{ .fd = server_fd },
    };
    _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, server_fd, &ev);

    std.debug.print("worker[{}]: ready\n", .{ctx.id});

    const nodelay: i32 = 1;
    var events: [64]linux.epoll_event = undefined;
    var counter: u64 = 0;

    while (true) {
        const nret = linux.epoll_wait(epfd, &events, events.len, -1);
        if (linux.errno(nret) != .SUCCESS) continue;

        // Drain all pending connections after each epoll wake
        while (true) {
            const ar = linux.accept4(server_fd, null, null, linux.SOCK.CLOEXEC);
            const ae = linux.errno(ar);
            if (ae == .AGAIN) break;
            if (ae != .SUCCESS) break;
            const client_fd: i32 = @intCast(ar);

            _ = linux.setsockopt(client_fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, @ptrCast(&nodelay), @sizeOf(i32));

            const idx: usize = counter & 1;
            counter +%= 1;

            if (ctrl_fds[idx] < 0) {
                if (connectUnix(CTRL_SOCKETS[idx])) |new_fd| {
                    ctrl_fds[idx] = new_fd;
                } else |_| {}
            }

            const ctrl = if (ctrl_fds[idx] >= 0) ctrl_fds[idx] else ctrl_fds[idx ^ 1];
            passfd(ctrl, client_fd) catch {
                _ = linux.close(ctrl_fds[idx]);
                ctrl_fds[idx] = -1;
                // Retry with other API before dropping the client.
                if (ctrl_fds[idx ^ 1] >= 0) {
                    passfd(ctrl_fds[idx ^ 1], client_fd) catch {};
                }
            };
            _ = linux.close(client_fd);
        }
    }
}

const MAX_WORKERS: usize = 32;

pub fn main() !void {
    const workers: usize = blk: {
        const s = std.c.getenv("LB_WORKERS") orelse break :blk 2;
        const span = std.mem.span(s);
        break :blk std.fmt.parseInt(usize, span, 10) catch 2;
    };

    const clamped = @min(workers, MAX_WORKERS);
    std.debug.print("lb: starting {d} workers on :{d}\n", .{ clamped, LISTEN_PORT });

    var threads: [MAX_WORKERS]std.Thread = undefined;
    for (0..clamped) |i| {
        threads[i] = try std.Thread.spawn(.{}, workerFn, .{WorkerCtx{ .id = i }});
    }
    for (threads[0..clamped]) |*t| t.join();
}
