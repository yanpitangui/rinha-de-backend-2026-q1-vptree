const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const CTRL_SOCKETS = [2][]const u8{
    "/sockets/api1.sock",
    "/sockets/api2.sock",
};

const LISTEN_PORT: u16 = 9999;
const BACKLOG: u31 = 1024;
const CONNECT_RETRY_NS: u64 = 200 * std.time.ns_per_ms;
const CONNECT_MAX_RETRIES: u32 = 600;
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
    if (linux.errno(ret) != .SUCCESS) {
        std.debug.print("lb: sendmsg errno={s}\n", .{@tagName(linux.errno(ret))});
        return error.Syscall;
    }
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
    const cr = linux.connect(sock, @ptrCast(&addr), addrlen);
    try checkErrno(cr);

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

pub fn main() !void {
    // TCP listener (blocking — accept4 will block until connection arrives)
    const srv = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    try checkErrno(srv);
    const server_fd: i32 = @intCast(srv);
    defer _ = linux.close(server_fd);

    var opt: i32 = 1;
    try checkErrno(linux.setsockopt(server_fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&opt), @sizeOf(i32)));
    try checkErrno(linux.setsockopt(server_fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, @ptrCast(&opt), @sizeOf(i32)));
    var defer_secs: i32 = 1;
    _ = linux.setsockopt(server_fd, linux.IPPROTO.TCP, linux.TCP.DEFER_ACCEPT, @ptrCast(&defer_secs), @sizeOf(i32));

    const addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, LISTEN_PORT),
        .addr = 0,
    };
    try checkErrno(linux.bind(server_fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.in)));
    try checkErrno(linux.listen(server_fd, BACKLOG));

    std.debug.print("lb: listening on :{d}\n", .{LISTEN_PORT});

    std.debug.print("lb: waiting for backends...\n", .{});
    var ctrl_fds: [2]i32 = undefined;
    for (CTRL_SOCKETS, 0..) |path, i| {
        ctrl_fds[i] = try connectWithRetry(path);
        std.debug.print("lb: connected to {s}\n", .{path});
    }
    defer for (ctrl_fds) |fd| {
        _ = linux.close(fd);
    };

    std.debug.print("lb: ready\n", .{});

    var counter: u64 = 0;
    while (true) {
        const ret = linux.accept4(server_fd, null, null, linux.SOCK.CLOEXEC);
        if (linux.errno(ret) != .SUCCESS) continue;
        const client_fd: i32 = @intCast(ret);
        const ctrl_fd = ctrl_fds[counter & 1];
        counter += 1;
        passfd(ctrl_fd, client_fd) catch |err| {
            std.debug.print("lb: passfd: {}\n", .{err});
        };
        _ = linux.close(client_fd);
    }
}
