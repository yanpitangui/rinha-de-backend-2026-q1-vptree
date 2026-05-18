using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using FraudApi.FraudDetection;

namespace FraudApi.Transport;

// Linux x86_64 kernel/glibc msghdr layout (56 bytes)
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct MsgHdr
{
    public void* msg_name;
    public uint msg_namelen;
    private uint _pad1;
    public IoVec* msg_iov;
    public nuint msg_iovlen;
    public void* msg_control;
    public nuint msg_controllen;
    public int msg_flags;
    private int _pad2;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct IoVec { public void* iov_base; public nuint iov_len; }

[StructLayout(LayoutKind.Sequential)]
internal struct CmsgHdr { public nuint cmsg_len; public int cmsg_level; public int cmsg_type; }

public static class RawServer
{
    private const int SolSocket = 1;
    private const int ScmRights = 1;
    private const int MsgNosignal = 0x4000;
    private const int IpprotoTcp = 6;
    private const int TcpNodelay = 1;

    [DllImport("libc", SetLastError = true)]
    private static extern unsafe nint recvmsg(int sockfd, MsgHdr* msg, int flags);

    [DllImport("libc")]
    private static extern unsafe int setsockopt(int sockfd, int level, int optname, int* optval, uint optlen);

    [DllImport("libc", SetLastError = true)]
    private static extern unsafe int recv(int sockfd, byte* buf, nuint len, int flags);

    [DllImport("libc", SetLastError = true)]
    private static extern unsafe int send(int sockfd, byte* buf, nuint len, int flags);

    [DllImport("libc")]
    private static extern int close(int fd);

    // Pre-built full HTTP responses (header + JSON body) for slots 0-5
    private static byte[][] s_responses = null!;

    private static readonly byte[] s_readyResp =
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"u8.ToArray();
    private static readonly byte[] s_badResp =
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"u8.ToArray();

    public static void Run(string socketPath)
    {
        // Pre-build full HTTP responses for all 6 fraud score slots
        var bodies = FraudHandler.Responses;
        s_responses = new byte[bodies.Length][];
        for (int i = 0; i < bodies.Length; i++)
        {
            var body = bodies[i];
            var hdr = System.Text.Encoding.ASCII.GetBytes(
                $"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {body.Length}\r\n\r\n");
            var full = new byte[hdr.Length + body.Length];
            hdr.CopyTo(full, 0);
            body.CopyTo(full, hdr.Length);
            s_responses[i] = full;
        }

        if (File.Exists(socketPath)) File.Delete(socketPath);
        var server = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        server.Bind(new UnixDomainSocketEndPoint(socketPath));
        server.Listen(4);
        System.Diagnostics.Process.Start("chmod", $"777 {socketPath}")?.WaitForExit();
        Console.WriteLine($"raw: bound {socketPath}");

        // Accept single persistent control connection from LB (blocking).
        // GC.KeepAlive pins the Socket objects through the blocking calls so
        // NativeAOT doesn't finalize (close) them before we're done.
        var ctrl = server.Accept();
        GC.KeepAlive(server);
        var ctrlFd = (int)ctrl.SafeHandle.DangerousGetHandle();
        Console.WriteLine("raw: lb connected");

        RecvLoop(ctrlFd);
        GC.KeepAlive(ctrl);
        Console.Error.WriteLine("raw: control lost, exiting");
    }

    private static unsafe void RecvLoop(int ctrlFd)
    {
        const int CmsgBufSize = 24;
        byte dummy = 0;
        byte* cmsgBuf = stackalloc byte[CmsgBufSize];

        while (true)
        {
            var iov = new IoVec { iov_base = &dummy, iov_len = 1 };
            new Span<byte>(cmsgBuf, CmsgBufSize).Clear();

            var msg = new MsgHdr
            {
                msg_iov = &iov,
                msg_iovlen = 1,
                msg_control = cmsgBuf,
                msg_controllen = CmsgBufSize,
            };

            if (recvmsg(ctrlFd, &msg, 0) <= 0) break;

            var hdr = (CmsgHdr*)cmsgBuf;
            if (hdr->cmsg_level != SolSocket || hdr->cmsg_type != ScmRights) continue;

            int clientFd = *(int*)(cmsgBuf + sizeof(CmsgHdr));
            if (clientFd < 0) continue;

            ThreadPool.UnsafeQueueUserWorkItem(HandleClient, clientFd, preferLocal: true);
        }
    }

    private static unsafe void HandleClient(int fd)
    {
        int one = 1;
        setsockopt(fd, IpprotoTcp, TcpNodelay, &one, 4);

        const int BufSize = 4096;
        const int MsgWaitAll = 0x100;
        byte* buf = stackalloc byte[BufSize];
        int filled = 0;

        try
        {
            while (true)
            {
                // Vectorized scan; on keep-alive the pipelined request may already be in buf
                int hdrEnd = FindHdrEnd(buf, 0, filled);
                while (hdrEnd < 0)
                {
                    if (filled >= BufSize) return;
                    int scanFrom = filled > 3 ? filled - 3 : 0;
                    int n = recv(fd, buf + filled, (nuint)(BufSize - filled), 0);
                    if (n <= 0) return;
                    filled += n;
                    hdrEnd = FindHdrEnd(buf, scanFrom, filled);
                }

                if (buf[0] == 'G') // GET /ready
                {
                    SendAll(fd, s_readyResp);
                    Shift(buf, hdrEnd, ref filled);
                    continue;
                }

                int clen = ParseContentLength(buf, hdrEnd);
                if (clen <= 0) { SendAll(fd, s_badResp); return; }

                int bodyEnd = hdrEnd + clen;
                if (bodyEnd > BufSize) return;
                if (filled < bodyEnd)
                {
                    // MSG_WAITALL: single syscall blocks until full body arrives
                    int n = recv(fd, buf + filled, (nuint)(bodyEnd - filled), MsgWaitAll);
                    if (n <= 0) return;
                    filled += n;
                }

                int idx = DirectHandler.ComputeIndex(new ReadOnlySpan<byte>(buf + hdrEnd, clen));
                SendAll(fd, s_responses[idx]);
                Shift(buf, bodyEnd, ref filled);
            }
        }
        finally
        {
            close(fd);
        }
    }

    // Move unconsumed bytes to buffer start for next request (keep-alive pipelining)
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe void Shift(byte* buf, int consumed, ref int filled)
    {
        int rem = filled - consumed;
        if (rem > 0)
            Buffer.MemoryCopy(buf + consumed, buf, rem, rem);
        filled = rem > 0 ? rem : 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe int FindHdrEnd(byte* buf, int from, int len)
    {
        int idx = new ReadOnlySpan<byte>(buf + from, len - from).IndexOf("\r\n\r\n"u8);
        return idx >= 0 ? from + idx + 4 : -1;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe int ParseContentLength(byte* buf, int hdrEnd)
    {
        // POST /fraud-score HTTP/1.1\r\n = 29 bytes; skip to start of headers
        const int RequestLineLen = 29;
        var hdrs = new ReadOnlySpan<byte>(buf + RequestLineLen, hdrEnd - RequestLineLen);
        var key = "Content-Length: "u8;
        int idx = hdrs.IndexOf(key);
        if (idx < 0) return -1;
        int pos = RequestLineLen + idx + key.Length;
        int result = 0;
        while (pos < hdrEnd && buf[pos] >= '0' && buf[pos] <= '9')
            result = result * 10 + buf[pos++] - '0';
        return result;
    }

    private static unsafe void SendAll(int fd, byte[] data)
    {
        fixed (byte* p = data)
        {
            int sent = 0;
            while (sent < data.Length)
            {
                int n = send(fd, p + sent, (nuint)(data.Length - sent), MsgNosignal);
                if (n <= 0) return;
                sent += n;
            }
        }
    }
}
