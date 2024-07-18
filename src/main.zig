const std = @import("std");
const debugPrint = std.debug.print;
const io = std.io;
const stdout = io.getStdOut().writer();
const ArrayList = std.ArrayList;
const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("pcap/pcap.h");
    @cInclude("arpa/inet.h");
});

const ETHER_ADDR_LEN = 6;
const ETHER_HDR_LEN = 14;
const IP_HDR_LEN = 20;

const pcap_t: type = c.pcap_t;

const EtherHdr = packed struct {
    ether_dst_addr: u48,
    ether_src_addr: u48,
    ether_type: u16,
};

const Packet = packed struct {
    ether_hdr: EtherHdr,
    ip_hdr: IpHdr,
    tcp_hdr: TcpHdr,
    data: u8,
};

const Hoge = packed struct {
    x: u32,
    y: u32,
};

const IpHdr = packed struct {
    ip_version_and_hdr_len: u8,
    ip_tos: u8,
    ip_len: u16,
    ip_id: u16,
    ip_flag_ofs: u16,
    ip_ttl: u8,
    ip_proto: u8,
    ip_checksum: u16,
    ip_src_addr: u32,
    ip_dst_addr: u32,
};

const TcpHdr = packed struct {
    tcp_src_port: u16,
    tcp_dst_port: u16,
    tcp_seq: u32,
    tcp_ack: u32,
    ofs: u8,
    flg: u8,
    tcp_window: u16,
    tcp_checksum: u16,
    tcp_urgent: u16,
    padding: u32,
};

fn fmtIp(ip_buf: []u8, ip: u32) []u8 {
    @memset(ip_buf, 0);
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const string = std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{
        ip << 24 >> 24,
        ip << 16 >> 24,
        ip << 8 >> 24,
        ip << 0 >> 24,
    }) catch {
        return ip_buf;
    };
    std.mem.copyForwards(u8, ip_buf, string);
    return ip_buf;
}

fn dumpData(buf: *ArrayList(u8), data: [*]u8, length: u32) void {
    buf.writer().print("((data))\n", .{}) catch {};
    var byte: u8 = undefined;
    for (0..length) |i| {
        byte = data[i];
        buf.writer().print("{x:0>2} ", .{byte}) catch {};
        if ((@mod(i, 16) == 15) or (i == length - 1)) {
            for (0..(15 - @mod(i, 16))) |_|
                buf.writer().print("   ", .{}) catch {};
            buf.writer().print("| ", .{}) catch {};
            for ((i - @mod(i, 16))..i + 1) |j| {
                if (j > i) break;
                byte = data[j];
                switch (byte) {
                    31...127 => buf.writer().print("{c}", .{byte}) catch {},
                    else => buf.writer().print(".", .{}) catch {},
                }
            }
            buf.writer().print("\n", .{}) catch {};
        }
    }
}

fn decodeEther(buf: *ArrayList(u8), ether_hdr: *EtherHdr) void {
    buf.writer().print("((ether header))\n", .{}) catch {};
    buf.writer().print("{x} => {x}\n", .{ ether_hdr.ether_src_addr, ether_hdr.ether_dst_addr }) catch {};
    buf.writer().print("type: {x}\n", .{ether_hdr.ether_type}) catch {};
}

fn decodeIp(buf: *ArrayList(u8), ip_hdr: *IpHdr) void {
    var ip_buf: [20]u8 = undefined;

    buf.writer().print("\t((ip header))\n", .{}) catch {};
    // buf.writer().print("\t{0s} => {1s}\n", .{
    //     fmtIp(&ip_buf, ip_hdr.ip_src_addr),
    //     fmtIp(&ip_buf, ip_hdr.ip_dst_addr),
    // }) catch {};
    buf.writer().print("\t{s} => ", .{fmtIp(&ip_buf, ip_hdr.ip_src_addr)}) catch {};
    buf.writer().print("{s}\n", .{fmtIp(&ip_buf, ip_hdr.ip_dst_addr)}) catch {};
    buf.writer().print("\ttos: {d}\n", .{ip_hdr.ip_tos}) catch {};
    buf.writer().print("\tprotocol: {d}, id: {d}, length: {d}\n", .{
        ip_hdr.ip_proto,
        c.ntohs(ip_hdr.ip_id),
        c.ntohs(ip_hdr.ip_len),
    }) catch {};
}

fn decodeTcp(buf: *ArrayList(u8), tcp_hdr: *TcpHdr) void {
    const src_port = c.ntohs(tcp_hdr.tcp_src_port);
    const dst_port = c.ntohs(tcp_hdr.tcp_dst_port);
    const seq = c.ntohl(tcp_hdr.tcp_seq);
    const ack = c.ntohl(tcp_hdr.tcp_ack);
    const header_sz = (tcp_hdr.ofs >> 4) * 4;

    buf.writer().print("\t\t((tcp header))\n", .{}) catch {};
    buf.writer().print("\t\tport: {d} => {d}\n", .{ src_port, dst_port }) catch {};
    buf.writer().print("\t\tSeq: {d}, Ack: {d}\n", .{ seq, ack }) catch {};
    buf.writer().print("\t\theader size: {d}\n", .{header_sz}) catch {};
}

fn callback(user: [*c]u8, pkthdr: *c.pcap_pkthdr, packet_ptr: [*]u8) callconv(.C) void {
    _ = user;
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    @setRuntimeSafety(false);

    const ether_hdr: *EtherHdr = @ptrCast(@alignCast(packet_ptr));
    const ip_hdr: *IpHdr = @ptrCast(@alignCast(packet_ptr + ETHER_HDR_LEN));
    const tcp_hdr: *TcpHdr = @ptrCast(@alignCast(packet_ptr + ETHER_HDR_LEN + IP_HDR_LEN));
    const total_hdr_size: u32 = ETHER_HDR_LEN + IP_HDR_LEN + (tcp_hdr.ofs >> 4) * 4;
    const pkt_data_len: u32 = pkthdr.len - total_hdr_size;
    const pkt_data: [*]u8 = packet_ptr + total_hdr_size;
    var buf: ArrayList(u8) = ArrayList(u8).init(allocator);
    defer buf.deinit();

    buf.writer().print("== caught packet === \n", .{}) catch {};
    buf.writer().print("header length: {d}, packet length: {d}, packet data: {d}\n", .{
        total_hdr_size,
        pkthdr.len,
        pkt_data_len,
    }) catch {};
    decodeEther(&buf, ether_hdr);
    decodeIp(&buf, ip_hdr);
    decodeTcp(&buf, tcp_hdr);
    if (pkt_data_len > 0)
        dumpData(&buf, pkt_data, pkt_data_len);
    stdout.print("{s}\n", .{buf.items}) catch {};
}

pub fn main() void {
    var device: [*c]u8 = undefined;
    var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    const packets: u32 = 20;
    const timeout: u32 = 10000; // milli seconds

    device = c.pcap_lookupdev(&errbuf);
    const capdev: ?*pcap_t = c.pcap_open_live(device, c.BUFSIZ, 1, timeout, &errbuf);

    if (capdev == null) {
        debugPrint("ERR: pcap_openi_live() {s}\n", .{errbuf});
        return;
    }

    stdout.print("Device: {s}\n", .{device}) catch {};
    const res = c.pcap_loop(capdev, packets, @ptrCast(&callback), null);
    if (res < 0) {
        debugPrint("ERR: pcap_loop() failed!\n", .{});
        return;
    }

    c.pcap_close(capdev);
}
