const std = @import("std");
const print = std.debug.print;
const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("pcap/pcap.h");
    @cInclude("arpa/inet.h");
});

const ETHER_ADDR_LEN = 6;
const ETHER_HDR_LEN = 14;

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
    padding: u32,
};

const TcpHdr = packed struct {
    tcp_src_port: u16,
    tcp_dst_port: u16,
    tcp_seq: u32,
    tcp_ack: u32,
    ofs: u4,
    rsvd: u4,
    flg: u8,
    tcp_window: u16,
    tcp_checksum: u16,
    tcp_urgent: u16,
    padding: u32,
};

fn decodeEther(hdr_start: [*c]const u8) void {
    _ = hdr_start;
    return;
}

fn fmtIp(ip: [*]const u8, buf: *[20]u8) !void {
    _ = try std.fmt.bufPrint(buf, "{d}.", .{ip[0]});
}

fn dumpData(data: [*]u8, length: u32) void {
    var byte: u8 = undefined;

    for (0..length) |i| {
        byte = data[i];

        print("{x:0>2} ", .{data[i]});

        // TODO: something good comment
        if ((@mod(i, 16) == 15) or (i == length - 1)) {
            for (0..(15 - @mod(i, 16))) |_| {
                print("   ", .{});
            }
            print("| ", .{});

            for ((i - @mod(i, 16))..i + 1) |j| {
                if (j > i) break;
                byte = data[j];

                if ((byte > 31) and (byte < 127)) {
                    print("{c}", .{byte});
                } else {
                    print(".", .{});
                } // endif
            } // endfor
            print("\n", .{});
        } // endif
    } // endfor
}

fn callback(user: [*c]u8, pkthdr: *c.pcap_pkthdr, packet_ptr: [*]u8) callconv(.C) void {
    @setRuntimeSafety(false);

    const ether_hdr: *EtherHdr = @ptrCast(@alignCast(packet_ptr));
    const ip_hdr: *IpHdr = @ptrCast(@alignCast(packet_ptr + ETHER_HDR_LEN));
    const tcp_hdr: *TcpHdr = @ptrCast(@alignCast(packet_ptr + ETHER_HDR_LEN + @sizeOf(TcpHdr)));

    const total_hdr_size: u32 = ETHER_HDR_LEN + @sizeOf(IpHdr) + @as(u32, tcp_hdr.ofs) * 4;
    const pkt_data_len: u32 = pkthdr.len - total_hdr_size;

    const pkt_data: [*]u8 = @ptrCast(@alignCast(packet_ptr + total_hdr_size));

    const src_ip = c.inet_ntoa(c.in_addr{ .s_addr = ip_hdr.ip_src_addr });
    const dst_ip = c.inet_ntoa(c.in_addr{ .s_addr = ip_hdr.ip_dst_addr });

    _ = user;
    // _ = ether_hdr;
    // _ = pkthdr;
    // _ = ip_hdr;
    // _ = tcp_hdr;

    print("== caught packet === \n", .{});
    print("ethertype = {d}\n", .{ether_hdr.ether_type});
    print(" {s}:{d} ==> ", .{ src_ip, tcp_hdr.tcp_src_port });
    print("{s}:{d}\n", .{ dst_ip, tcp_hdr.tcp_dst_port });
    dumpData(pkt_data, pkt_data_len);
}

pub fn main() !void {
    var device: [*c]u8 = undefined;
    var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    const packets: u32 = 5;
    const timeout: u32 = 10000; // milli seconds

    device = c.pcap_lookupdev(&errbuf);
    const capdev: ?*pcap_t = c.pcap_open_live(device, c.BUFSIZ, 1, timeout, &errbuf);

    if (capdev == null) {
        print("ERR: pcap_openi_live() {s}\n", .{errbuf});
        return;
    } else {
        print("Device: {s}\n", .{device});
    }

    const res = c.pcap_loop(capdev, packets, @ptrCast(&callback), null);
    if (res < 0) {
        print("ERR: pcap_loop() failed!\n", .{});
        return;
    }

    c.pcap_close(capdev);
}
