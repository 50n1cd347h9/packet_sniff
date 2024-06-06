const std = @import("std");
const print = std.debug.print;
const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("pcap/pcap.h");
});
const pcap_t: type = c.pcap_t;

fn callback(user: [*c]u8, pkthdr: [*c]const c.pcap_pkthdr, packet_ptr: [*c]const u8) callconv(.C) void {
    _ = user;
    _ = pkthdr;
    _ = packet_ptr;
    print("Yout just received a packet!\n", .{});
}

pub fn main() !void {
    var device: [*c]u8 = undefined;
    var errbuf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    const packets: u32 = 10;

    device = c.pcap_lookupdev(&errbuf);
    const capdev: ?*pcap_t = c.pcap_open_live(device, c.BUFSIZ, 1, 0, &errbuf);

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
