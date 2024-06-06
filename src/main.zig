const std = @import("std");
const print = std.debug.print;
const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("pcap/pcap.h");
});
const pcap_t: type = c.pcap_t;

pub fn main() !void {
    const device: *const [6]u8 = "wlp5s0";
    var error_buf: [c.PCAP_ERRBUF_SIZE]u8 = undefined;
    const capdev: ?*pcap_t = c.pcap_open_live(device, c.BUFSIZ, 0, -1, &error_buf);

    if (capdev == null) {
        print("ERR: pcap_openi_live() {s}\n", .{error_buf});
    }
}
