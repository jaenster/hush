//! hush-bar — a macOS menu bar app, in pure Zig.
//!
//! Talks to AppKit through the Objective-C runtime (objc_msgSend), the same way
//! the daemon talks to Security.framework. It is just another client of hushd:
//! it reuses the core `hush` socket protocol to show whether the daemon is up.

const std = @import("std");
const hush = @import("hush");

// --- Objective-C runtime ------------------------------------------------------

const id = ?*anyopaque;

extern "c" fn objc_getClass(name: [*:0]const u8) id;
extern "c" fn sel_registerName(name: [*:0]const u8) id;
extern "c" fn objc_msgSend() void;

fn class(name: [*:0]const u8) id {
    return objc_getClass(name);
}
fn sel(name: [*:0]const u8) id {
    return sel_registerName(name);
}

// Typed objc_msgSend wrappers for the signatures we use.
fn msg(obj: id, name: [*:0]const u8) id {
    return @as(*const fn (id, id) callconv(.c) id, @ptrCast(&objc_msgSend))(obj, sel(name));
}
fn msgId(obj: id, name: [*:0]const u8, a: id) id {
    return @as(*const fn (id, id, id) callconv(.c) id, @ptrCast(&objc_msgSend))(obj, sel(name), a);
}
fn msgVoidId(obj: id, name: [*:0]const u8, a: id) void {
    @as(*const fn (id, id, id) callconv(.c) void, @ptrCast(&objc_msgSend))(obj, sel(name), a);
}
fn msgVoidI64(obj: id, name: [*:0]const u8, a: i64) void {
    @as(*const fn (id, id, i64) callconv(.c) void, @ptrCast(&objc_msgSend))(obj, sel(name), a);
}
fn msgF64(obj: id, name: [*:0]const u8, a: f64) id {
    return @as(*const fn (id, id, f64) callconv(.c) id, @ptrCast(&objc_msgSend))(obj, sel(name), a);
}

fn nsString(text: [*:0]const u8) id {
    return @as(*const fn (id, id, [*:0]const u8) callconv(.c) id, @ptrCast(&objc_msgSend))(
        class("NSString"),
        sel("stringWithUTF8String:"),
        text,
    );
}

/// NSMenuItem with title + action selector (nil target → goes up the responder
/// chain to NSApp, which handles e.g. terminate:).
fn menuItem(title: [*:0]const u8, action_sel: [*:0]const u8, key: [*:0]const u8) id {
    const alloc = msg(class("NSMenuItem"), "alloc");
    return @as(*const fn (id, id, id, id, id) callconv(.c) id, @ptrCast(&objc_msgSend))(
        alloc,
        sel("initWithTitle:action:keyEquivalent:"),
        nsString(title),
        sel(action_sel),
        nsString(key),
    );
}

fn disabledItem(title: [*:0]const u8) id {
    const item = menuItem(title, "", "");
    msgVoidId(item, "setEnabled:", null); // BOOL NO
    return item;
}

const NSApplicationActivationPolicyAccessory: i64 = 1;
const NSVariableStatusItemLength: f64 = -1.0;

// --- daemon status ------------------------------------------------------------

fn daemonRunning(io: std.Io, gpa: std.mem.Allocator) bool {
    var paths = hush.paths.Paths.init(gpa) catch return false;
    defer paths.deinit();
    const addr = std.Io.net.UnixAddress.init(paths.socket) catch return false;
    var stream = addr.connect(io) catch return false;
    defer stream.close(io);

    var rbuf: [256]u8 = undefined;
    var wbuf: [256]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);

    const payload = hush.protocol.encodeRequest(gpa, .ping) catch return false;
    defer gpa.free(payload);
    hush.transport.writeFrame(&sw.interface, payload) catch return false;
    const resp = hush.transport.readFrame(&sr.interface, gpa) catch return false;
    defer gpa.free(resp);
    var r = hush.protocol.decodeResponse(gpa, resp) catch return false;
    defer r.deinit(gpa);
    return r.status == .ok;
}

// --- app ----------------------------------------------------------------------

pub fn main(init: std.process.Init) !u8 {
    const app = msg(class("NSApplication"), "sharedApplication");
    msgVoidI64(app, "setActivationPolicy:", NSApplicationActivationPolicyAccessory);

    const status_bar = msg(class("NSStatusBar"), "systemStatusBar");
    const item = msgF64(status_bar, "statusItemWithLength:", NSVariableStatusItemLength);
    const button = msg(item, "button");
    msgVoidId(button, "setTitle:", nsString("🤫"));

    const menu = msg(msg(class("NSMenu"), "alloc"), "init");

    const running = daemonRunning(init.io, init.gpa);
    msgVoidId(menu, "addItem:", disabledItem(if (running) "● hushd: running" else "○ hushd: not running"));
    msgVoidId(menu, "addItem:", msg(class("NSMenuItem"), "separatorItem"));
    msgVoidId(menu, "addItem:", menuItem("Quit hush", "terminate:", "q"));

    msgVoidId(item, "setMenu:", menu);

    _ = msg(app, "run"); // blocks until Quit
    return 0;
}
