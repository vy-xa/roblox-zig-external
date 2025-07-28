const std = @import("std");

const HANDLE = usize;
const DWORD = u32;
const LPCVOID = ?*const u8;
const LPVOID = ?*u8;
const SIZE_T = usize;
const BOOL = i32;
const MAX_PATH = 260;

extern fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) HANDLE;
extern fn ReadProcessMemory(hProcess: HANDLE, lpBaseAddress: LPCVOID, lpBuffer: LPVOID, nSize: SIZE_T, lpNumberOfBytesRead: ?*usize) BOOL;
extern fn WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: LPVOID, lpBuffer: ?*const u8, nSize: SIZE_T, lpNumberOfBytesWritten: ?*usize) BOOL;
extern fn CloseHandle(hObject: HANDLE) BOOL;
extern fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) HANDLE;
extern fn Process32First(snapshot: HANDLE, lppe: *PROCESSENTRY32) BOOL;
extern fn Process32Next(snapshot: HANDLE, lppe: *PROCESSENTRY32) BOOL;
extern fn Module32First(snapshot: HANDLE, lpme: *MODULEENTRY32) BOOL;
extern fn Module32Next(snapshot: HANDLE, lpme: *MODULEENTRY32) BOOL;

const PROCESS_ALL_ACCESS = 0x1F0FFF;
const TH32CS_SNAPPROCESS = 0x00000002;
const TH32CS_SNAPMODULE = 0x00000008;

const PROCESSENTRY32 = extern struct {
    dwSize: DWORD,
    cntUsage: DWORD,
    th32ProcessID: DWORD,
    th32DefaultHeapID: usize,
    th32ModuleID: DWORD,
    cntThreads: DWORD,
    th32ParentProcessID: DWORD,
    pcPriClassBase: i32,
    dwFlags: DWORD,
    szExeFile: [MAX_PATH]u8,
};

const MODULEENTRY32 = extern struct {
    dwSize: DWORD,
    th32ModuleID: DWORD,
    th32ProcessID: DWORD,
    GlblcntUsage: DWORD,
    ProccntUsage: DWORD,
    modBaseAddr: *u8,
    modBaseSize: DWORD,
    hModule: HANDLE,
    szModule: [256]u8,
    szExePath: [MAX_PATH]u8,
};

fn u8ArrayToSliceNullTerm(arr: []const u8) []const u8 {
    var len: usize = 0;
    while (len < arr.len and arr[len] != 0) : (len += 1) {}
    return arr[0..len];
}

fn getProcessIdByName(proc_name: []const u8) !u32 {
    const snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == 0 or snapshot == ~@as(usize, 0)) return error.FailedToCreateSnapshot;
    defer _ = CloseHandle(snapshot);

    var entry: PROCESSENTRY32 = undefined;
    entry.dwSize = @sizeOf(PROCESSENTRY32);

    if (Process32First(snapshot, &entry) == 0) return error.FailedToEnumerateProcesses;

    while (true) {
        const exe_name = u8ArrayToSliceNullTerm(&entry.szExeFile);
        if (std.mem.eql(u8, exe_name, proc_name)) {
            return entry.th32ProcessID;
        }
        if (Process32Next(snapshot, &entry) == 0) break;
    }
    return error.ProcessNotFound;
}

fn getModuleBaseAddress(pid: u32, module_name: []const u8) !usize {
    const snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snapshot == 0 or snapshot == ~@as(usize, 0)) return error.FailedToCreateSnapshot;
    defer _ = CloseHandle(snapshot);

    var me32: MODULEENTRY32 = undefined;
    me32.dwSize = @sizeOf(MODULEENTRY32);

    if (Module32First(snapshot, &me32) == 0) return error.FailedToEnumerateModules;

    while (true) {
        const mod_name = u8ArrayToSliceNullTerm(&me32.szModule);
        if (std.mem.eql(u8, mod_name, module_name)) {
            return @intFromPtr(me32.modBaseAddr);
        }
        if (Module32Next(snapshot, &me32) == 0) break;
    }

    return error.ModuleNotFound;
}

fn readU64(process: HANDLE, address: usize) !u64 {
    var buf: u64 = 0;
    const ok = ReadProcessMemory(
        process,
        @as(LPCVOID, @ptrFromInt(address)),
        @as(LPVOID, @ptrCast(&buf)),
        @sizeOf(u64),
        null,
    );
    if (ok == 0) return error.ReadMemoryFailed;
    return buf;
}

fn writeFloat(process: HANDLE, address: usize, value: f32) !void {
    var val = value;
    const ok = WriteProcessMemory(
        process,
        @as(LPVOID, @ptrFromInt(address)),
        @as(?*const u8, @ptrCast(&val)),
        @sizeOf(f32),
        null,
    );
    if (ok == 0) return error.WriteMemoryFailed;
}

const offsets = struct {
    pub const VisualEnginePointer = 0x6719638;
    pub const VisualEngineToDataModel1 = 0x700;
    pub const VisualEngineToDataModel2 = 0x1C0;
    pub const Workspace = 0x180;
    pub const Camera = 0x428;
    pub const CameraSubject = 0xF0;
    pub const WalkSpeedCheck = 0x3B8;
    pub const WalkSpeed = 0x1DC;
};

fn getCamAddr(process: HANDLE, base_address: usize) !usize {
    const visEnginePtr = base_address + offsets.VisualEnginePointer;
    const visEngine = try readU64(process, visEnginePtr);
    const fakeDatamodel = try readU64(process, visEngine + offsets.VisualEngineToDataModel1);
    const dataModel = try readU64(process, fakeDatamodel + offsets.VisualEngineToDataModel2);
    const wsAddr = try readU64(process, dataModel + offsets.Workspace);
    const camAddr = try readU64(process, wsAddr + offsets.Camera);
    return camAddr;
}

pub fn main() !void {
    const proc_name = "RobloxPlayerBeta.exe";
    const pid = try getProcessIdByName(proc_name);
    const base_addr = try getModuleBaseAddress(pid, proc_name);

    const process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (process == 0) return error.FailedToOpenProcess;
    defer _ = CloseHandle(process);

    while (true) {
        const camAddr = try getCamAddr(process, base_addr);
        const hum = try readU64(process, camAddr + offsets.CameraSubject);
        try writeFloat(process, hum + offsets.WalkSpeedCheck, std.math.inf(f32));
        try writeFloat(process, hum + offsets.WalkSpeed, 120.0);
        std.time.sleep(std.time.ns_per_ms * 100);
    }
}
