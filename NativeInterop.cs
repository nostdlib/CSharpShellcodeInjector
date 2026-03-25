using System;
using System.Runtime.InteropServices;

namespace ShellcodeInjector
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Parameters
    {
        public uint InjectorVersion;
        public uint InjectorCompilationType;
        public IntPtr DllPath;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_INFO
    {
        public ushort wProcessorArchitecture;
        public ushort wReserved;
        public uint dwPageSize;
        public IntPtr lpMinimumApplicationAddress;
        public IntPtr lpMaximumApplicationAddress;
        public IntPtr dwActiveProcessorMask;
        public uint dwNumberOfProcessors;
        public uint dwProcessorType;
        public uint dwAllocationGranularity;
        public ushort wProcessorLevel;
        public ushort wProcessorRevision;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate IntPtr GetTEBDelegate();

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref UIntPtr RegionSize,
        uint AllocationType,
        uint Protect
    );

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    internal delegate int EntryDelegate(ulong injectorVersion);

    internal static class NativeImports
    {
        [DllImport("kernel32.dll", EntryPoint = "VirtualProtect", SetLastError = true)]
        internal static extern bool ChangeMemoryProtection(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        internal static extern void GetNativeSystemInfo(out SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);
    }
}
