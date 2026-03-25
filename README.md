# ShellcodeInjector

.NET Framework 2.0 shellcode injector that downloads and executes position-independent shellcode in-process. Builds as a COM-visible class library (DLL) with automatic base64 output.

## How It Works

1. Detects architecture (x86/x64/ARM64) via `GetNativeSystemInfo` and selects the appropriate payload URL
2. Downloads shellcode from the configured URL
3. Resolves `NtAllocateVirtualMemory` from ntdll via PEB walking and export table hashing (no `GetProcAddress` import)
4. Allocates RWX memory and copies the shellcode
5. Passes injector parameters via the TEB
6. Executes the shellcode

## Project Structure

| File | Purpose |
|---|---|
| `Program.cs` | Entry point, orchestrates download and execution |
| `ShellcodeRunner.cs` | TEB/PEB walking, memory allocation, PE export resolution, payload execution |
| `NativeInterop.cs` | P/Invoke declarations, delegates, and native structs |
| `Downloader.cs` | HTTP download via WebClient |

## Configuration

Replace the following placeholders before building:

| Placeholder | Description |
|---|---|
| `%URL64%` | URL to the x64 shellcode payload |
| `%URL32%` | URL to the x86 shellcode payload |
| `%URLARM64%` | URL to the ARM64 shellcode payload |

## Build

Requires Visual Studio or MSBuild with .NET Framework 2.0 targeting pack.

```
msbuild ShellcodeInjector.csproj /p:Configuration=Release /p:Platform=AnyCPU
```

Build targets: `AnyCPU`, `x86`, `x64`, `ARM64`

A post-build step automatically generates a base64-encoded copy of the output DLL (`ShellcodeInjector.b64.txt`).
