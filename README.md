# CSharpShellcodeInjector

> .NET Framework 2.0 shellcode injector that downloads and executes position-independent shellcode in-process via PEB/TEB walking and native API resolution -- no `GetProcAddress` import required.

![Language](https://img.shields.io/badge/Language-C%23-239120?logo=csharp)
![Framework](https://img.shields.io/badge/.NET_Framework-2.0-512BD4)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?logo=windows)
![Architecture](https://img.shields.io/badge/Arch-x86_%7C_x64_%7C_ARM64-lightgrey)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Output](https://img.shields.io/badge/Output-DLL_(COM--visible)-orange)

---

## Features

- **Multi-architecture support** -- automatically detects x86, x64, and ARM64 at runtime via `GetNativeSystemInfo` and selects the appropriate payload URL.
- **PEB/TEB walking** -- resolves `ntdll.dll` base address through the Process Environment Block loader data structures, avoiding suspicious API imports.
- **Export table hashing** -- locates `NtAllocateVirtualMemory` by walking the PE export table and matching a precomputed hash, eliminating the need for `GetProcAddress`.
- **COM-visible DLL** -- builds as a class library with `[ComVisible(true)]`, enabling invocation from COM clients, `rundll32`, or managed harnesses.
- **Minimal dependencies** -- targets .NET Framework 2.0 with only a `System` reference; no NuGet packages required.
- **Base64 post-build output** -- a post-build step automatically generates a base64-encoded copy of the compiled DLL for easy transport and staging.
- **ARM64 instruction cache flush** -- correctly calls `FlushInstructionCache` on ARM64 to ensure written code is visible to the instruction pipeline.

## Project Structure

| File | Purpose |
|---|---|
| `Program.cs` | Entry point; detects architecture, orchestrates download and execution |
| `ShellcodeRunner.cs` | TEB/PEB walking, RWX memory allocation, PE export resolution, payload execution |
| `NativeInterop.cs` | P/Invoke declarations, unmanaged delegates, and native structs |
| `Downloader.cs` | HTTPS download via `WebClient` with TLS 1.2 negotiation |

## Requirements

- **OS:** Windows 7 or later
- **Build tools:** Visual Studio 2017+ or MSBuild with the .NET Framework 2.0 targeting pack
- **Runtime:** .NET Framework 2.0 (included in all modern Windows installations)

## Configuration

Before building, replace the URL placeholders in `Program.cs` with the addresses of your shellcode payloads:

| Placeholder | Description |
|---|---|
| `%URL64%` | URL serving the x64 shellcode binary |
| `%URL32%` | URL serving the x86 shellcode binary |
| `%URLARM64%` | URL serving the ARM64 shellcode binary |

## Build

Build from the command line using MSBuild:

```bash
msbuild ShellcodeInjector.sln /p:Configuration=Release /p:Platform=AnyCPU
```

Or target a specific platform:

```bash
# x86 only
msbuild ShellcodeInjector.csproj /p:Configuration=Release /p:Platform=x86

# x64 only
msbuild ShellcodeInjector.csproj /p:Configuration=Release /p:Platform=x64

# ARM64 only
msbuild ShellcodeInjector.csproj /p:Configuration=Release /p:Platform=ARM64
```

Build output is placed in `bin\<Platform>\Release\`. The post-build step generates `ShellcodeInjector.b64.txt` alongside the DLL.

## Usage

The DLL executes its payload when the static constructor runs (i.e., when the `Program` type is first loaded). Common invocation methods:

```powershell
# Load via PowerShell reflection
[System.Reflection.Assembly]::LoadFile("C:\path\to\ShellcodeInjector.dll")

# Load from base64
$bytes = [Convert]::FromBase64String((Get-Content ShellcodeInjector.b64.txt))
[System.Reflection.Assembly]::Load($bytes)
```

## How It Works

1. The static constructor in `Program` calls `Main()` on type load.
2. `GetNativeSystemInfo` determines the processor architecture (x86 / x64 / ARM64).
3. The corresponding payload URL is selected and the shellcode is downloaded over HTTPS.
4. A small architecture-specific stub is assembled and executed to read the Thread Environment Block (TEB) address.
5. The PEB is reached from the TEB, then the PEB loader data's in-memory-order module list is walked to find `ntdll.dll`'s base address.
6. `NtAllocateVirtualMemory` is resolved from `ntdll`'s export table using a hash lookup (no `GetProcAddress` call).
7. RWX memory is allocated via the resolved `NtAllocateVirtualMemory`, and the shellcode is copied in.
8. Injector parameters are written to a reserved TEB slot so the shellcode can read them.
9. Control is transferred to the shellcode entry point.

## Disclaimer

This project is provided **strictly for authorized security testing, education, and research purposes**. Using this software against systems you do not own or do not have explicit written permission to test is illegal and unethical. The authors assume no liability for misuse.

See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) for the full responsible use policy.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
