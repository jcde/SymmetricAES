using System;
using System.Management;
using System.Security.Permissions;
using System.Text;

namespace ICB.Domain.Security
{
    [StrongNameIdentityPermission(SecurityAction.LinkDemand, PublicKey =
        "1111"
        )]
    public sealed class LicenseFileData
    {
        private static int _revisionCounter;

        private readonly int _revision = _revisionCounter++;
        string _productName = "ProductManager.Product";

        /// <summary>
        /// downloadId;$cpuid;$diskmodel;$diskid;$boardid;$tag
        /// </summary>
        public string InstallId { get; set; }

        public string DownloadId
        {
            get { return InstallId.Split(';')[0]; }
            set
            {
                var sb = new StringBuilder();
                sb.Append(value);
                sb.Append(';');
                sb.Append(GetWmi("Win32_Processor", "ProcessorId"));
                sb.Append(';');
                sb.Append(GetWmi("Win32_DiskDrive", "Model"));
                sb.Append(';');
                sb.Append(GetWmi("Win32_PhysicalMedia", "SerialNumber"));
                sb.Append(';');
                sb.Append(GetWmi("Win32_BaseBoard", "SerialNumber"));
                sb.Append(';');
                sb.Append(GetWmi("Win32_SystemEnclosure", "SMBIOSAssetTag"));
                sb.Append(';');
                InstallId = sb.ToString();
            }
        }

        public string ProductName
        {
            get { return _productName; }
            set { _productName = value; }
        }

        /// <summary>
        /// Request
        /// </summary>
        public string KeyCode { get; set; }

        /// <summary>
        /// License
        /// </summary>
        public string LicenseCode { get; set; }

        /// <summary>
        /// DateTime of existing license file. If file not exists - Minvalue
        /// </summary>
        public DateTime FileDateTime { get; set; }

        /// <summary>
        /// Internal number of license file revision.
        /// If file was modified and was reloaded, that number increased.
        /// </summary>
        public int Revision
        {
            get { return _revision; }
        }

        /// <summary>
        /// Whether license file exists or no
        /// </summary>
        public bool IsExists
        {
            get { return FileDateTime != DateTime.MinValue; }
        }

        /// <summary>
        /// Indicates that license file is corrupt and can't be parsed
        /// </summary>
        public bool FormatError { get; internal set; }

        /// <summary>
        /// Whether license is requested or no (another status)
        /// </summary>
        public bool IsRequested
        {
            get { return string.IsNullOrEmpty(LicenseCode); }
        }

        public static string GetWmi(string query, string prop)
        {
            string result = null;
            var search = new ManagementObjectSearcher(new SelectQuery(query));
            foreach (ManagementObject info in search.Get())
            {
                result = string.Format("{0}", info[prop]);
                break;
            }

            return result;
        }
    }
}