using System;
using System.IO;
using System.Security.Permissions;
using System.Text;

using ICB.Domain.Security.Crypto;

namespace ICB.Domain.Security
{
    [StrongNameIdentityPermission(SecurityAction.LinkDemand, PublicKey =
    "1111")]
    public class LicenseManager
    {
        public static string GenerateLicense(string installId)
        {
            //may be called from web-site without strong key StrongNameSecurityPermissionValidator.Validate();
            lock (typeof(LicenseManager))
            {
                var licenseFileData = LicenseFileManager.GetLicenseFile();
                licenseFileData.InstallId = installId;
                licenseFileData.KeyCode = CryptoHelper.GenerateKey(licenseFileData);
                licenseFileData.LicenseCode = CryptoHelper.GenerateLicense(licenseFileData);
                using (var s = new StringWriter())
                {
                    LicenseFileManager.PutLicenseFileInStream(licenseFileData, s);
                    return s.ToString();
                }
            }
        }

        public static bool CheckLicense()
        {
            StrongNameSecurityPermissionValidator.Validate();
            var licenseFileData = LicenseFileManager.GetLicenseFile();
            if (!licenseFileData.IsExists)
            {
                Console.WriteLine("Error: license file does not exist");
                return false;
            }
            if (licenseFileData.FormatError)
            {
                Console.WriteLine("Error: license file has incorrect format");
                return false;
            }
            if (licenseFileData.IsRequested)
            {
                Console.WriteLine("Error: no license generated");
                return false;
            }

            return CryptoHelper.CreateLicenseInfo(licenseFileData).LicenseStatus == LicenseStatus.Licensed;
        }
    }
}
