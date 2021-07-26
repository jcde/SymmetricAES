using System;
using System.Collections;
using System.IO;
using System.Security.Permissions;

namespace ICB.Domain.Security
{
    [StrongNameIdentityPermission(SecurityAction.LinkDemand, PublicKey =
        "1111"
        )]
    public static class LicenseFileManager
    {
        private const string LicenseFileHeader = "*** ChromeSync License file ***";
        private const string LicenseProductHead = "--- Product Information ---";
        private const string LicenseProductName = "Product Name";
        private const string LicenseCustomerHead = "--- Customer Information ---";
        private const string LicenseDownloadId = "Download ID";
        private const string LicenseHead = "--- License Information ---";
        private const string LicenseKey = "Key";
        private const string LicenseCode = "License";
        private const string LicenseFileFooter = "*** *** *** * E O F * *** *** ***";

        private static readonly Hashtable LicenseFiles = new Hashtable();

        public static string LicenseFolder
        {
            get
            {
                return AppDomain.CurrentDomain.BaseDirectory;
            }
        }

        /// <returns>LicenseFileData instance (wheither file exists or no)</returns>
        public static LicenseFileData GetLicenseFile()
        {
            const string productName = "ProductManager.Product";
            lock (typeof(LicenseFileManager))
            {
                var licenseFileData = (LicenseFileData) LicenseFiles[productName];
                if (licenseFileData == null || licenseFileData.FileDateTime != GetFileDateTime(productName))
                {
                    LicenseFiles.Remove(productName);
                    licenseFileData = LoadLicenseFile(productName);
                    LicenseFiles.Add(productName, licenseFileData);
                }
                return licenseFileData;
            }
        }

        /// <summary>
        /// Save data from LicenseFileData instance to disk
        /// </summary>
        /// <param name="licenseFileData">LicenseFileData instance with modified data</param>
        public static void SaveLicenseFile(LicenseFileData licenseFileData)
        {
            StrongNameSecurityPermissionValidator.Validate();

            if (!Directory.Exists(LicenseFolder))
            {
                Directory.CreateDirectory(LicenseFolder);
            }

            string fileName = GetFileName(licenseFileData.ProductName);
            using (StreamWriter streamWriter = File.CreateText(fileName))
            {
                PutLicenseFileInStream(licenseFileData, streamWriter);
            }
        }

        internal static void PutLicenseFileInStream(LicenseFileData licenseFileData, TextWriter streamWriter)
        {
            streamWriter.WriteLine(LicenseFileHeader);
            streamWriter.WriteLine(string.Empty);
            streamWriter.WriteLine(LicenseProductHead);
            streamWriter.WriteLine(string.Format("{0}: {1}", LicenseProductName, licenseFileData.ProductName));
            streamWriter.WriteLine(string.Empty);
            streamWriter.WriteLine(LicenseCustomerHead);
            streamWriter.WriteLine(string.Format("{0}: {1}", LicenseDownloadId, licenseFileData.DownloadId));
            streamWriter.WriteLine(string.Empty);
            streamWriter.WriteLine(LicenseHead);
            streamWriter.WriteLine(string.Format("{0}: {1}", LicenseKey, licenseFileData.KeyCode));
            streamWriter.WriteLine(string.Format("{0}: {1}", LicenseCode, licenseFileData.LicenseCode));
            streamWriter.WriteLine(string.Empty);
            streamWriter.WriteLine(LicenseFileFooter);
        }

        public static string GetShortFileName(string productName)
        {
            return string.Format("license.txt");
        }

        private static LicenseFileData LoadLicenseFile(string productCode)
        {
            string fileName = GetFileName(productCode);

            var file = new LicenseFileData();

            if (File.Exists(fileName))
            {
                StrongNameSecurityPermissionValidator.Validate();
                using (StreamReader streamReader = File.OpenText(fileName))
                {
                    try
                    {
                        CheckLineSignature(streamReader, LicenseFileHeader);
                        CheckLineSignature(streamReader, string.Empty);
                        CheckLineSignature(streamReader, LicenseProductHead);
                        file.ProductName = GetLineSignature(streamReader, LicenseProductName);
                        CheckLineSignature(streamReader, string.Empty);
                        CheckLineSignature(streamReader, LicenseCustomerHead);
                        file.DownloadId = GetLineSignature(streamReader, LicenseDownloadId);
                        CheckLineSignature(streamReader, string.Empty);
                        CheckLineSignature(streamReader, LicenseHead);
                        file.KeyCode = GetLineSignature(streamReader, LicenseKey);
                        file.LicenseCode = GetLineSignature(streamReader, LicenseCode);
                        CheckLineSignature(streamReader, string.Empty);
                        CheckLineSignature(streamReader, LicenseFileFooter);
                    }
                    catch
                    {
                        file.FormatError = true;
                    }

                    if (file.ProductName == string.Empty ||
                        file.InstallId == string.Empty ||
                        string.Empty.Equals(file.KeyCode))
                    {
                        file.FormatError = true;
                    }

                    file.FileDateTime = GetFileDateTime(productCode);
                }
            }
            return file;
        }

        private static void CheckLineSignature(StreamReader streamReader, string signature)
        {
            string s = streamReader.ReadLine();
            if (!string.Equals(s, signature))
            {
                throw new Exception("CheckLineSignature error");
            }
        }

        private static string GetLineSignature(StreamReader streamReader, string signature)
        {
            string s = streamReader.ReadLine();
            if (s == null)
                throw new Exception("CheckLineSignature null error");
            int index = s.IndexOf(": ");
            string signPart = s.Substring(0, index);
            string dataPart = s.Length > index + 2 ? s.Substring(index + 2) : string.Empty;
            if (!string.Equals(signPart, signature))
            {
                throw new Exception("CheckLineSignature error");
            }
            return dataPart;
        }

        private static DateTime GetFileDateTime(string productCode)
        {
            string fileName = GetFileName(productCode);
            return File.Exists(fileName) ? File.GetLastWriteTime(fileName) : DateTime.MinValue;
        }

        private static string GetFileName(string productCode)
        {
            string divider = LicenseFolder.EndsWith(@"\") ? string.Empty : @"\";
            return string.Format("{0}{1}{2}", LicenseFolder, divider, GetShortFileName(productCode));
        }
    }
}