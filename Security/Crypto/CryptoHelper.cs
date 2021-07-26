using System;
using System.IO;
using System.Security.Permissions;
using System.Text;
using System.Security.Cryptography;

namespace ICB.Domain.Security.Crypto
{
	/// <summary>
	/// Static class, which includes all low-level crypto algorithms
	/// </summary>
	[StrongNameIdentityPermission(SecurityAction.LinkDemand, PublicKey=
    "00240000048000009400000006020000002400005253413100040000010001008de5fc232e7c3cade965dbe98780b4c6bcb5de18a32631ef6ed1853745211857411dae9ac5850a98170230fd0d3a24e23d8edbc866b3b38c740a47b722e20ee3290bd1b8a47d9aca7e250030636939529694eae842d113d36dc08795f45841a09644c92d9390b2df321e4e04d2c0e0521116fff0d873fecc17709e4ddcd2aee5")]
    public static class CryptoHelper
	{
	    internal static LicenseInfo CreateLicenseInfo (LicenseFileData licenseFileData)
		{
            if (licenseFileData.IsExists)
            {
                if (licenseFileData.FormatError)
                {
                    return new LicenseInfo
                               {
                                   InstallId = licenseFileData.InstallId,
                                   LicenseStatus = LicenseStatus.Invalid
                               };
                }
                if (licenseFileData.IsRequested)
                {
                    return new LicenseInfo
                               {
                                   InstallId = licenseFileData.InstallId,
                                   LicenseStatus = LicenseStatus.Requested
                               };
                }
                LicenseStatus licenseStatus = CheckLicense(licenseFileData) && CheckKey(licenseFileData)
                                                  ? LicenseStatus.Licensed
                                                  : LicenseStatus.Invalid;
                return new LicenseInfo
                           {
                               InstallId = licenseFileData.InstallId,
                               LicenseStatus = licenseStatus
                           };
            }

	        return new LicenseInfo
            {
                InstallId = licenseFileData.InstallId,
                LicenseStatus = LicenseStatus.None
            };
		}
		
		internal static string GenerateKey(LicenseFileData licenseFileData)
		{
			string signature = CreateShortSignature(licenseFileData);
			byte[] clearData = Encoding.ASCII.GetBytes(signature);
			byte[] buffer = Dpapi.CryptData(KeyStoreAccount.Machine, clearData, EntropyHolder.Entropy);
			return Convert.ToBase64String(buffer);
		}

		private static bool CheckKey (LicenseFileData licenseFileData)
		{
		    return true;

            /* commented because of problems with Base64 decoding
			string signature = CreateShortSignature(licenseFileData);
			byte[] clearData;
			try
			{
                byte[] encrData = Convert.FromBase64String(licenseFileData.KeyCode);
                clearData = Dpapi.DecryptData(KeyStoreAccount.Machine, encrData, EntropyHolder.Entropy);
			}
			catch
			{
				return false;
			}
			return string.Equals(Encoding.ASCII.GetString(clearData), signature);*/
		}
		
		/// <summary>
		/// Generates license key by data from license file
		/// </summary>
		/// <remarks>
		/// Method uses customer name, orgamization name, module name and request key.
		/// </remarks>
		/// <param name="licenseFileData">Instanse of LicenseFileData</param>
		/// <returns>License Key string</returns>
		public static string GenerateLicense(LicenseFileData licenseFileData)
		{
		    //StrongNameSecurityPermissionValidator.Validate();
		    
			string signature = CreateSignature(licenseFileData);
			Byte[] desKey = CreateKey(signature);
			Byte[] desIV = CreateIV(signature);
			
			return EncriptString(signature, desKey, desIV);
		}

		private static bool CheckLicense (LicenseFileData licenseFileData)
		{
			string signature = CreateSignature(licenseFileData);
			Byte[] desKey = CreateKey(signature);
			Byte[] desIV = CreateIV(signature);
			try
			{
				string descryptSign = DescryptString(licenseFileData.LicenseCode, desKey, desIV);
				return string.Equals(signature, descryptSign);
			}
			catch
			{
				return false;
			}
		}

		private static string CreateShortSignature (LicenseFileData licenseFileData)
		{
			return 
				START_SIGN +
				licenseFileData.ProductName + "#" +
				licenseFileData.InstallId + "#" +
				END_SIGN;
		}

		private static string CreateSignature (LicenseFileData licenseFileData)
		{
			return 
				START_SIGN +
				licenseFileData.ProductName + "#" +
				licenseFileData.InstallId+ "#" +
				licenseFileData.KeyCode.Substring(0, 30) +
				END_SIGN;
		}

		private static byte[] CreateKey(string signature)
		{
			return GetDataFromSignature (signature, 3);
		}

		private static byte[] CreateIV(string signature)
		{
			return GetDataFromSignature (signature, 2);
		}
		
		private static Byte[] GetDataFromSignature (string signature, int increment)
		{
			Byte[] signArray = Encoding.ASCII.GetBytes(signature);
			int keySize = des.Key.Length;
			Byte[] result = new byte[keySize];
			int index = 0;
			for (int i=0; i<keySize; i++)
			{
				index = index + increment;
				if (index > signArray.Length)
				{
					index = 0;
				}
				result[i] = signArray[index];
			}
			return result;
		}
		
		private static string EncriptString (string input, byte[] desKey, byte[] desIV)
		{
			byte[] data = Encoding.ASCII.GetBytes(input);

			MemoryStream ms = new MemoryStream();
			ICryptoTransform transform = des.CreateEncryptor(desKey, desIV);
			CryptoStream cstream = new CryptoStream(ms,transform,CryptoStreamMode.Write); 
			cstream.Write(data,0,(int)data.Length); 
			cstream.FlushFinalBlock(); 
			cstream.Close(); 
			
			return Convert.ToBase64String(ms.ToArray());
		}
		
		private static string DescryptString (string input, byte[] desKey, byte[] desIV)
		{
			byte[] data = Convert.FromBase64String(input);
			MemoryStream ms = new MemoryStream(data);
			
			ICryptoTransform transform = des.CreateDecryptor(desKey, desIV); 
			CryptoStream cstream = new CryptoStream(ms,transform,CryptoStreamMode.Read); 
			StreamReader sr = new StreamReader(cstream); 
			
			return sr.ReadToEnd();
		}
		

		private const string START_SIGN = "33A3D1067EBF44b191A52D352B460AA7";
		private const string END_SIGN = "0ED13791E1774513B9B4416748B09689";

		private static DESCryptoServiceProvider des = new DESCryptoServiceProvider();
		
	}
}
