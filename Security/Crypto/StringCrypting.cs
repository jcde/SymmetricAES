using System;
using System.Text;

namespace ICB.Domain.Security.Crypto
{
	/// <summary>
	/// Summary description for StringCrypting.
	/// </summary>
	public class StringCrypting
	{
		private StringCrypting()
		{
		}
		
		/// <summary>
		/// Crypting string
		/// </summary>
		/// <param name="inputString">string, which has to be crypted</param>
		/// <returns>crypted string</returns>
		public static string CryptString(string inputString)
		{
			ASCIIEncoding aEncoding = new ASCIIEncoding();
			byte[] sourceData = aEncoding.GetBytes(inputString);

			byte[] outputData =  Dpapi.CryptData(KeyStoreAccount.Machine, sourceData, EntropyHolder.Entropy);
			
			return Convert.ToBase64String(outputData);
		}

		/// <summary>
		/// Decrypting string
		/// </summary>
		/// <param name="inputString">string, which has to be descrypted</param>
		/// <returns>descrypted string</returns>
		public static string DecryptString(string inputString)
		{
			byte[] cryptedData = Convert.FromBase64String(inputString);
			byte[] outputData = Dpapi.DecryptData(KeyStoreAccount.Machine, cryptedData, EntropyHolder.Entropy);
			ASCIIEncoding aEncoding = new ASCIIEncoding();
			return aEncoding.GetString(outputData);
		}

		/// <summary>
		/// Decrypting string
		/// </summary>
		/// <param name="inputString">string, which has to be descrypted</param>
		/// <param name="DefaultValue">default value, if decryption will fail</param>
		/// <returns>descrypted string</returns>
		public static string DecryptString(string inputString, string DefaultValue)
		{
			string Result;
			try
			{
				Result = DecryptString(inputString);
			}
			catch
			{
				Result = DefaultValue;
			}
			return Result;
		}

		/// <summary>
		/// Decrypting string
		/// </summary>
		/// <param name="inputString">string, which has to be descrypted</param>
		/// <returns>descrypted string or string.Empty on any error</returns>
		public static string DecryptStringDef(string inputString)
		{
			return DecryptString(inputString, string.Empty);
		}

		/// <summary>
		/// Signature is used during crypting
		/// </summary>
		public static byte[] Signature = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};

	}
}
