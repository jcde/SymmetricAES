using System;
using System.Runtime.InteropServices;

namespace ICB.Domain.Security.Crypto
{
	internal static class Dpapi
	{
	    static internal byte[] CryptData(KeyStoreAccount keyStoreAccount, byte[] plainText, byte[] optionalEntropy)
		{
			DataBlob plainTextBlob = DataBlob.AllocateBlob(plainText);
			try
			{
				DataBlob entropyBlob = Dpapi.PrepareEnthropy(keyStoreAccount, optionalEntropy);
				try
				{
					CryptProtectPrompt prompt = CryptProtectPrompt.InitPrompt();
					DataBlob dataOut = new DataBlob();
					try
					{
						if (!Dpapi.CryptProtectData(ref plainTextBlob, "", ref entropyBlob, IntPtr.Zero, ref prompt, (int) Dpapi.CalculateFlags(keyStoreAccount), ref dataOut))
						{
							//throw new FrameworkException("Encryption failed. " + ErrorMessageFormatter.Format(Marshal.GetLastWin32Error()));
							throw new Exception("a");
						}
						return dataOut.ExtractBytes();
					}
					finally
					{
						dataOut.FreeBuffer();
					}
				}
				finally
				{
					entropyBlob.FreeBuffer();
				}
			}
			finally
			{
				plainTextBlob.FreeBuffer();
			}
		}

		static internal byte[] DecryptData(KeyStoreAccount keyStoreAccount, byte[] cipherText, byte[] optionalEntropy)
		{
			CryptProtectPrompt prompt = CryptProtectPrompt.InitPrompt();
			DataBlob cipherBlob = DataBlob.AllocateBlob(cipherText);
			try
			{
				DataBlob entropyBlob = Dpapi.PrepareEnthropy(keyStoreAccount, optionalEntropy);
				try
				{
					DataBlob dataOut = new DataBlob();
					try
					{
						if (!Dpapi.CryptUnprotectData(ref cipherBlob, null, ref entropyBlob, IntPtr.Zero, ref prompt, (int) Dpapi.CalculateFlags(keyStoreAccount), ref dataOut))
						{
							//throw new FrameworkException("Decryption failed. " + ErrorMessageFormatter.Format(Marshal.GetLastWin32Error()));
							throw new Exception("Decryption failed. " + Marshal.GetLastWin32Error());
						}
						return dataOut.ExtractBytes();
					}
					finally
					{
						dataOut.FreeBuffer();
					}
				}
				finally
				{
					entropyBlob.FreeBuffer();
				}
			}
			finally
			{
				cipherBlob.FreeBuffer();
			}
		}

		static private Flags CalculateFlags(KeyStoreAccount keyStoreAccount)
		{
			return KeyStoreAccount.Machine == keyStoreAccount ? Flags.CRYPTPROTECT_LOCAL_MACHINE | Flags.CRYPTPROTECT_UI_FORBIDDEN : Flags.CRYPTPROTECT_UI_FORBIDDEN;
		}

		static private DataBlob PrepareEnthropy(KeyStoreAccount keyStoreAccount, byte[] entropy)
		{
			return KeyStoreAccount.Machine == keyStoreAccount ? DataBlob.AllocateBlob(entropy == null ? new byte[0] : entropy) : new DataBlob();
		}

		[DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		static private extern bool CryptProtectData(ref DataBlob dataIn, string dataDescr, ref DataBlob optionalEntropy, IntPtr reserved, ref CryptProtectPrompt prompt, int flags, ref DataBlob dataOut);

		[DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
		static private extern bool CryptUnprotectData(ref DataBlob dataIn, string dataDescr, ref DataBlob optionalEntropy, IntPtr reserved, ref CryptProtectPrompt prompt, int flags, ref DataBlob dataOut);

		[Flags]
		private enum Flags
		{
			CRYPTPROTECT_UI_FORBIDDEN = 0x1,
			CRYPTPROTECT_LOCAL_MACHINE = 0x4,
		}
	}
}