using System;
using System.Runtime.InteropServices;

namespace ICB.Domain.Security.Crypto
{
	[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
	internal struct CryptProtectPrompt
	{
		static internal CryptProtectPrompt InitPrompt()
		{
			CryptProtectPrompt prompt = new CryptProtectPrompt();
			prompt.Size = Marshal.SizeOf(typeof(CryptProtectPrompt));
			prompt.Flags = 0;
			prompt.HWndApp = NullPtr;
			prompt.Prompt = null;
			return prompt;
		}

		internal int Size;
		internal int Flags;
		internal IntPtr HWndApp;
		internal string Prompt;

		static private IntPtr NullPtr = (IntPtr) 0;
	}
}