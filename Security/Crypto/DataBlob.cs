using System;
using System.Runtime.InteropServices;

namespace ICB.Domain.Security.Crypto
{
	// Think about using IDisposable since it is more essential
	// way for handling umanaged resource.
	// But since we have there structure, not a class
	// this could resuire additional class, like DataBlobWrapper.
	// Anyway, there are no memory leaks since DataBlob usages
	// are wrapped with try-finally blocks of code.
	[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
	internal struct DataBlob
	{
		static internal DataBlob AllocateBlob(byte[] bytes)
		{
			DataBlob blob = new DataBlob();
			try
			{
				blob.Buffer = Marshal.AllocHGlobal(bytes.Length);
				if (blob.Buffer == IntPtr.Zero)
				{
					throw new Exception("Unable to allocate plaintext buffer.");
				}
				blob.Size = bytes.Length;
				try
				{
					Marshal.Copy(bytes, 0, blob.Buffer, bytes.Length);
				}
				catch (Exception ex)
				{
					blob.FreeBuffer();
					throw new Exception("Marshal.Copy failed.", ex);
				}
			}
			catch (Exception ex)
			{
				throw new Exception("Exception marshalling data. " + ex.Message);
			}
			return blob;
		}

		internal void FreeBuffer()
		{
			if (this.Buffer != IntPtr.Zero)
			{
				Marshal.FreeHGlobal(this.Buffer);
				this.Buffer = IntPtr.Zero;
			}
		}

		internal byte[] ExtractBytes()
		{
			byte[] bytes = new byte[this.Size];
			Marshal.Copy(this.Buffer, bytes, 0, this.Size);
			this.FreeBuffer();
			return bytes;
		}

		internal int Size;
		internal IntPtr Buffer;
	}
}