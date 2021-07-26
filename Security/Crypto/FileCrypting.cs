using System;
using System.IO;

namespace ICB.Domain.Security.Crypto
{
    /// <summary>
    /// Implementation of crypting/decrypting of deployment files
    /// </summary>
    public class FileCrypting
    {
        private FileCrypting()
        {
        }

        /// <summary>
        /// Crypting stream
        /// </summary>
        /// <param name="inputStream">stream, which has to be crypted</param>
        /// <returns>crypted stream</returns>
        public static MemoryStream CryptStream(Stream inputStream)
        {
            byte[] sourceData = new byte[(int) inputStream.Length];
            inputStream.Read(sourceData, 0, (int) inputStream.Length);

            byte[] outputData = Dpapi.CryptData(KeyStoreAccount.Machine, sourceData, EntropyHolder.Entropy);
            byte[] result = new byte[Signature.Length + outputData.Length];

            Signature.CopyTo(result, 0);
            outputData.CopyTo(result, Signature.Length);

            MemoryStream outputStream = new MemoryStream(result, true);
            return outputStream;
        }

        /// <summary>
        /// Decrypting stream
        /// </summary>
        /// <param name="inputStream">stream, which has to be descrypted</param>
        /// <returns>descrypted stream</returns>
        public static MemoryStream DecryptStream(Stream inputStream)
        {
            if (inputStream.Length < Signature.Length)
            {
                throw new Exception("Error! File is invalid!");
            }

            byte[] streamSignature = new byte[Signature.Length];
            inputStream.Read(streamSignature, 0, Signature.Length);

            if (ArrayEquals(Signature, streamSignature))
            {
                byte[] cryptedData = new byte[inputStream.Length];
                inputStream.Read(cryptedData, 0, cryptedData.Length);
                byte[] outputData = Dpapi.DecryptData(KeyStoreAccount.Machine, cryptedData, EntropyHolder.Entropy);
                return new MemoryStream(outputData, true);
            }
            else
            {
                throw new Exception("Bad signature");
            }
        }

        /// <summary>
        /// For comparing two arrays
        /// </summary>
        /// <param name="a">first array element</param>
        /// <param name="b">second array element</param>
        /// <returns>logical flag</returns>
        public static bool ArrayEquals(byte[] a, byte[] b)
        {
            int length = a.Length > b.Length ? b.Length : a.Length;
            for (int index = 0; index < length; index++)
            {
                if (a[index] != b[index])
                {
                    return false;
                }
            }
            return a.Length == b.Length;
        }

        /// <summary>
        /// Signature is used during crypting stream
        /// </summary>
        public static byte[] Signature = {1, 2, 3, 4, 5, 6, 7, 8, 9, 0};
    }
}