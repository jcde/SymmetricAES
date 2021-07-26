using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace ICB.Domain.Security.Crypto
{
    public class Symmetric
    {
        private static byte[] _salt = Encoding.ASCII.GetBytes("23MQ4S-=");

        public const string tempSecret = "for testing";

        /// <summary>
        /// there is assymetric AppConfiguration.SecurityUtils.Hash()
        /// </summary>
        public static string EncryptStringAES(string plainText)
        {
            return EncryptStringAES(plainText,
                StrongNameSecurityPermissionValidator.GetAssemblyPublicKey(Assembly.GetCallingAssembly()));
        }

        /// <summary>
        /// Encrypt the given string using AES.  The string can be decrypted using 
        /// DecryptStringAES().  The sharedSecret parameters must match.
        /// </summary>
        /// <param name="plainText">The text to encrypt.</param>
        /// <param name="sharedSecret">A password used to generate a key for encryption.</param>
        public static string EncryptStringAES(string plainText, string sharedSecret)
        {
            if (string.IsNullOrEmpty(plainText))
                return null;
            if (string.IsNullOrEmpty(sharedSecret))
            {
#if DEBUG
                sharedSecret = "for testing";
#else
                    throw new ArgumentNullException("sharedSecret");
#endif
            }

            string outStr = null; // Encrypted string to return
            RijndaelManaged aesAlg = null; // RijndaelManaged object used to encrypt the data.

            try
            {
                // generate the key from the shared secret and the salt
                var key = new Rfc2898DeriveBytes(sharedSecret, _salt);

                // Create a RijndaelManaged object
                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    // prepend the IV
                    msEncrypt.Write(BitConverter.GetBytes(aesAlg.IV.Length), 0, sizeof(int));
                    msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                    }
                    outStr = Convert.ToBase64String(msEncrypt.ToArray());
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                    aesAlg.Clear();
            }

            // Return the encrypted bytes from the memory stream.
            return outStr;
        }

        public static string DecryptStringAES(string cipherText)
        {
            return DecryptStringAES(cipherText,
                StrongNameSecurityPermissionValidator.GetAssemblyPublicKey(Assembly.GetCallingAssembly()));
        }

        /// <summary>
        /// Decrypt the given string.  Assumes the string was encrypted using 
        /// EncryptStringAES(), using an identical sharedSecret.
        /// </summary>
        /// <param name="cipherText">The text to decrypt.</param>
        /// <param name="sharedSecret">A password used to generate a key for decryption.</param>
        public static string DecryptStringAES(string cipherText, string sharedSecret)
        {
            if (string.IsNullOrEmpty(cipherText))
                return null;
            if (string.IsNullOrEmpty(sharedSecret))
#if DEBUG
                sharedSecret = tempSecret;
#else
                throw new ArgumentNullException("sharedSecret");
#endif

            // Declare the RijndaelManaged object
            // used to decrypt the data.
            RijndaelManaged aesAlg = null;

            try
            {
                return GetPlainText(cipherText, sharedSecret, ref aesAlg);
            }
            catch
            {
                try
                {
                    return GetPlainText(cipherText, tempSecret, ref aesAlg);
                }
                catch
                {
                    return null;
                }
            }
            finally
            {
                // Clear the RijndaelManaged object.
                if (aesAlg != null)
                    aesAlg.Clear();
            }
        }

        private static string GetPlainText(string cipherText, string sharedSecret, ref RijndaelManaged aesAlg)
        {
            // generate the key from the shared secret and the salt
            var key = new Rfc2898DeriveBytes(sharedSecret, _salt);

            // Create the streams used for decryption.                
            byte[] bytes = Convert.FromBase64String(cipherText);
            using (MemoryStream msDecrypt = new MemoryStream(bytes))
            {
                // Create a RijndaelManaged object
                // with the specified key and IV.
                aesAlg = new RijndaelManaged();
                aesAlg.Key = key.GetBytes(aesAlg.KeySize / 8);
                // Get the initialization vector from the encrypted stream
                aesAlg.IV = ReadByteArray(msDecrypt);
                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        // Read the decrypted bytes from the decrypting stream
                        return srDecrypt.ReadToEnd();
                }
            }
        }

        private static byte[] ReadByteArray(Stream s)
        {
            byte[] rawLength = new byte[sizeof(int)];
            if (s.Read(rawLength, 0, rawLength.Length) != rawLength.Length)
            {
                throw new SystemException("Stream did not contain properly formatted byte array");
            }

            byte[] buffer = new byte[BitConverter.ToInt32(rawLength, 0)];
            if (s.Read(buffer, 0, buffer.Length) != buffer.Length)
            {
                throw new SystemException("Did not read byte array properly");
            }

            return buffer;
        }
    }
}
