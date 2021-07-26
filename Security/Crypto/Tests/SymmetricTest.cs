#if UNIT_TESTS

using System;
using System.IO;
using System.Reflection;
using System.Text;

using NUnit.Framework;

namespace ICB.Domain.Security.Crypto.Tests
{
    [TestFixture]
    public class SymmetricTest 
    {
        [Test]
        public void EncryptStringAES()
        {
            var filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"ICB.Domain.dll");//ccnet
            if (!File.Exists(filePath))
                filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, @"..\..\..\..\Server\ICB.Server\bin\Debug\ICB.Domain.dll");//resharper
            
            byte[] publicKey = Assembly.LoadFile(filePath).GetName().GetPublicKey();
            StringBuilder stringBuilder = new StringBuilder();
            foreach (byte publicKeyByte in publicKey)
                stringBuilder.Append(publicKeyByte.ToString("X2"));
            var sharedSecret = //stringBuilder.ToString();
                StrongNameSecurityPermissionValidator.GetAssemblyPublicKey();

            var pass = "Password@1234";
            var hashed = Symmetric.EncryptStringAES(pass, sharedSecret);
            Assert.IsTrue(hashed.Length < 100);
            //hashed = "EAAAAD4REUp1xtZH7bxbrDNn5sGkR1e3qwsh7FBhgt7uO7kG";
            Assert.AreEqual(pass, Symmetric.DecryptStringAES(hashed, sharedSecret));
        }
    }
}

#endif