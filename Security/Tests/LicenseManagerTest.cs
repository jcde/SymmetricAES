#if UNIT_TESTS

using System;
using System.Text;
using NUnit.Framework;

namespace ICB.Domain.Security.Tests
{
    [TestFixture]
    public class LicenseManagerTest 
    {
        [Test]
        public void GenerateLicense()
        {
            var l = LicenseManager.GenerateLicense(
                //"a5f862c5-3119-4f7f-bbee-66bc4410887f;BFEBFBFF00010677;SAMSUNG SP2514N ATA Device;S08BJ1CPA12642      ;To be filled by O.E.M.;To Be Filled By O.E.M.;"
                "example;BFEBFBFF00010677;SAMSUNG SP2514N ATA Device;S08BJ1CPA12642      ;To be filled by O.E.M.;To Be Filled By O.E.M.;"
                );
            var keyDirtyStart = l.IndexOf("Key: ") + 6 + 30;
            var keyDirtyEnd = l.IndexOf("License:") - 1;
            Assert.AreEqual(
@"*** ChromeSync License file ***

--- Product Information ---
Product Name: ICB

--- Customer Information ---
Download ID: example

--- License Information ---
Key: AQAAANCMnd8BFdERjHoAwE/Cl+sBAAA
License: Fw5KuOE/aoLAcHKruYj3uarkrf8M3fdv1vYB1gHmg4cKTgYmxOsSe8WV45Xs7k1w3eftHZIN/IDwliksSW+X8NmZAQYCPTQCsWqirsymx5X5UqwPoYE13tNZBIvbmBcxbjsB9r5VJmxgnPsYJdldeqMw7IIjGEWASuQvsZlViXH5bDte9AdzN3KDRDU6xSkQh8BlnnIbIRxMYasghdIWyUPWVyemSqxmVXpJkvUskkjUAlwTEsQlSH++gAzqo7XP/SSDkb25WGA7mYaAaUhLX6fI6iexyS31wnKsno6sPQ4=

*** *** *** * E O F * *** *** ***
",
                l.Remove(keyDirtyStart, keyDirtyEnd - keyDirtyStart - 1));
        }

        [Test]
        public void CheckLicense()
        {
            Assert.IsTrue(LicenseManager.CheckLicense());
        }

        [Test]
        public void Base64String_Symmetric()
        {
            var bytes = Encoding.ASCII.GetBytes("KeyCode");
            var based = Convert.ToBase64String(bytes);
            var bytesRes = Convert.FromBase64String(based);
            for(int i=0; i<bytes.Length;i++)
            {
                Assert.AreEqual(bytes[i], bytesRes[i]);
            }
        }
    }
}

#endif