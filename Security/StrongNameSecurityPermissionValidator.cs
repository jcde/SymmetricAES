using System.Diagnostics;
using System.Reflection;
using System.Security;
using System.Text;

namespace ICB.Domain.Security
{
    internal class StrongNameSecurityPermissionValidator
    {
        public static void Validate()
        {
#if !UNIT_TESTS
            AssertIsCallLegall();
#endif
        }
        
        private static void AssertIsCallLegall()
        {
            if (!IsCallLegal())
                throw new SecurityException();
        }

        private static bool IsCallLegal()
        {
            string requiredPublicKey = GetAssemblyPublicKey(Assembly.GetCallingAssembly());
            bool result = true;
            Assembly executingAssembly = Assembly.GetExecutingAssembly();
            Assembly licenseManagerAssembly = typeof (System.ComponentModel.LicenseManager).Assembly;
            StackTrace stackTrace = new StackTrace();
            foreach (StackFrame stackFrame in stackTrace.GetFrames())
            {
                Assembly assembly = stackFrame.GetMethod().Module.Assembly;
                if (assembly != executingAssembly && assembly != licenseManagerAssembly)
                {
                    string assemblyPublicKey = GetAssemblyPublicKey(assembly);
                    if (assemblyPublicKey == requiredPublicKey)
                        result = true;
                    else
                        result = false;
                    break;
                }
            }
            return result;
        }

        internal static string GetAssemblyPublicKey(Assembly assembly = null)
        {
            return
            "1111";
            //"65306266326430653935643135373430";

            /*byte[] publicKey = assembly.GetName().GetPublicKey();
            StringBuilder stringBuilder = new StringBuilder();
            foreach (byte publicKeyByte in publicKey)
                stringBuilder.Append(publicKeyByte.ToString("X2"));
            return stringBuilder.ToString();*/
        }
    }
}
