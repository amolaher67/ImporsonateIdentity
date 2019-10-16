using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;
//for dotnet core 3.0
namespace TestApp
{
    public class IdentityImpersonator
    {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(String lpszUsername, String lpszDomain, String lpszPassword,int dwLogonType, int dwLogonProvider, out SafeAccessTokenHandle phToken);

        public static void ImporsonateIdentity(string domainName, string userName, string password,Action userAction)
        {
            // Get the user token for the specified user, domain, and password using the   
            // unmanaged LogonUser method.   
            // The local machine name can be used for the domain name to impersonate a user on this machine.  
            //Console.Write("Enter the name of the domain on which to log on: ");
            //string domainName = Console.ReadLine();

            // Console.Write("Enter the login of a user on {0} that you wish to impersonate: ", domainName);
            //  string userName = Console.ReadLine();

            //  Console.Write("Enter the password for {0}: ", userName);

            const int LOGON32_PROVIDER_DEFAULT = 0;
            //This parameter causes LogonUser to create a primary token.   
            const int LOGON32_LOGON_INTERACTIVE = 2;

            // Call LogonUser to obtain a handle to an access token.   
            SafeAccessTokenHandle safeAccessTokenHandle;
            bool returnValue = LogonUser(userName, domainName, password,
                LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
                out safeAccessTokenHandle);

            if (false == returnValue)
            {
                int ret = Marshal.GetLastWin32Error();
                Console.WriteLine("LogonUser failed with error code : {0}", ret);
                throw new System.ComponentModel.Win32Exception(ret);
            }

            Console.WriteLine("Did LogonUser Succeed? " + (returnValue ? "Yes" : "No"));
            // Check the identity.  
            Console.WriteLine("Before impersonation: " + WindowsIdentity.GetCurrent().Name);

            // Note: if you want to run as unimpersonated, pass  
            // 'SafeAccessTokenHandle.InvalidHandle' instead of variable 'safeAccessTokenHandle'  
            WindowsIdentity.RunImpersonated(safeAccessTokenHandle, userAction);
            
            // Check the identity again.  
            Console.WriteLine("After impersonation: " + WindowsIdentity.GetCurrent().Name);

        }
    }
}
