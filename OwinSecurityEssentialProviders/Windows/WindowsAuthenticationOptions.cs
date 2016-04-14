using Microsoft.Owin.Security;

namespace OwinSecurityEssentialProviders.Windows
{
    public class WindowsAuthenticationOptions : AuthenticationOptions
    {
        internal ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        internal string StateCookieName { get; set; }


        public string SignInAsAuthenticationType { get; set; }

        public IWindowsAuthenticationProvider Provider { get; set; }


        public WindowsAuthenticationOptions() : base(WindowsAuthentication.AuthenticationType)
        {
            AuthenticationMode = AuthenticationMode.Passive;
            StateCookieName = "WindowsAuthentication:state";
            Provider = new WindowsAuthenticationProvider();
        }
    }

    public static class WindowsAuthentication
    {
        public const string AuthenticationType = "Windows";
    }
}
