using Microsoft.Owin.Security;

namespace OwinSecurityEssentialProviders.Basic
{
    public class BasicAuthenticationOptions : AuthenticationOptions
    {
        public IBasicAuthenticationProvider Provider { get; set; }

        public string Realm { get; set; }

        public BasicAuthenticationOptions() : base(BasicAuthentication.AuthenticationType)
        {
            AuthenticationMode = AuthenticationMode.Active;
            Provider = new BasicAuthenticationProvider();
        }
    }

    public static class BasicAuthentication
    {
        public const string AuthenticationType = "Basic";
    }
}
