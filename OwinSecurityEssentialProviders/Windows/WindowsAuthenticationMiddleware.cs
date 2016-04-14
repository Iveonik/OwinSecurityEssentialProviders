using System;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace OwinSecurityEssentialProviders.Windows
{
    public class WindowsAuthenticationMiddleware : AuthenticationMiddleware<WindowsAuthenticationOptions>
    {
        public WindowsAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, WindowsAuthenticationOptions options)
            : base(next, options)
        {
            if (String.IsNullOrWhiteSpace(Options.SignInAsAuthenticationType))
            {
                options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            if (options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(WindowsAuthenticationMiddleware).FullName, options.AuthenticationType);
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
        }

        protected override AuthenticationHandler<WindowsAuthenticationOptions> CreateHandler()
        {
            return new WindowsAuthenticationHandler();
        }
    }
}
