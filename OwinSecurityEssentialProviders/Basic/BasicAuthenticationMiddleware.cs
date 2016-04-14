using Microsoft.Owin;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace OwinSecurityEssentialProviders.Basic
{
    public class BasicAuthenticationMiddleware : AuthenticationMiddleware<BasicAuthenticationOptions>
    {
        public BasicAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, BasicAuthenticationOptions options)
            : base(next, options)
        { }

        protected override AuthenticationHandler<BasicAuthenticationOptions> CreateHandler()
        {
            return new BasicAuthenticationHandler();
        }
    }
}
