using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Extensions;
using Owin;

namespace OwinSecurityEssentialProviders.Basic
{
    public static class BasicAuthenticationExtensions
    {
        public static IAppBuilder UseBasicAuthentication(this IAppBuilder app, Func<BasicAuthenticationCredentials, Task<bool>> validateCredentialsCallback)
        {
            return UseBasicAuthentication(app, new BasicAuthenticationOptions
            {
                Provider = new BasicAuthenticationProvider { OnValidateCredentials = validateCredentialsCallback }
            });
        }

        public static IAppBuilder UseBasicAuthentication(this IAppBuilder app, BasicAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(BasicAuthenticationMiddleware), app, options);
            app.UseStageMarker(PipelineStage.Authenticate);

            return app;
        }

        public static bool HasBasicAuthorizationHeader(this IOwinRequest request)
        {
            var authorizationHeader = request.Headers["Authorization"];
            if (String.IsNullOrEmpty(authorizationHeader))
            {
                return false;
            }

            return authorizationHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase);
        }
    }
}
