using System;
using System.Linq;
using Microsoft.Owin;
using Microsoft.Owin.Extensions;
using Owin;

namespace OwinSecurityEssentialProviders.Windows
{
    public static class WindowsAuthenticationExtensions
    {
        public static IAppBuilder UseWindowsAuthentication(this IAppBuilder app)
        {
            return UseWindowsAuthentication(app, new WindowsAuthenticationOptions());
        }

        public static IAppBuilder UseWindowsAuthentication(this IAppBuilder app, WindowsAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }

            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(WindowsAuthenticationMiddleware), app, options);
            app.UseStageMarker(PipelineStage.Authenticate);

            return app;
        }


        public static bool HasNtlmAuthorizationHeader(this IOwinRequest request)
        {
            var authorizationHeader = request.Headers["Authorization"];
            if (String.IsNullOrEmpty(authorizationHeader))
            {
                return false;
            }

            return authorizationHeader.StartsWith("NTLM ") || authorizationHeader.StartsWith("Negotiate ");
        }

        public static bool IsNtlmAuthenticationNegotiated(this IOwinResponse response)
        {
            string[] authenticateHeaders;
            if (response.Headers.TryGetValue("WWW-Authenticate", out authenticateHeaders))
            {
                return authenticateHeaders.Contains("NTLM");
            }

            return false;
        }

        public static bool IsNtlmHandshake(this IOwinContext context)
        {
            return context.Request.HasNtlmAuthorizationHeader() || context.Response.IsNtlmAuthenticationNegotiated();
        }
    }
}
