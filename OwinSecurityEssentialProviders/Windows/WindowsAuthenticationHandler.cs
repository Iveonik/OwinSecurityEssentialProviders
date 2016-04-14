using System;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace OwinSecurityEssentialProviders.Windows
{
    public class WindowsAuthenticationHandler : AuthenticationHandler<WindowsAuthenticationOptions>
    {
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {            
            if (Request.User != null && IsNtlmIdentity(Request.User))
            {
                var identity = new ClaimsIdentity(Options.SignInAsAuthenticationType);
                identity.AddClaims(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, Context.Request.User.Identity.Name, null, Options.AuthenticationType),
                    new Claim(ClaimTypes.AuthenticationMethod, WindowsAuthentication.AuthenticationType)
                });
                identity.AddClaims((Context.Request.User.Identity as ClaimsIdentity).Claims);

                var properties = Options.StateDataFormat.Unprotect(Request.Cookies[Options.StateCookieName]);
                Response.Cookies.Delete(Options.StateCookieName);

                var context = new ValidateIdentityContext(Context, new AuthenticationTicket(identity, properties), Options);
                await Options.Provider.ValidateIdentity(context);

                if (context.Identity != null)
                {
                    return new AuthenticationTicket(context.Identity, context.Properties);
                }
            }

            return null;
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
                if (challenge != null)
                {
                    if (!Response.IsNtlmAuthenticationNegotiated())
                    {
                        var state = Options.StateDataFormat.Protect(challenge.Properties);
                        Response.Headers.Add("WWW-Authenticate", new[] { "Negotiate", "NTLM" });
                        Response.Cookies.Append(Options.StateCookieName, state);
                    }
                }
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Request.HasNtlmAuthorizationHeader())
            {
                var ticket = await AuthenticateAsync();
                if (ticket != null)
                {
                    Context.Authentication.SignIn(ticket.Properties, ticket.Identity);

                    string redirectUri = ticket.Properties.RedirectUri;
                    if (!String.IsNullOrWhiteSpace(redirectUri) && IsHostRelative(redirectUri))
                    {
                        Response.Redirect(redirectUri);
                        return true;
                    }
                }
            }

            return false;
        }

        private static bool IsHostRelative(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return false;
            }
            if (path.Length == 1)
            {
                return path[0] == '/';
            }
            return path[0] == '/' && path[1] != '/' && path[1] != '\\';
        }

        private static bool IsNtlmIdentity(IPrincipal principal)
        {
            var identity = principal.Identity;
            if (identity == null || !identity.IsAuthenticated)
            {
                return false;
            }

            return identity.AuthenticationType == "NTLM" || identity.AuthenticationType == "Negotiate";
        }
    }
}
