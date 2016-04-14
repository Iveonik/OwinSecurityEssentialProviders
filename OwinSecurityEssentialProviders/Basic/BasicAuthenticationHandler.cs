using System;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace OwinSecurityEssentialProviders.Basic
{
    public class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
    {
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            if (Request.HasBasicAuthorizationHeader())
            {
                string token = Request.Headers["Authorization"].Substring("Basic ".Length);
                var credentials = TryGetCredentialsFromToken(token);
                if (credentials == null)
                {
                    return null;
                }
                                
                if (await Options.Provider.ValidateCredentials(credentials))
                {
                    var identity = new ClaimsIdentity(BasicAuthentication.AuthenticationType);
                    identity.AddClaims(new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, credentials.Username, null, Options.AuthenticationType),
                        new Claim(ClaimTypes.AuthenticationMethod, Options.AuthenticationType)
                    });

                    var context = new ValidateIdentityContext(Context, new AuthenticationTicket(identity, new AuthenticationProperties()), Options);
                    await Options.Provider.ValidateIdentity(context);

                    if (context.Identity != null)
                    {
                        return new AuthenticationTicket(context.Identity, context.Properties);
                    }
                }
            }

            return null;
        }

        private BasicAuthenticationCredentials TryGetCredentialsFromToken(string token)
        {
            try
            {
                token = Encoding.ASCII.GetString(Convert.FromBase64String(token));
            }
            catch (FormatException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }

            int index = token.IndexOf(':');
            if (index == -1)
            {
                return null;
            }

            return new BasicAuthenticationCredentials
            {
                Username = token.Substring(0, index),
                Password = token.Substring(index + 1)
            };
        }
               

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
                if (challenge != null)
                {
                    Response.Headers.Append("WWW-Authenticate", "Basic realm=" + Options.Realm);
                }
            }

            return Task.FromResult<object>(null);
        }
    }
}
