using System.Threading.Tasks;

namespace OwinSecurityEssentialProviders.Basic
{
    public interface IBasicAuthenticationProvider
    {
        Task<bool> ValidateCredentials(BasicAuthenticationCredentials credentials);

        Task ValidateIdentity(ValidateIdentityContext context);
    }
}
