using System.Threading.Tasks;

namespace OwinSecurityEssentialProviders.Windows
{
    public interface IWindowsAuthenticationProvider
    {
        Task ValidateIdentity(ValidateIdentityContext context);
    }
}
