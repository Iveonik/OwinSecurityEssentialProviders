using System;
using System.Threading.Tasks;

namespace OwinSecurityEssentialProviders.Windows
{
    public class WindowsAuthenticationProvider : IWindowsAuthenticationProvider
    {
        public WindowsAuthenticationProvider()
        {
            OnValidateIdentity = context => Task.FromResult<object>(null);
        }

        public Func<ValidateIdentityContext, Task> OnValidateIdentity { get; set; }

        public Task ValidateIdentity(ValidateIdentityContext context)
        {
            return OnValidateIdentity.Invoke(context);
        }
    }
}
