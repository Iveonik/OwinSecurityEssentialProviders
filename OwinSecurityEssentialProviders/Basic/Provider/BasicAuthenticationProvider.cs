using System;
using System.Threading.Tasks;

namespace OwinSecurityEssentialProviders.Basic
{
    public class BasicAuthenticationProvider : IBasicAuthenticationProvider
    {
        public BasicAuthenticationProvider()
        {
            OnValidateCredentials = credentials => Task.FromResult(true);
            OnValidateIdentity = context => Task.FromResult<object>(null);
        }

        public Func<BasicAuthenticationCredentials, Task<bool>> OnValidateCredentials { get; set; }

        Task<bool> IBasicAuthenticationProvider.ValidateCredentials(BasicAuthenticationCredentials credentials)
        {
            return OnValidateCredentials(credentials);
        }

        public Func<ValidateIdentityContext, Task> OnValidateIdentity { get; set; }

        Task IBasicAuthenticationProvider.ValidateIdentity(ValidateIdentityContext context)
        {
            return OnValidateIdentity(context);
        }
    }
}
