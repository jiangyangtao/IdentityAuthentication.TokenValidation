using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityAuthentication.TokenValidation.Providers
{
    internal class TokenProviderFactory : ITokenProviderFactory
    {
        private readonly IServiceProvider _serviceProvider;

        public TokenProviderFactory(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public ITokenProvider CreateTokenProvider()
        {
            var tokenType = TokenValidationConfiguration.AuthenticationConfiguration.TokenType;
            return _serviceProvider.GetServices<ITokenProvider>().FirstOrDefault(a => a.TokenType == tokenType);
        }
    }
}
