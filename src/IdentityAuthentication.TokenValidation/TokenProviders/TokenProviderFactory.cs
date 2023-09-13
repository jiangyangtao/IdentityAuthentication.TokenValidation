using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityAuthentication.TokenValidation.TokenProviders
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
            if (TokenValidationConfiguration.AuthenticationConfiguration.EnableJwtEncrypt)
                return _serviceProvider.GetServices<ITokenProvider>().FirstOrDefault(a => a.IsEncrypt);

            var tokenType = TokenValidationConfiguration.AuthenticationConfiguration.TokenType;
            return _serviceProvider.GetServices<ITokenProvider>().FirstOrDefault(a => a.TokenType == tokenType && a.IsEncrypt == false);
        }
    }
}
