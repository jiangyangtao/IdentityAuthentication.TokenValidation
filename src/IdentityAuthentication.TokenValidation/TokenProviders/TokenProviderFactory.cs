using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityAuthentication.TokenValidation.TokenProviders
{
    internal class TokenProviderFactory : ITokenProviderFactory
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IAuthenticationConfigurationProvider _configurationProvider;

        public TokenProviderFactory(IServiceProvider serviceProvider, IAuthenticationConfigurationProvider configurationProvider)
        {
            _serviceProvider = serviceProvider;
            _configurationProvider = configurationProvider;
        }

        public ITokenProvider CreateTokenProvider()
        {
            if (_configurationProvider.CanClientValidation)
                return _serviceProvider.GetServices<ITokenProvider>().FirstOrDefault(a => a.TokenType == _configurationProvider.AuthenticationConfiguration.TokenType);

            var tokenType = _configurationProvider.AuthenticationConfiguration.TokenType;
            return _serviceProvider.GetServices<ITokenProvider>().FirstOrDefault(a => a.TokenType == tokenType);
        }
    }
}
