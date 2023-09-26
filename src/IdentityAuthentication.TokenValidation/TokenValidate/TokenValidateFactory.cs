using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityAuthentication.TokenValidation.TokenValidate
{
    internal class TokenValidateFactory : ITokenValidateFactory
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IAuthenticationConfigurationProvider _configurationProvider;

        public TokenValidateFactory(IServiceProvider serviceProvider, IAuthenticationConfigurationProvider configurationProvider)
        {
            _serviceProvider = serviceProvider;
            _configurationProvider = configurationProvider;
        }

        public ITokenValidateProvider CreateTokenValidateProvider()
        {
            var isRsaValidate = _configurationProvider.CanClientValidation;
            var provider = _serviceProvider.GetServices<ITokenValidateProvider>().FirstOrDefault(a => a.IsRsaValidate == isRsaValidate);

            return provider ?? throw new Exception("Not found TokenValidateProvider");
        }
    }
}
