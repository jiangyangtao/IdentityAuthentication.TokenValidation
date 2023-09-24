using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Enums;
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
            var connectionType = ConnectionType.Http;
            if (_configurationProvider.AuthenticationConfiguration.EnableGrpcConnection) connectionType = ConnectionType.Grpc;

            return _serviceProvider.GetServices<ITokenValidateProvider>().FirstOrDefault(a => a.ConnectionType == connectionType);
        }
    }
}
