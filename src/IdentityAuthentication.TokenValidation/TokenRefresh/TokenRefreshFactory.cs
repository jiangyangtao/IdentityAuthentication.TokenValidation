using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Enums;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityAuthentication.TokenValidation.TokenRefresh
{
    internal class TokenRefreshFactory : ITokenRefreshFactory
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IAuthenticationConfigurationProvider _configurationProvider;

        public TokenRefreshFactory(IServiceProvider serviceProvider, IAuthenticationConfigurationProvider configurationProvider)
        {
            _serviceProvider = serviceProvider;
            _configurationProvider = configurationProvider;
        }

        public ITokenRefreshProvider CreateTokenRefreshProvider()
        {
            var connectionType = ConnectionType.Http;
            if (_configurationProvider.AuthenticationConfiguration.EnableGrpcConnection) connectionType = ConnectionType.Grpc;

            return _serviceProvider.GetServices<ITokenRefreshProvider>().FirstOrDefault(a => a.ConnectionType == connectionType);
        }
    }
}
