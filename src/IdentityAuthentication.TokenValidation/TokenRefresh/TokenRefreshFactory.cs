using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityAuthentication.TokenValidation.TokenRefresh
{
    internal class TokenRefreshFactory : ITokenRefreshFactory
    {
        private readonly IServiceProvider _serviceProvider;

        public TokenRefreshFactory(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public ITokenRefreshProvider CreateTokenRefreshProvider()
        {
            var connectionType = ConnectionType.Http;
            if (TokenValidationConfiguration.AuthenticationConfiguration.EnableGrpcConnection) connectionType = ConnectionType.Grpc;

            return _serviceProvider.GetServices<ITokenRefreshProvider>().FirstOrDefault(a => a.ConnectionType == connectionType);
        }
    }
}
