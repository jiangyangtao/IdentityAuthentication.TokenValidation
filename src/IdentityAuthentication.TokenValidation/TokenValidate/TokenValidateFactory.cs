using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityAuthentication.TokenValidation.TokenValidate
{
    internal class TokenValidateFactory : ITokenValidateFactory
    {
        private readonly IServiceProvider _serviceProvider;

        public TokenValidateFactory(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public ITokenValidateProvider CreateTokenValidateProvider()
        {
            var connectionType = ConnectionType.Http;
            if (TokenValidationConfiguration.AuthenticationConfiguration.EnableGrpcConnection) connectionType = ConnectionType.Grpc;

            return _serviceProvider.GetServices<ITokenValidateProvider>().FirstOrDefault(a => a.ConnectionType == connectionType);
        }
    }
}
