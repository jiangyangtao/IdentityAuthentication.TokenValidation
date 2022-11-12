using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityAuthentication.TokenValidation.Providers
{
    internal class TokenValidateServiceFactory : ITokenValidateServiceFactory
    {
        private readonly IServiceProvider _serviceProvider;

        public TokenValidateServiceFactory(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public ITokenValidateService CreateTokenValidateService()
        {
            var protocol = "http";
            if (IdentityAuthenticationConfiguration.AuthenticationConfiguration.EnableGrpcConnection) protocol = "grpc";

            return _serviceProvider.GetServices<ITokenValidateService>().FirstOrDefault(a => a.CommunicationProtocol == protocol);
        }
    }
}
