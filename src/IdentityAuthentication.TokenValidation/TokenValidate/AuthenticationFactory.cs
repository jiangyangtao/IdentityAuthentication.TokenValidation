using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Enums;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityAuthentication.TokenValidation.TokenValidate
{
    internal class AuthenticationFactory : IAuthenticationFactory
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IAuthenticationConfigurationProvider _configurationProvider;
        private readonly ConnectionType ConnectionType;

        public AuthenticationFactory(IAuthenticationConfigurationProvider configurationProvider, IServiceProvider serviceProvider)
        {
            _configurationProvider = configurationProvider;
            _serviceProvider = serviceProvider;

            ConnectionType = ConnectionType.Http;
            if (_configurationProvider.AuthenticationConfiguration.EnableGrpcConnection) ConnectionType = ConnectionType.Grpc;
        }

        public ITokenRefreshProvider CreateTokenRefreshProvider()
        {
            var provider = _serviceProvider.GetServices<IAuthenticationProvider>().FirstOrDefault(a => a.IsRsaValidate == false && a.ConnectionType == ConnectionType);
            return provider ?? throw new Exception("Not found IServerValidateProvider the realize");
        }

        public ITokenValidateProvider CreateTokenValidateProvider()
        {
            if (_configurationProvider.CanClientValidation)
                return _serviceProvider.GetServices<ITokenValidateProvider>().FirstOrDefault(a => a.IsRsaValidate == true) ?? throw new Exception("Not found ITokenValidateProvider the rsa realize");

            var provider = _serviceProvider.GetServices<IAuthenticationProvider>().FirstOrDefault(a => a.IsRsaValidate == false && a.ConnectionType == ConnectionType);
            return provider as ITokenValidateProvider ?? throw new Exception("Not found ITokenValidateProvider the realize");
        }
    }
}
