using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Enums;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityAuthentication.TokenValidation.TokenValidate
{
    internal class RemoteValidateFactory : IRemoteValidateFactory
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly IAuthenticationConfigurationProvider _configurationProvider;

        public RemoteValidateFactory(IAuthenticationConfigurationProvider configurationProvider, IServiceProvider serviceProvider)
        {
            _configurationProvider = configurationProvider;
            _serviceProvider = serviceProvider;
        }

        public IServerValidateProvider CreateValidateProvider()
        {
            var connectionType = ConnectionType.Http;
            if (_configurationProvider.AuthenticationConfiguration.EnableGrpcConnection) connectionType = ConnectionType.Grpc;

            var provider = _serviceProvider.GetServices<IServerValidateProvider>().FirstOrDefault(a => a.ConnectionType == connectionType);

            return provider ?? throw new Exception("Not found IServerValidateProvider the realize");
        }
    }
}
