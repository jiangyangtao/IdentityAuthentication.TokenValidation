using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.TokenValidate
{
    internal class RemoteValidateProvider : ITokenValidateProvider
    {
        private readonly IServerValidateProvider _serverValidateProvider;

        public RemoteValidateProvider(IAuthenticationFactory remoteFactory)
        {
            _serverValidateProvider = remoteFactory.CreateValidateProvider();
        }

        public bool IsRsaValidate => false;

        public Task<TokenValidationResult> TokenValidateAsync(string token) => _serverValidateProvider.TokenValidateAsync(token);
    }
}
