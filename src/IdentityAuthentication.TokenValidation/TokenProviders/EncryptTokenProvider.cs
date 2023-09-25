using IdentityAuthentication.Model.Enums;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.TokenProviders
{
    internal class EncryptTokenProvider : ITokenProvider
    {
        private readonly ITokenValidateFactory _tokenValidateFactory;

        public EncryptTokenProvider(ITokenValidateFactory tokenValidateFactory)
        {
            _tokenValidateFactory = tokenValidateFactory;
        }

        public TokenType TokenType => TokenType.JWT;

        public bool IsEncrypt => true;

        public Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            return _tokenValidateFactory.CreateTokenValidateProvider().TokenValidateAsync(token);
        }
    }
}
