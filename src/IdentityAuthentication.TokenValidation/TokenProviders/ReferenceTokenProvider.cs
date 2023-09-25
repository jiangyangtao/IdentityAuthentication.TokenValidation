using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.Model.Enums;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.TokenProviders
{
    internal class ReferenceTokenProvider : ITokenProvider
    {
        private readonly ITokenValidateFactory _tokenValidateFactory;


        public ReferenceTokenProvider(ITokenValidateFactory tokenValidateFactory)
        {
            _tokenValidateFactory = tokenValidateFactory;
        }

        public TokenType TokenType => TokenType.Reference;

        public Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            return _tokenValidateFactory.CreateTokenValidateProvider().TokenValidateAsync(token);
        }
    }
}
