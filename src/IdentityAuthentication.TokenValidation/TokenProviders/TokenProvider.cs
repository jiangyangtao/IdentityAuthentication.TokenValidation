using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.TokenProviders
{
    internal class TokenProvider : ITokenProvider
    {
        private readonly ITokenValidateProvider _tokenValidateProvider;

        public TokenProvider(ITokenValidateFactory tokenValidateFactory)
        {
            _tokenValidateProvider = tokenValidateFactory.CreateTokenValidateProvider();
        }

        public async Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            if (token.IsNullOrEmpty()) return Model.TokenValidation.FailedTokenValidationResult;

            return await _tokenValidateProvider.TokenValidateAsync(token);
        }
    }
}
