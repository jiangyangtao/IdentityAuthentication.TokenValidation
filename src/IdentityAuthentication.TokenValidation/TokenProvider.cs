using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation
{
    internal class TokenProvider : ITokenProvider
    {
        private readonly ITokenValidateProvider _tokenValidateProvider;

        public TokenProvider(IAuthenticationFactory authenticationFactory)
        {
            _tokenValidateProvider = authenticationFactory.CreateTokenValidateProvider();
        }

        public async Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            if (token.IsNullOrEmpty()) return Model.TokenValidation.FailedTokenValidationResult;

            return await _tokenValidateProvider.TokenValidateAsync(token);
        }
    }
}
