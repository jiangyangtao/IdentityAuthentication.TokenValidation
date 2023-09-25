using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.Model.Enums;
using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.TokenRefresh;
using IdentityAuthentication.TokenValidation.TokenValidate;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace IdentityAuthentication.TokenValidation.TokenProviders
{
    internal class JwtTokenProvider : ITokenProvider
    {
        private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;
        private readonly Model.TokenValidation _tokenValidation;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly RefreshTokenProvider _refreshTokenService;

        public JwtTokenProvider(RefreshTokenProvider refreshTokenService)
        {
            _tokenValidation = new Model.TokenValidation(
                        TokenValidationConfiguration.AccessTokenConfiguration,
                        TokenValidationConfiguration.RefreshTokenConfiguration,
                        TokenValidationConfiguration.SecretKeyConfiguration,
                        TokenValidationConfiguration.AuthenticationConfiguration);

            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            _tokenValidationParameters = _tokenValidation.GenerateAccessTokenValidation();
            _refreshTokenService = refreshTokenService;
        }

        public TokenType TokenType => TokenType.JWT;

        public bool IsEncrypt => false;

        public async Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            var tokenValidationResult = await _jwtSecurityTokenHandler.ValidateTokenAsync(token, _tokenValidationParameters);
            if (tokenValidationResult.IsValid) await _refreshTokenService.RefreshTokenAsync(tokenValidationResult.ClaimsIdentity.Claims);

            return tokenValidationResult;
        }
    }
}
