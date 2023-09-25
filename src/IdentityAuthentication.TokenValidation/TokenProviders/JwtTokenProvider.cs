using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Enums;
using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.TokenRefresh;
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
        private readonly Credentials PublicCredentials;

        public JwtTokenProvider(RefreshTokenProvider refreshTokenService, IAuthenticationConfigurationProvider configurationProvider)
        {
            var publicSignature = configurationProvider.RsaVerifySignatureConfiguration.ToRsaSignature();
            PublicCredentials = new Credentials(publicSignature);

            _tokenValidation = new Model.TokenValidation(configurationProvider.AccessTokenConfiguration, PublicCredentials);

            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            _tokenValidationParameters = _tokenValidation.GenerateTokenValidation();
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
