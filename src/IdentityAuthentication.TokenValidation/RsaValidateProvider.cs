using IdentityAuthentication.Model;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace IdentityAuthentication.TokenValidation
{
    internal class RsaValidateProvider : ITokenValidateProvider
    {
        private readonly IRefreshTokenProvider _refreshTokenService;
        private readonly Credentials PublicCredentials;
        private readonly IAuthenticationConfigurationProvider _configurationProvider;
        private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;

        public RsaValidateProvider(IRefreshTokenProvider refreshTokenService, IAuthenticationConfigurationProvider configurationProvider)
        {
            var publicSignature = configurationProvider.RsaVerifySignatureConfiguration.ToRsaSignature();
            PublicCredentials = new Credentials(publicSignature);

            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            _refreshTokenService = refreshTokenService;
            _configurationProvider = configurationProvider;
        }

        public bool IsRsaValidate => true;

        public async Task<TokenValidationResult> TokenValidateAsync(string token)
        {
            using var tokenValidation = new Model.TokenValidation(_configurationProvider.AccessTokenConfiguration, PublicCredentials);

            var tokenValidationParameters = tokenValidation.GenerateTokenValidation();
            var tokenValidationResult = await _jwtSecurityTokenHandler.ValidateTokenAsync(token, tokenValidationParameters);
            if (tokenValidationResult.IsValid) await _refreshTokenService.RefreshTokenAsync(tokenValidationResult.ClaimsIdentity.Claims);

            return tokenValidationResult;
        }
    }
}
