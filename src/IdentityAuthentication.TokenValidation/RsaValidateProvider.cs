using IdentityAuthentication.Model;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace IdentityAuthentication.TokenValidation
{
    internal class RsaValidateProvider : ITokenValidateProvider
    {
        private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;
        private readonly Model.TokenValidation _tokenValidation;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly RefreshTokenProvider _refreshTokenService;
        private readonly Credentials PublicCredentials;

        public RsaValidateProvider(RefreshTokenProvider refreshTokenService, IAuthenticationConfigurationProvider configurationProvider)
        {
            var publicSignature = configurationProvider.RsaVerifySignatureConfiguration.ToRsaSignature();
            PublicCredentials = new Credentials(publicSignature);

            _tokenValidation = new Model.TokenValidation(configurationProvider.AccessTokenConfiguration, PublicCredentials);

            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            _tokenValidationParameters = _tokenValidation.GenerateTokenValidation();
            _refreshTokenService = refreshTokenService;
        }

        public bool IsRsaValidate => true;

        public async Task<TokenValidationResult> TokenValidateAsync(string token)
        {
            var tokenValidationResult = await _jwtSecurityTokenHandler.ValidateTokenAsync(token, _tokenValidationParameters);
            if (tokenValidationResult.IsValid) await _refreshTokenService.RefreshTokenAsync(tokenValidationResult.ClaimsIdentity.Claims);

            return tokenValidationResult;
        }
    }
}
