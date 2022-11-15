using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Services;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace IdentityAuthentication.TokenValidation.Providers
{
    internal class JwtTokenProvider : ITokenProvider
    {
        private readonly RsaAlgorithm _rsaAlgorithm;
        private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;
        private readonly Model.TokenValidation _tokenValidation;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly RefreshTokenService _claimHandler;

        public JwtTokenProvider(RefreshTokenService claimHandler)
        {
            _rsaAlgorithm = new RsaAlgorithm(TokenValidationConfiguration.SecretKeyConfiguration);
            _tokenValidation = new Model.TokenValidation(
                        TokenValidationConfiguration.AccessTokenConfiguration,
                        TokenValidationConfiguration.RefreshTokenConfiguration,
                        TokenValidationConfiguration.SecretKeyConfiguration,
                        TokenValidationConfiguration.AuthenticationConfiguration);

            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            _tokenValidationParameters = _tokenValidation.GenerateAccessTokenValidation();
            _claimHandler = claimHandler;
        }

        public TokenType TokenType => TokenType.JWT;

      


        public async Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            token = HandleTokenDecrypt(token);

            var tokenValidationResult = await _jwtSecurityTokenHandler.ValidateTokenAsync(token, _tokenValidationParameters);
            await _claimHandler.RefreshTokenAsync(tokenValidationResult.ClaimsIdentity.Claims);

            return tokenValidationResult;
        }

        /// <summary>
        /// 处理 token 的解密
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        private string HandleTokenDecrypt(string token)
        {
            if (TokenValidationConfiguration.AuthenticationConfiguration.EnableJwtEncrypt == false) return token;

            return _rsaAlgorithm.Decrypt(token);
        }
    }
}
