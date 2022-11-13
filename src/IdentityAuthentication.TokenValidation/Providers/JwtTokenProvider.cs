using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.TokenValidation.Abstractions;
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

        public JwtTokenProvider()
        {
            _rsaAlgorithm = new RsaAlgorithm(IdentityAuthenticationConfiguration.SecretKeyConfiguration);
            _tokenValidation = new Model.TokenValidation(
                        IdentityAuthenticationConfiguration.AccessTokenConfiguration,
                        IdentityAuthenticationConfiguration.RefreshTokenConfiguration,
                        IdentityAuthenticationConfiguration.SecretKeyConfiguration,
                        IdentityAuthenticationConfiguration.AuthenticationConfiguration);

            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            _tokenValidationParameters = _tokenValidation.GenerateAccessTokenValidation();
        }

        public TokenType TokenType => TokenType.JWT;


        public async Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            token = HandleTokenDecrypt(token);

            var tokenValidationResult = await _jwtSecurityTokenHandler.ValidateTokenAsync(token, _tokenValidationParameters);
            return tokenValidationResult;
        }

        /// <summary>
        /// 处理 token 的解密
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        private string HandleTokenDecrypt(string token)
        {
            if (IdentityAuthenticationConfiguration.AuthenticationConfiguration.EnableJwtEncrypt == false) return token;

            return _rsaAlgorithm.Decrypt(token);
        }
    }
}
