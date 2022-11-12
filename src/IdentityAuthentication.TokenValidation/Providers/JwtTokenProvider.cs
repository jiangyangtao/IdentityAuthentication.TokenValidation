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

        public JwtTokenProvider()
        {
            _rsaAlgorithm = new RsaAlgorithm(IdentityAuthenticationConfiguration.SecretKeyConfiguration);
        }

        public TokenType TokenType => TokenType.JWT;


        private TokenValidationParameters _tokenValidationParameters;

        private TokenValidationParameters TokenValidationParameters
        {
            get
            {
                if (_tokenValidationParameters == null)
                    _tokenValidationParameters = TokenValidation.GenerateAccessTokenValidation();

                return _tokenValidationParameters;
            }
        }


        private Model.TokenValidation _tokenValidation;

        private Model.TokenValidation TokenValidation
        {
            get
            {
                if (_tokenValidation == null)
                {
                    _tokenValidation = new Model.TokenValidation(
                        IdentityAuthenticationConfiguration.AccessTokenConfiguration,
                        IdentityAuthenticationConfiguration.RefreshTokenConfiguration,
                        IdentityAuthenticationConfiguration.SecretKeyConfiguration,
                        IdentityAuthenticationConfiguration.AuthenticationConfiguration);
                }

                return _tokenValidation;
            }
        }


        public async Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            token = HandleTokenDecrypt(token);

            var tokenValidationResult = await _jwtSecurityTokenHandler.ValidateTokenAsync(token, TokenValidationParameters);
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
