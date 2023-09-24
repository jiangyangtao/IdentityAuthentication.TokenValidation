using IdentityAuthentication.Model.Enums;
using IdentityAuthentication.Model.Extensions;
using IdentityAuthentication.Model.Handles;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace IdentityAuthentication.TokenValidation.TokenRefresh
{
    internal class RefreshTokenProvider : IRefreshTokenProvider
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly TokenValidationOptions _validationOptions;
        private readonly ITokenRefreshFactory _tokenRefreshFactory;
        private readonly IAuthenticationConfigurationProvider _configurationProvider;


        public RefreshTokenProvider(
            IHttpContextAccessor httpContextAccessor,
            IOptions<TokenValidationOptions> tokenValidationOptions,
            ITokenRefreshFactory tokenRefreshFactory,
            IAuthenticationConfigurationProvider configurationProvider)
        {
            _httpContextAccessor = httpContextAccessor;
            _validationOptions = tokenValidationOptions.Value;
            _tokenRefreshFactory = tokenRefreshFactory;
            _configurationProvider = configurationProvider;
        }

        private string AccessToken => _httpContextAccessor.HttpContext?.Request.Headers.GetAuthorization();

        private string RefreshToken => _httpContextAccessor.HttpContext?.Request.Headers.GetRefreshToken();

        public async Task RefreshTokenAsync(IEnumerable<Claim> claims)
        {
            var expiration = claims.FirstOrDefault(a => a.Type == IdentityAuthenticationDefaultKeys.Expiration);
            if (expiration != null) await RefreshTokenAsync(expiration.Value);
        }

        public async Task RefreshTokenAsync(string expiration)
        {
            if (_validationOptions.EnableJWTRefreshToken == false) return;
            if (_configurationProvider.AuthenticationConfiguration.TokenType == TokenType.JWT && RefreshToken.IsNullOrEmpty()) return;

            var r = DateTime.TryParse(expiration, out DateTime expirationTime);
            if (r == false) return;

            var refreshTime = DateTime.Now.AddSeconds(_configurationProvider.AccessTokenConfiguration.RefreshTime);
            if (refreshTime < expirationTime) return;

            var accessToken = await _tokenRefreshFactory.CreateTokenRefreshProvider().RefreshTokenAsync(AccessToken, RefreshToken);
            if (accessToken.NotNullAndEmpty()) _httpContextAccessor.HttpContext?.Response.Headers.SetAccessToken(accessToken);
        }
    }
}
