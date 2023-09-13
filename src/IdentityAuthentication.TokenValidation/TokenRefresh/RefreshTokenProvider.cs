using Grpc.Core;
using IdentityAuthentication.Application.Grpc.Provider;
using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.Model.Extensions;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System.Net.Mime;
using System.Security.Claims;
using System.Text;

namespace IdentityAuthentication.TokenValidation.TokenRefresh
{
    internal class RefreshTokenProvider : IRefreshTokenProvider
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly TokenValidationOptions _validationOptions;
        private readonly TokenGrpcProvider.TokenGrpcProviderClient _tokenGrpcProvider;
        private readonly ITokenRefreshFactory _tokenRefreshFactory;


        public RefreshTokenProvider(
            IHttpContextAccessor httpContextAccessor,
            IHttpClientFactory httpClientFactory,
            IOptions<TokenValidationOptions> tokenValidationOptions,
            TokenGrpcProvider.TokenGrpcProviderClient tokenGrpcProvider,
            ITokenRefreshFactory tokenRefreshFactory)
        {
            _httpContextAccessor = httpContextAccessor;
            _httpClientFactory = httpClientFactory;
            _validationOptions = tokenValidationOptions.Value;
            _tokenGrpcProvider = tokenGrpcProvider;
            _tokenRefreshFactory = tokenRefreshFactory;
        }

        public static StringContent EmptyContent => new(string.Empty, Encoding.UTF8, MediaTypeNames.Application.Json);

        public Metadata BuildGrpcHeader(string token = "") => new() { { HttpHeaderKeyDefaults.Authorization, token.IsNullOrEmpty() ? AccessToken : token } };

        public async Task RefreshTokenAsync(IEnumerable<Claim> claims)
        {
            var expiration = claims.FirstOrDefault(a => a.Type == ClaimKeyDefaults.Expiration);
            if (expiration != null) await RefreshTokenAsync(expiration.Value);
        }

        public async Task RefreshTokenAsync(string expiration)
        {
            if (_validationOptions.EnableJWTRefreshToken == false) return;
            if (TokenValidationConfiguration.AuthenticationConfiguration.TokenType == TokenType.JWT && RefreshToken.IsNullOrEmpty()) return;

            var r = DateTime.TryParse(expiration, out DateTime expirationTime);
            if (r == false) return;

            var refreshTime = DateTime.Now.AddSeconds(TokenValidationConfiguration.AccessTokenConfiguration.RefreshTime);
            if (refreshTime < expirationTime) return;

            var accessToken = await _tokenRefreshFactory.CreateTokenRefreshProvider().RefreshTokenAsync(AccessToken, RefreshToken);
            if (accessToken.NotNullAndEmpty()) _httpContextAccessor.HttpContext?.Response.Headers.SetAccessToken(accessToken);
        }

        private async Task HttpRefreshTokenAsync()
        {
            var httpClient = _httpClientFactory.CreateClient();

            httpClient.DefaultRequestHeaders.SetAuthorization(AccessToken);
            if (RefreshToken.NotNullAndEmpty()) httpClient.DefaultRequestHeaders.SetRefreshToken(RefreshToken);

            var response = await httpClient.PostAsync(TokenValidationConfiguration.AuthenticationEndpoints.RefreshToeknEndpoint, EmptyContent);
            if (response.IsSuccessStatusCode == false) return;

            var json = await response.Content.ReadAsStringAsync();
            if (json.IsNullOrEmpty()) return;

            var result = JObject.Parse(json);
            if (result.ContainsKey(HttpHeaderKeyDefaults.AccessToken) == false) return;

            var accessToken = result[HttpHeaderKeyDefaults.AccessToken].ToString();
            if (accessToken.IsNullOrEmpty()) return;

            _httpContextAccessor.HttpContext?.Response.Headers.SetAccessToken(accessToken);
        }


        private async Task GrpcRefreshTokenAsync()
        {
            try
            {
                var headers = BuildGrpcHeader();
                var r = await _tokenGrpcProvider.RefreshAsync(new RefreshTokenRequest { RefreshToken = RefreshToken }, headers);
                if (r.Result == false) return;

                if (r.AccessToken.NotNullAndEmpty())
                    _httpContextAccessor.HttpContext?.Response.Headers.SetAccessToken(r.AccessToken);
            }
            finally { }
        }

        private string AccessToken => _httpContextAccessor.HttpContext?.Request.Headers.GetAuthorization();

        private string RefreshToken => _httpContextAccessor.HttpContext?.Request.Headers.GetRefreshToken();
    }
}
