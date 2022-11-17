using Grpc.Core;
using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.Model.Extensions;
using IdentityAuthentication.TokenValidation.Protos;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1.Ocsp;
using System.Net.Http;
using System.Net.Mime;
using System.Security.Claims;
using System.Text;

namespace IdentityAuthentication.TokenValidation.Services
{
    internal class RefreshTokenService
    {
        private const string AccessTokenKey = "access_token";
        private const string RefreTokenHeaderKey = "refresh-token";
        private const string ExpirationKey = ClaimTypes.Expiration;

        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IHttpClientFactory _httpClientFactory;

        private readonly TokenProto.TokenProtoClient _tokenProtoClient;

        public RefreshTokenService(
            IHttpContextAccessor httpContextAccessor,
            IHttpClientFactory httpClientFactory,
            TokenProto.TokenProtoClient tokenProtoClient)
        {
            _httpContextAccessor = httpContextAccessor;
            _httpClientFactory = httpClientFactory;
            _tokenProtoClient = tokenProtoClient;
        }

        public static StringContent EmptyContent => new(string.Empty, Encoding.UTF8, MediaTypeNames.Application.Json);

        public Metadata BuildGrpcHeader(string token = "") => new() { { HttpHeaderKeyDefaults.Authorization, token.IsNullOrEmpty() ? AccessToken : token } };

        public async Task<TokenValidationResult> BuildTokenSuccessResultAsync(string json)
        {
            var obj = JObject.Parse(json);
            var claims = new List<Claim>();

            string grantType = string.Empty, expiration = string.Empty;
            foreach (var item in obj)
            {
                var value = item.Value.ToString();
                if (item.Key.Equals(nameof(grantType), StringComparison.OrdinalIgnoreCase)) grantType = value;
                if (item.Key.Equals(ExpirationKey, StringComparison.OrdinalIgnoreCase)) expiration = value;

                claims.Add(new Claim(item.Key, value));
            }
            await RefreshTokenAsync(expiration);

            var identity = new ClaimsIdentity(claims, grantType);
            var result = new TokenValidationResult
            {
                IsValid = true,
                ClaimsIdentity = identity,
            };
            return result;
        }

        public async Task RefreshTokenAsync(IEnumerable<Claim> claims)
        {
            var expiration = claims.FirstOrDefault(a => a.Type == ExpirationKey);
            if (expiration != null) await RefreshTokenAsync(expiration.Value);
        }

        public async Task RefreshTokenAsync(string expiration)
        {
            if (TokenValidationConfiguration.AuthenticationConfiguration.TokenType == TokenType.JWT && RefreshToken.IsNullOrEmpty()) return;

            var r = DateTime.TryParse(expiration, out DateTime expirationTime);
            if (r == false) return;

            var refreshTime = DateTime.Now.AddSeconds(TokenValidationConfiguration.AccessTokenConfiguration.RefreshTime);
            if (refreshTime < expirationTime) return;

            if (TokenValidationConfiguration.AuthenticationConfiguration.EnableGrpcConnection)
            {
                await GrpcRefreshTokenAsync();
                return;
            }

            await HttpRefreshTokenAsync();
        }

        private async Task HttpRefreshTokenAsync()
        {
            var httpClient = _httpClientFactory.CreateClient();

            httpClient.DefaultRequestHeaders.SetAuthorization(AccessToken);
            if (RefreshToken.NotNullAndEmpty()) httpClient.DefaultRequestHeaders.SetRefreshToken(RefreshToken);

            var response = await httpClient.PostAsync(TokenValidationConfiguration.AuthenticationEndpoints.RefreshToeknEndpoint, EmptyContent);
            if (response.IsSuccessStatusCode == false) return;

            var json = await response.Content.ReadAsStringAsync();
            if (string.IsNullOrEmpty(json)) return;

            var result = JObject.Parse(json);
            if (result.ContainsKey(AccessTokenKey) == false) return;

            var accessToken = result[AccessTokenKey].ToString();
            if (string.IsNullOrEmpty(accessToken)) return;

            _httpContextAccessor.HttpContext?.Response.Headers.SetAccessToken(accessToken);
        }


        private async Task GrpcRefreshTokenAsync()
        {
            try
            {
                var headers = BuildGrpcHeader();
                var r = await _tokenProtoClient.RefreshAsync(new TokenRequest { Token = RefreshToken }, headers);
                if (r.Result == false) return;

                _httpContextAccessor.HttpContext?.Response.Headers.SetAccessToken(r.AccessToken);
            }
            finally { }
        }

        private string AccessToken => _httpContextAccessor.HttpContext?.Request.Headers.GetAuthorization();

        private string RefreshToken => _httpContextAccessor.HttpContext?.Request.Headers.GetRefreshToken();
    }
}
