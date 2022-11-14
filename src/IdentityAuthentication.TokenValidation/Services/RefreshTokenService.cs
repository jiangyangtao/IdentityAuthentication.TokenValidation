using Grpc.Core;
using IdentityAuthentication.TokenValidation.Protos;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
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

        public Metadata BuildGrpcHeader(string token = "") => new() { { "Authorization", string.IsNullOrEmpty(token) ? Token : token } };

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
            var r = DateTime.TryParse(expiration, out DateTime expirationTime);
            if (r == false) return;

            var refreshTime = DateTime.Now.AddSeconds(IdentityAuthenticationConfiguration.AccessTokenConfiguration.RefreshTime);
            if (refreshTime < expirationTime) return;

            if (IdentityAuthenticationConfiguration.AuthenticationConfiguration.EnableGrpcConnection)
            {
                await GrpcRefreshTokenAsync();
                return;
            }

            await HttpRefreshTokenAsync();
        }

        private async Task HttpRefreshTokenAsync()
        {
            var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Add("Authorization", Token);
            var url = IdentityAuthenticationConfiguration.AuthenticationEndpoints.RefreshToeknEndpoint;
            var response = await httpClient.PostAsync(url, EmptyContent);
            if (response.IsSuccessStatusCode == false) return;

            var json = await response.Content.ReadAsStringAsync();
            if (string.IsNullOrEmpty(json)) return;

            var result = JObject.Parse(json);
            if (result.ContainsKey(AccessTokenKey) == false) return;

            var accessToken = result[AccessTokenKey].ToString();
            if (string.IsNullOrEmpty(accessToken)) return;

            _httpContextAccessor.HttpContext?.Response.Headers.TryAdd(RefreTokenHeaderKey, accessToken);
        }

        private async Task GrpcRefreshTokenAsync()
        {
            try
            {
                var headers = BuildGrpcHeader();
                var r = await _tokenProtoClient.RefreshAsync(new TokenRequest { Token = Token }, headers);
                if (r.Result == false) return;

                _httpContextAccessor.HttpContext?.Response.Headers.TryAdd(RefreTokenHeaderKey, r.AccessToken);
            }
            finally { }
        }

        private string Token
        {
            get
            {
                var token = _httpContextAccessor.HttpContext?.Request.Headers.Authorization.ToString();
                if (token.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    token = token["Bearer ".Length..].Trim();
                }

                return token;
            }
        }

    }
}
