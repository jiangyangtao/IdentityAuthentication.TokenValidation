using IdentityAuthentication.Model.Extensions;
using IdentityAuthentication.Model;
using IdentityAuthentication.TokenValidation.Abstractions;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace IdentityAuthentication.TokenValidation.TokenRefresh
{
    internal class HttpRefreshProvider : ITokenRefreshProvider
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IHttpClientFactory _httpClientFactory;

        public HttpRefreshProvider(
            IHttpContextAccessor httpContextAccessor,
            IHttpClientFactory httpClientFactory)
        {
            _httpContextAccessor = httpContextAccessor;
            _httpClientFactory = httpClientFactory;
        }

        public ConnectionType ConnectionType => ConnectionType.Http;

        public async Task<string> RefreshTokenAsync(string accessToken, string refreshToken)
        {
            var httpClient = _httpClientFactory.CreateClient();

            httpClient.DefaultRequestHeaders.SetAuthorization(accessToken);
            if (refreshToken.NotNullAndEmpty()) httpClient.DefaultRequestHeaders.SetRefreshToken(refreshToken);

            var response = await httpClient.PostAsync(TokenValidationConfiguration.AuthenticationEndpoints.RefreshToeknEndpoint, EmptyContent);
            if (response.IsSuccessStatusCode == false) return string.Empty;

            var json = await response.Content.ReadAsStringAsync();
            if (json.IsNullOrEmpty()) return string.Empty;

            var result = JObject.Parse(json);
            if (result.ContainsKey(HttpHeaderKeyDefaults.AccessToken) == false) return string.Empty;

            return result[HttpHeaderKeyDefaults.AccessToken].ToString();
        }
    }
}
