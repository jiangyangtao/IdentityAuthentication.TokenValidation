using IdentityAuthentication.Model.Extensions;
using IdentityAuthentication.Model.Handles;
using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Enums;
using Newtonsoft.Json.Linq;

namespace IdentityAuthentication.TokenValidation.TokenRefresh
{
    internal class HttpRefreshProvider : ITokenRefreshProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IAuthenticationConfigurationProvider _configurationProvider;

        public HttpRefreshProvider(
            IHttpClientFactory httpClientFactory,
            IAuthenticationConfigurationProvider configurationProvider)
        {
            _httpClientFactory = httpClientFactory;
            _configurationProvider = configurationProvider;
        }

        public ConnectionType ConnectionType => ConnectionType.Http;

        public async Task<string> RefreshTokenAsync(string accessToken, string refreshToken)
        {
            var httpClient = _httpClientFactory.CreateClient();

            httpClient.DefaultRequestHeaders.SetAuthorization(accessToken);
            if (refreshToken.NotNullAndEmpty()) httpClient.DefaultRequestHeaders.SetRefreshToken(refreshToken);

            var response = await httpClient.PostAsync(_configurationProvider.AuthenticationEndpoints.RefreshToeknEndpoint, TokenBuilder.EmptyContent);
            if (response.IsSuccessStatusCode == false) return string.Empty;

            var json = await response.Content.ReadAsStringAsync();
            if (json.IsNullOrEmpty()) return string.Empty;

            var result = JObject.Parse(json);
            if (result.ContainsKey(IdentityAuthenticationDefaultKeys.AccessToken) == false) return string.Empty;

            return result[IdentityAuthenticationDefaultKeys.AccessToken].ToString();
        }
    }
}
