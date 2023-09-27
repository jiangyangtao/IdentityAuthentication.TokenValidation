using IdentityAuthentication.Model.Extensions;
using IdentityAuthentication.Model.Handles;
using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Enums;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;

namespace IdentityAuthentication.TokenValidation
{
    internal class HttpAuthenticationProvider : IAuthenticationProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IAuthenticationConfigurationProvider _configurationProvider;

        public HttpAuthenticationProvider(
            IHttpClientFactory httpClientFactory,
            IAuthenticationConfigurationProvider configurationProvider)
        {
            _httpClientFactory = httpClientFactory;
            _configurationProvider = configurationProvider;
        }

        public ConnectionType ConnectionType => ConnectionType.Http;

        public bool IsRsaValidate => false;

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
            if (result == null) return string.Empty;
            if (result.ContainsKey(IdentityAuthenticationDefaultKeys.AccessToken) == false) return string.Empty;

            return result[IdentityAuthenticationDefaultKeys.AccessToken].ToString();
        }

        public async Task<TokenValidationResult> TokenValidateAsync(string token)
        {
            var httpClient = _httpClientFactory.CreateClient();
            var url = _configurationProvider.AuthenticationEndpoints.AuthorizeEndpoint;

            httpClient.DefaultRequestHeaders.Add(IdentityAuthenticationDefaultKeys.Authorization, token);
            var response = await httpClient.PostAsync(url, TokenBuilder.EmptyContent);
            if (response.IsSuccessStatusCode == false) return Model.TokenValidation.FailedTokenValidationResult;

            var json = await response.Content.ReadAsStringAsync();
            if (json.IsNullOrEmpty()) return Model.TokenValidation.FailedTokenValidationResult;

            var result = TokenBuilder.BuildTokenSuccessResultAsync(json);
            return result;
        }
    }
}
