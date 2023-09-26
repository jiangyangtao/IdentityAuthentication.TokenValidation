using IdentityAuthentication.Model.Handles;
using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Enums;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.TokenValidate
{
    internal class HttpAuthenticationProvider : IServerValidateProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ITokenResultProvider _tokenResultProvider;
        private readonly IAuthenticationConfigurationProvider _configurationProvider;

        public HttpAuthenticationProvider(
            IHttpClientFactory httpClientFactory,
            ITokenResultProvider tokenResultProvider,
            IAuthenticationConfigurationProvider configurationProvider)
        {
            _httpClientFactory = httpClientFactory;
            _tokenResultProvider = tokenResultProvider;
            _configurationProvider = configurationProvider;
        }

        public ConnectionType ConnectionType => ConnectionType.Http;

        public async Task<TokenValidationResult> TokenValidateAsync(string token)
        {
            var httpClient = _httpClientFactory.CreateClient();
            var url = _configurationProvider.AuthenticationEndpoints.AuthorizeEndpoint;

            httpClient.DefaultRequestHeaders.Add(IdentityAuthenticationDefaultKeys.Authorization, token);
            var response = await httpClient.PostAsync(url, TokenBuilder.EmptyContent);
            if (response.IsSuccessStatusCode == false) return TokenBuilder.FailTokenResult;

            var json = await response.Content.ReadAsStringAsync();
            if (json.IsNullOrEmpty()) return TokenBuilder.FailTokenResult;

            var result = await _tokenResultProvider.BuildTokenSuccessResultAsync(json);
            return result;
        }
    }
}
