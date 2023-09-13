using IdentityAuthentication.Model;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.TokenValidate
{
    internal class HttpValidateProvider : ITokenValidateProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ITokenResultProvider _tokenResultProvider;

        public HttpValidateProvider(
            IHttpClientFactory httpClientFactory,
            ITokenResultProvider tokenResultProvider)
        {
            _httpClientFactory = httpClientFactory;
            _tokenResultProvider = tokenResultProvider;
        }

        public ConnectionType ConnectionType => ConnectionType.Http;

        public async Task<TokenValidationResult> TokenValidateAsync(string token)
        {
            var httpClient = _httpClientFactory.CreateClient();
            var url = TokenValidationConfiguration.AuthenticationEndpoints.AuthorizeEndpoint;

            httpClient.DefaultRequestHeaders.Add(HttpHeaderKeyDefaults.Authorization, token);
            var response = await httpClient.PostAsync(url, TokenBuilder.EmptyContent);
            if (response.IsSuccessStatusCode == false) return TokenBuilder.FailTokenResult;

            var json = await response.Content.ReadAsStringAsync();
            if (json.IsNullOrEmpty()) return TokenBuilder.FailTokenResult;

            var result = await _tokenResultProvider.BuildTokenSuccessResultAsync(json);
            return result;
        }
    }
}
