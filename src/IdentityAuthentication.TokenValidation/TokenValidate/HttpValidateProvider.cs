using IdentityAuthentication.Model;
using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Services;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.TokenValidate
{
    internal class HttpValidateProvider : BaseTokenValidate, ITokenValidateProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public HttpValidateProvider(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        public async Task<TokenValidationResult> TokenValidateAsync(string token)
        {
            var httpClient = _httpClientFactory.CreateClient();
            var url = TokenValidationConfiguration.AuthenticationEndpoints.AuthorizeEndpoint;

            httpClient.DefaultRequestHeaders.Add(HttpHeaderKeyDefaults.Authorization, token);
            var response = await httpClient.PostAsync(url, RefreshTokenService.EmptyContent);
            if (response.IsSuccessStatusCode == false) return FailTokenResult;

            var json = await response.Content.ReadAsStringAsync();
            if (json.IsNullOrEmpty()) return FailTokenResult;

            var result = await _refreshTokenService.BuildTokenSuccessResultAsync(json);
            return result;
        }
    }
}
