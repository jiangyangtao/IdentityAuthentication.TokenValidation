using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Extensions;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace IdentityAuthentication.TokenValidation.Services
{
    internal class AuthenticationEndpointService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly TokenValidationOptions _validationOptions;

        public AuthenticationEndpointService(IHttpClientFactory httpClientFactory, IOptions<TokenValidationOptions> tokenValidationOptions)
        {
            _httpClientFactory = httpClientFactory;
            _validationOptions = tokenValidationOptions.Value;
        }

        public async Task<AuthenticationEndpoints> GetAuthenticationEndpointsAsync()
        {
            var httpClient = _httpClientFactory.CreateClient();
            httpClient.BaseAddress = _validationOptions.AuthorityUrl;

            var response = await httpClient.GetAsync(AuthenticationEndpoints.DefaultConfigurationEndpoint);
            if (response.IsSuccessStatusCode == false) throw new HttpRequestException("Failed to request authentication endpoints.");

            var result = await response.Content.ReadAsStringAsync();
            if (result.IsNullOrEmpty()) throw new NullReferenceException("Authentication endpoints the response result is empty.");

            var endpoints = JsonConvert.DeserializeObject<AuthenticationEndpoints>(result);
            if (endpoints == null) throw new NullReferenceException("Authentication endpoints the response result deserialization failed.");

            return endpoints;
        }
    }
}
