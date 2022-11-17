using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Extensions;
using Newtonsoft.Json;

namespace IdentityAuthentication.TokenValidation.Services
{
    internal class AuthenticationEndpointService
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public AuthenticationEndpointService(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        public async Task<AuthenticationEndpoints> GetAuthenticationEndpointsAsync()
        {
            var httpClient = _httpClientFactory.CreateClient();
            httpClient.BaseAddress = IdentityAuthenticationOptions.AuthorityUrl;

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
