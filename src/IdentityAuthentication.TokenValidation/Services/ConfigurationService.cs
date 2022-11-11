using IdentityAuthentication.Model.Configurations;
using Newtonsoft.Json;

namespace IdentityAuthentication.TokenValidation.Services
{
    internal class ConfigurationService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly AuthenticationEndpointService _authenticationEndpointService;

        public ConfigurationService(IHttpClientFactory httpClientFactory, AuthenticationEndpointService authenticationEndpointService)
        {
            _httpClientFactory = httpClientFactory;
            _authenticationEndpointService = authenticationEndpointService;
        }

        public void InitializationConfiguration()
        {
            IdentityAuthenticationConfiguration.AuthenticationEndpoints = _authenticationEndpointService.GetAuthenticationEndpointsAsync().Result;
            IdentityAuthenticationConfiguration.AuthenticationConfiguration = GetAuthenticationConfigurationAsync().Result;
            IdentityAuthenticationConfiguration.AccessTokenConfiguration = GetAccessTokenConfigurationAsync().Result;
            IdentityAuthenticationConfiguration.RefreshTokenConfiguration = GetRefreshTokenConfigurationAsync().Result;
            IdentityAuthenticationConfiguration.SecretKeyConfiguration = GetSecretKeyConfigurationAsync().Result;
        }


        private async Task<AuthenticationConfiguration> GetAuthenticationConfigurationAsync()
        {
            var endpoint = IdentityAuthenticationConfiguration.AuthenticationEndpoints.AutnenticationConfigurationEndpoint;
            return await GetConfigurationAsync<AuthenticationConfiguration>(endpoint);
        }

        private async Task<AccessTokenConfiguration> GetAccessTokenConfigurationAsync()
        {
            var endpoint = IdentityAuthenticationConfiguration.AuthenticationEndpoints.AccessTokenConfigurationEndpoint;
            return await GetConfigurationAsync<AccessTokenConfiguration>(endpoint);
        }

        private async Task<RefreshTokenConfiguration> GetRefreshTokenConfigurationAsync()
        {
            var endpoint = IdentityAuthenticationConfiguration.AuthenticationEndpoints.RefreshTokenConfigurationEndpoint;
            return await GetConfigurationAsync<RefreshTokenConfiguration>(endpoint);
        }

        private async Task<SecretKeyConfigurationBase> GetSecretKeyConfigurationAsync()
        {
            var endpoint = IdentityAuthenticationConfiguration.AuthenticationEndpoints.SecretKeyConfigurationEndpoint;
            return await GetConfigurationAsync<SecretKeyConfigurationBase>(endpoint);
        }

        private async Task<TConfiguration> GetConfigurationAsync<TConfiguration>(string endpoint) where TConfiguration : class
        {
            if (string.IsNullOrEmpty(endpoint)) throw new ArgumentNullException(nameof(endpoint));

            var httpClient = _httpClientFactory.CreateClient();
            var response = await httpClient.GetAsync(endpoint);
            if (response.IsSuccessStatusCode == false) throw new HttpRequestException($"Failed to request {endpoint}.");

            var result = await response.Content.ReadAsStringAsync();
            if (string.IsNullOrEmpty(result)) throw new NullReferenceException($"{endpoint} the response result is empty.");

            var config = JsonConvert.DeserializeObject<TConfiguration>(result);
            if (config == null) throw new NullReferenceException($"{endpoint} the response result deserialization failed.");

            return config;
        }
    }
}
