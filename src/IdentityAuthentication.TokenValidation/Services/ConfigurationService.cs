using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.Model.Extensions;
using Microsoft.Extensions.Configuration;
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
            TokenValidationConfiguration.AuthenticationEndpoints = _authenticationEndpointService.GetAuthenticationEndpointsAsync().Result;

            var configuration = GetAuthenticationConfigurationAsync().Result;
            TokenValidationConfiguration.AuthenticationConfiguration = configuration.AuthenticationConfiguration;
            TokenValidationConfiguration.AccessTokenConfiguration = configuration.AccessTokenConfiguration;
            TokenValidationConfiguration.RefreshTokenConfiguration = configuration.RefreshTokenConfiguration;
            TokenValidationConfiguration.SecretKeyConfiguration = new SecretKeyConfiguration
            {
                HmacSha256Key = configuration.SecretKeyConfiguration.HmacSha256Key,
                RsaDecryptPrivateKey = configuration.SecretKeyConfiguration.RsaDecryptPrivateKey,
                RsaSignaturePublicKey = configuration.SecretKeyConfiguration.RsaSignaturePublicKey
            };
        }


        private async Task<IdentityAuthenticationConfiguration> GetAuthenticationConfigurationAsync()
        {
            var endpoint = TokenValidationConfiguration.AuthenticationEndpoints.AutnenticationConfigurationEndpoint;
            var httpClient = _httpClientFactory.CreateClient();
            var response = await httpClient.GetAsync(endpoint);
            if (response.IsSuccessStatusCode == false) throw new HttpRequestException($"Failed to request {endpoint}.");

            var result = await response.Content.ReadAsStringAsync();
            if (result.IsNullOrEmpty()) throw new NullReferenceException($"{endpoint} the response result is empty.");

            var config = JsonConvert.DeserializeObject<IdentityAuthenticationConfiguration>(result);
            if (config == null) throw new NullReferenceException($"{endpoint} the response result deserialization failed.");


            return config;
        }
    }
}
