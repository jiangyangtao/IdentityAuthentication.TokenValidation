using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.Model.Extensions;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;

namespace IdentityAuthentication.TokenValidation.Services
{
    internal class AuthenticationConfigurationService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly TokenValidationOptions _validationOptions;


        public AuthenticationConfigurationService(
            IHttpClientFactory httpClientFactory,
            IOptions<TokenValidationOptions> tokenValidationOptions)
        {
            _httpClientFactory = httpClientFactory;
            _validationOptions = tokenValidationOptions.Value;
        }

        public void InitializationConfiguration()
        {
            try
            {
                TokenValidationConfiguration.AuthenticationEndpoints = GetAuthenticationEndpointsAsync().Result;

                var configuration = GetAuthenticationConfigurationAsync().Result;
                SetConfiguration(configuration);
            }
            catch (Exception) { }
        }

        public async Task InitializationConfigurationaAsync()
        {
            if (TokenValidationConfiguration.HasConfigValue == false)
            {
                TokenValidationConfiguration.AuthenticationEndpoints = await GetAuthenticationEndpointsAsync();
                var configuration = await GetAuthenticationConfigurationAsync();
                SetConfiguration(configuration);
            }
        }

        private async Task<IdentityAuthenticationEndpoints> GetAuthenticationEndpointsAsync()
        {
            var httpClient = _httpClientFactory.CreateClient();
            httpClient.BaseAddress = _validationOptions.AuthorityUrl;

            var response = await httpClient.GetAsync(IdentityAuthenticationEndpoints.DefaultConfigurationEndpoint);
            if (response.IsSuccessStatusCode == false) throw new HttpRequestException("Failed to request authentication endpoints.");

            var result = await response.Content.ReadAsStringAsync();
            if (result.IsNullOrEmpty()) throw new NullReferenceException("Authentication endpoints the response result is empty.");

            var endpoints = JsonConvert.DeserializeObject<IdentityAuthenticationEndpoints>(result);
            return endpoints ?? throw new NullReferenceException("Authentication endpoints the response result deserialization failed.");
        }

        private static void SetConfiguration(IdentityAuthenticationConfiguration configuration)
        {
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
            var endpoint = TokenValidationConfiguration.AuthenticationEndpoints.AuthenticationConfigurationEndpoint;
            var httpClient = _httpClientFactory.CreateClient();
            var response = await httpClient.GetAsync(endpoint);
            if (response.IsSuccessStatusCode == false) throw new HttpRequestException($"Failed to request {endpoint}.");

            var result = await response.Content.ReadAsStringAsync();
            if (result.IsNullOrEmpty()) throw new NullReferenceException($"{endpoint} the response result is empty.");

            var config = JsonConvert.DeserializeObject<IdentityAuthenticationConfiguration>(result);
            return config ?? throw new NullReferenceException($"{endpoint} the response result deserialization failed.");
        }
    }
}
