using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.Model.Enums;
using IdentityAuthentication.Model.Models;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace IdentityAuthentication.TokenValidation
{
    internal class AuthenticationConfigurationProvider : IAuthenticationConfigurationProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly TokenValidationOptions _validationOptions;

        public AuthenticationConfigurationProvider(
            IHttpClientFactory httpClientFactory,
            IOptions<TokenValidationOptions> tokenValidationOptions)
        {
            _httpClientFactory = httpClientFactory;
            _validationOptions = tokenValidationOptions.Value;
        }

        public AccessTokenConfiguration? AccessTokenConfiguration => IdentityAuthenticationConfiguration.AccessTokenConfiguration;

        public TokenBaseConfiguration? RefreshTokenConfiguration => IdentityAuthenticationConfiguration.RefreshTokenConfiguration;

        public RsaVerifySignatureConfiguration? RsaVerifySignatureConfiguration => IdentityAuthenticationConfiguration.RsaVerifySignatureConfiguration;

        public bool CanClientValidation
        {
            get
            {
                if (AuthenticationConfiguration.TokenType != TokenType.JWT) return false;
                if (IdentityAuthenticationConfiguration.RsaVerifySignatureConfiguration == null) return false;
                if (IdentityAuthenticationConfiguration.RsaVerifySignatureConfiguration.PublicKey.IsNullOrEmpty()) return false;

                return true;
            }
        }

        public AuthenticationBaseConfiguration AuthenticationConfiguration => IdentityAuthenticationConfiguration.AuthenticationConfiguration;

        private IdentityAuthenticationConfiguration IdentityAuthenticationConfiguration { set; get; }

        public IdentityAuthenticationEndpoints AuthenticationEndpoints { set; get; }


        public void Initialize() => InitializeAuthenticationConfigurationAsync().Wait();


        public Task InitializeAsync() => InitializeAuthenticationConfigurationAsync();

        private async Task<IdentityAuthenticationEndpoints> GetAuthenticationEndpointsAsync()
        {
            if (AuthenticationEndpoints != null) return AuthenticationEndpoints;

            var httpClient = _httpClientFactory.CreateClient();
            httpClient.BaseAddress = _validationOptions.AuthorityUrl;

            var response = await httpClient.GetAsync(IdentityAuthenticationEndpoints.DefaultConfigurationEndpoint);
            if (response.IsSuccessStatusCode == false) throw new HttpRequestException("Failed to request authentication endpoints.");

            var result = await response.Content.ReadAsStringAsync();
            if (result.IsNullOrEmpty()) throw new HttpRequestException("Authentication endpoints the response result is empty.");

            AuthenticationEndpoints = JsonConvert.DeserializeObject<IdentityAuthenticationEndpoints>(result);
            return AuthenticationEndpoints ?? throw new JsonException("Authentication endpoints the response result deserialization failed.");
        }

        private async Task InitializeAuthenticationConfigurationAsync()
        {
            if (IdentityAuthenticationConfiguration != null) return;

            var endpoint = await GetAuthenticationEndpointsAsync();
            var httpClient = _httpClientFactory.CreateClient();
            var response = await httpClient.GetAsync(endpoint.AuthenticationConfigurationEndpoint);
            if (response.IsSuccessStatusCode == false) throw new HttpRequestException($"Failed to request {endpoint}.");

            var result = await response.Content.ReadAsStringAsync();
            if (result.IsNullOrEmpty()) throw new HttpRequestException($"{endpoint} the response result is empty.");

            var configuration = JsonConvert.DeserializeObject<IdentityAuthenticationConfiguration>(result);
            IdentityAuthenticationConfiguration = configuration ?? throw new JsonException($"{endpoint} the response result deserialization failed.");
        }
    }
}
