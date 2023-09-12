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


    }
}
