using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mime;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation.Services
{
    internal class HttpTokenValidateService : ITokenValidateService
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly StringContent httpContent;

        public HttpTokenValidateService(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
            httpContent = new StringContent(string.Empty, Encoding.UTF8, MediaTypeNames.Application.Json);
        }

        public string CommunicationProtocol => "http";

        public async Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            var httpClient = _httpClientFactory.CreateClient();
            var url = IdentityAuthenticationConfiguration.AuthenticationEndpoints.AuthorizeEndpoint;

            httpClient.DefaultRequestHeaders.Add("Authorization", token);
            var response = await httpClient.PostAsync(url, httpContent);

            throw new NotImplementedException();
        }
    }
}
