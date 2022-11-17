using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.Model.Extensions;
using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Protos;
using IdentityAuthentication.TokenValidation.Services;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.Providers
{
    internal class ReferenceTokenProvider : ITokenProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly TokenProto.TokenProtoClient _tokenProtoClient;
        private readonly TokenValidationResult _failTokenResult;
        private readonly RefreshTokenService _refreshTokenService;

        public ReferenceTokenProvider(
            IHttpClientFactory httpClientFactory,
            TokenProto.TokenProtoClient tokenProtoClient,
            RefreshTokenService refreshTokenService)
        {
            _httpClientFactory = httpClientFactory;
            _tokenProtoClient = tokenProtoClient;
            _refreshTokenService = refreshTokenService;
            _failTokenResult = new TokenValidationResult { IsValid = false, };
        }

        public TokenType TokenType => TokenType.Reference;

        public async Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            if (TokenValidationConfiguration.AuthenticationConfiguration.EnableGrpcConnection)
                return await GrpcValidateTokenAsync(token);

            return await HttpValidateTokenAsync(token);
        }

        private async Task<TokenValidationResult> GrpcValidateTokenAsync(string token)
        {
            try
            {
                var headers = _refreshTokenService.BuildGrpcHeader();
                var r = await _tokenProtoClient.AuthorizeAsync(new TokenRequest { Token = token }, headers);
                if (r.Result == false) return new TokenValidationResult
                {
                    IsValid = r.Result
                };
                return await _refreshTokenService.BuildTokenSuccessResultAsync(r.Claims);
            }
            catch
            {
                return new TokenValidationResult { IsValid = false };
            }
        }

        private async Task<TokenValidationResult> HttpValidateTokenAsync(string token)
        {
            var httpClient = _httpClientFactory.CreateClient();
            var url = TokenValidationConfiguration.AuthenticationEndpoints.AuthorizeEndpoint;

            httpClient.DefaultRequestHeaders.Add(HttpHeaderKeyDefaults.Authorization, token);
            var response = await httpClient.PostAsync(url, RefreshTokenService.EmptyContent);
            if (response.IsSuccessStatusCode == false) return _failTokenResult;

            var json = await response.Content.ReadAsStringAsync();
            if (json.IsNullOrEmpty()) return _failTokenResult;

            var result = await _refreshTokenService.BuildTokenSuccessResultAsync(json);
            return result;
        }
    }
}
