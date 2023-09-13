using IdentityAuthentication.Application.Grpc.Provider;
using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.Model.Extensions;
using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.TokenRefresh;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.TokenProviders
{
    internal class ReferenceTokenProvider : ITokenProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ITokenResultProvider _tokenResultProvider;
        private readonly TokenGrpcProvider.TokenGrpcProviderClient _tokenGrpcProvider;
        private readonly TokenValidationResult _failTokenResult;
        private readonly RefreshTokenProvider _refreshTokenService;

        public ReferenceTokenProvider(
            IHttpClientFactory httpClientFactory,
            TokenGrpcProvider.TokenGrpcProviderClient okenGrpcProvider,
            RefreshTokenProvider refreshTokenService,
            ITokenResultProvider tokenResultProvider)
        {
            _httpClientFactory = httpClientFactory;
            _tokenGrpcProvider = okenGrpcProvider;
            _refreshTokenService = refreshTokenService;
            _failTokenResult = new TokenValidationResult { IsValid = false, };
            _tokenResultProvider = tokenResultProvider;
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
                var r = await _tokenGrpcProvider.AuthorizeAsync(new AccessTokenRequest { AccessToken = token }, headers);
                if (r.Result == false) return new TokenValidationResult
                {
                    IsValid = r.Result
                };
                return await _tokenResultProvider.BuildTokenSuccessResultAsync(r.Claims);
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
            var response = await httpClient.PostAsync(url, RefreshTokenProvider.EmptyContent);
            if (response.IsSuccessStatusCode == false) return _failTokenResult;

            var json = await response.Content.ReadAsStringAsync();
            if (json.IsNullOrEmpty()) return _failTokenResult;

            var result = await _tokenResultProvider.BuildTokenSuccessResultAsync(json);
            return result;
        }
    }
}
