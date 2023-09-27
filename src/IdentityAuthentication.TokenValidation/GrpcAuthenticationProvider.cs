using Grpc.Core;
using IdentityAuthentication.Application.Grpc.Provider;
using IdentityAuthentication.Model.Extensions;
using IdentityAuthentication.Model.Handles;
using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Enums;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation
{
    internal class GrpcAuthenticationProvider : IAuthenticationProvider
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly TokenGrpcProvider.TokenGrpcProviderClient _tokenGrpcProvider;

        public GrpcAuthenticationProvider(
            IHttpContextAccessor httpContextAccessor,
            TokenGrpcProvider.TokenGrpcProviderClient tokenGrpcProvider)
        {
            _httpContextAccessor = httpContextAccessor;
            _tokenGrpcProvider = tokenGrpcProvider;
        }

        public ConnectionType ConnectionType => ConnectionType.Grpc;

        private string AccessToken => _httpContextAccessor.HttpContext?.Request.Headers.GetAuthorization();

        public bool IsRsaValidate => false;

        private Metadata BuildGrpcHeader(string token = "") => new() { { IdentityAuthenticationDefaultKeys.Authorization, token.IsNullOrEmpty() ? AccessToken : token } };

        public async Task<string> RefreshTokenAsync(string accessToken, string refreshToken)
        {
            try
            {
                var headers = BuildGrpcHeader(accessToken);
                var r = await _tokenGrpcProvider.RefreshAsync(new RefreshTokenRequest { RefreshToken = refreshToken }, headers);
                if (r.Result == false) return string.Empty;

                return r.AccessToken;
            }
            finally { }
        }

        public async Task<TokenValidationResult> TokenValidateAsync(string token)
        {
            try
            {
                var headers = BuildGrpcHeader(AccessToken);
                var r = await _tokenGrpcProvider.AuthorizeAsync(new AccessTokenRequest { AccessToken = token }, headers);
                if (r.Result == false) return new TokenValidationResult
                {
                    IsValid = r.Result
                };
                return TokenBuilder.BuildTokenSuccessResultAsync(r.Claims);
            }
            catch
            {
                return new TokenValidationResult { IsValid = false };
            }
        }
    }
}
