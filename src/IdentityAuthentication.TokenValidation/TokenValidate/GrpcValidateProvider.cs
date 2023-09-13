using IdentityAuthentication.Application.Grpc.Provider;
using IdentityAuthentication.Model.Extensions;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.TokenValidate
{
    internal class GrpcValidateProvider : ITokenValidateProvider
    {
        private readonly IGrpcProvider _grpcProvider;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ITokenResultProvider _tokenResultProvider;
        private readonly TokenGrpcProvider.TokenGrpcProviderClient _tokenGrpcProvider;

        public GrpcValidateProvider(
            IGrpcProvider grpcProvider,
            IHttpContextAccessor httpContextAccessor,
            ITokenResultProvider tokenResultProvider,
            TokenGrpcProvider.TokenGrpcProviderClient tokenGrpcProvider)
        {
            _grpcProvider = grpcProvider;
            _httpContextAccessor = httpContextAccessor;    
            _tokenResultProvider = tokenResultProvider;
            _tokenGrpcProvider = tokenGrpcProvider;
        }

        private string AccessToken => _httpContextAccessor.HttpContext?.Request.Headers.GetAuthorization();

        public async Task<TokenValidationResult> TokenValidateAsync(string token)
        {
            try
            {
                var headers = _grpcProvider.BuildGrpcHeader(AccessToken);
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
    }
}
