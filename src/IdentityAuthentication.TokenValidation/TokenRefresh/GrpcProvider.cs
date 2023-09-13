using Grpc.Core;
using IdentityAuthentication.Model;
using IdentityAuthentication.Model.Extensions;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.AspNetCore.Http;

namespace IdentityAuthentication.TokenValidation.TokenRefresh
{
    internal class GrpcProvider : IGrpcProvider
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public GrpcProvider(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }

        private string AccessToken => _httpContextAccessor.HttpContext?.Request.Headers.GetAuthorization();

        public Metadata BuildGrpcHeader(string token = "") => new() { { HttpHeaderKeyDefaults.Authorization, token.IsNullOrEmpty() ? AccessToken : token } };
    }
}
