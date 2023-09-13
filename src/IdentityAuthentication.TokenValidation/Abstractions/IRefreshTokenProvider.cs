using Grpc.Core;
using System.Security.Claims;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface IRefreshTokenProvider
    {
        Metadata BuildGrpcHeader(string token = "");

        Task RefreshTokenAsync(IEnumerable<Claim> claims);

        Task RefreshTokenAsync(string expiration);
    }
}
