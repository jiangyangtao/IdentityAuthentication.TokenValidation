using IdentityAuthentication.TokenValidation.Enums;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface ITokenRefreshProvider
    {
        ConnectionType ConnectionType { get; }

        Task<string> RefreshTokenAsync(string accessToken, string refreshToken);
    }
}
