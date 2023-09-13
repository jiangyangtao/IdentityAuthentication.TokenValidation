using IdentityAuthentication.Application.Grpc.Provider;
using IdentityAuthentication.TokenValidation.Abstractions;

namespace IdentityAuthentication.TokenValidation.TokenRefresh
{
    internal class GrpcRefreshProvider : ITokenRefreshProvider
    {
        private readonly IGrpcProvider _grpcProvider;
        private readonly TokenGrpcProvider.TokenGrpcProviderClient _tokenGrpcProvider;

        public GrpcRefreshProvider(IGrpcProvider grpcProvider, TokenGrpcProvider.TokenGrpcProviderClient tokenGrpcProvider)
        {
            _grpcProvider = grpcProvider;
            _tokenGrpcProvider = tokenGrpcProvider;
        }

        public ConnectionType ConnectionType => ConnectionType.Grpc;

        public async Task<string> RefreshTokenAsync(string accessToken, string refreshToken)
        {
            try
            {
                var headers = _grpcProvider.BuildGrpcHeader(accessToken);
                var r = await _tokenGrpcProvider.RefreshAsync(new RefreshTokenRequest { RefreshToken = refreshToken }, headers);
                if (r.Result == false) return string.Empty;

                return r.AccessToken;
            }
            finally { }
        }
    }
}
