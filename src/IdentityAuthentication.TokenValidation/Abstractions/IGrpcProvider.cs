using Grpc.Core;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface IGrpcProvider
    {
        Metadata BuildGrpcHeader(string token = "");
    }
}
