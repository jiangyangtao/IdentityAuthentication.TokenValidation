using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Protos;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation.Services
{
    internal class GrpcTokenValidateService : ITokenValidateService
    {
        public readonly TokenProto.TokenProtoClient _tokenProtoClient;

        public GrpcTokenValidateService(TokenProto.TokenProtoClient tokenProtoClient)
        {
            _tokenProtoClient = tokenProtoClient;
        }

        public string CommunicationProtocol => "grpc";

        public Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            throw new NotImplementedException();
        }
    }
}
