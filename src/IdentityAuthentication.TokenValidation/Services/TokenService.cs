using IdentityAuthentication.TokenValidation.Protos;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation.Services
{
    internal class TokenService
    {
        public readonly TokenProto.TokenProtoClient _tokenProtoClient;

        public TokenService(TokenProto.TokenProtoClient tokenProtoClient)
        {
            _tokenProtoClient = tokenProtoClient;
        }

        public Task<ClaimsIdentity> AuthorizeAsync()
        {
            throw new Exception();
        }
    }
}
