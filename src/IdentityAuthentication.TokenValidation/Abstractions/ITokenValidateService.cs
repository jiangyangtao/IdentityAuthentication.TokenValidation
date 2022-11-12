using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface ITokenValidateService
    {
        Task<TokenValidationResult> ValidateTokenAsync(string token);

        string CommunicationProtocol { get; }
    }
}
