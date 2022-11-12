using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.TokenValidation.Abstractions;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAuthentication.TokenValidation.Providers
{
    internal class ReferenceTokenProvider : ITokenProvider
    {
        private readonly ITokenValidateService _tokenValidateService;

        public ReferenceTokenProvider(ITokenValidateServiceFactory tokenValidateService)
        {
            _tokenValidateService = tokenValidateService.CreateTokenValidateService();
        }

        public TokenType TokenType => TokenType.Reference;

        public async Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            return await _tokenValidateService.ValidateTokenAsync(token);
        }
    }
}
