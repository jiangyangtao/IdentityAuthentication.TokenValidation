﻿using IdentityAuthentication.Model.Configurations;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAuthentication.TokenValidation.Abstractions
{
    internal interface ITokenProvider
    {
        TokenType TokenType { get; }

        bool IsEncrypt { get; }

        Task<TokenValidationResult> ValidateTokenAsync(string token);
    }
}
