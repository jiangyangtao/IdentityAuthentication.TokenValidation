﻿using Microsoft.IdentityModel.Tokens;
using System.Net.Mime;
using System.Text;

namespace IdentityAuthentication.TokenValidation
{
    internal class TokenBuilder
    {
        public static StringContent EmptyContent => new(string.Empty, Encoding.UTF8, MediaTypeNames.Application.Json);

        public static TokenValidationResult FailTokenResult = new() { IsValid = false, };
    }
}