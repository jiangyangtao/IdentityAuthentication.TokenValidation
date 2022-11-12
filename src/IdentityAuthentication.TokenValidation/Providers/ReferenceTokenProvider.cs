﻿using IdentityAuthentication.Model.Configurations;
using IdentityAuthentication.TokenValidation.Abstractions;
using IdentityAuthentication.TokenValidation.Protos;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System.Net.Mime;
using System.Security.Claims;
using System.Text;

namespace IdentityAuthentication.TokenValidation.Providers
{
    internal class ReferenceTokenProvider : ITokenProvider
    {
        private readonly IHttpClientFactory _httpClientFactory;

        private readonly StringContent _httpContent;
        public readonly TokenProto.TokenProtoClient _tokenProtoClient;
        private readonly Model.TokenValidation _tokenValidation;
        private readonly TokenValidationResult _failTokenResult;

        public ReferenceTokenProvider(IHttpClientFactory httpClientFactory, TokenProto.TokenProtoClient tokenProtoClient)
        {
            _httpClientFactory = httpClientFactory;
            _tokenProtoClient = tokenProtoClient;

            _httpContent = new StringContent(string.Empty, Encoding.UTF8, MediaTypeNames.Application.Json);
            _tokenValidation = new Model.TokenValidation(IdentityAuthenticationConfiguration.AccessTokenConfiguration,
                IdentityAuthenticationConfiguration.RefreshTokenConfiguration,
                IdentityAuthenticationConfiguration.SecretKeyConfiguration,
                IdentityAuthenticationConfiguration.AuthenticationConfiguration);

            _failTokenResult = new TokenValidationResult { IsValid = false, };
        }

        public TokenType TokenType => TokenType.Reference;

        public async Task<TokenValidationResult> ValidateTokenAsync(string token)
        {
            if (IdentityAuthenticationConfiguration.AuthenticationConfiguration.EnableGrpcConnection)
                return await GrpcValidateTokenAsync(token);

            return await HttpValidateTokenAsync(token);
        }

        private async Task<TokenValidationResult> GrpcValidateTokenAsync(string token)
        {
            var r = await _tokenProtoClient.AuthorizeAsync(new TokenRequest { Token = token });
            if (r.Result == false) return new TokenValidationResult
            {
                IsValid = r.Result
            };

            return BuildTokenSuccessResult(r.Claims);
        }

        private async Task<TokenValidationResult> HttpValidateTokenAsync(string token)
        {
            var httpClient = _httpClientFactory.CreateClient();
            var url = IdentityAuthenticationConfiguration.AuthenticationEndpoints.AuthorizeEndpoint;

            httpClient.DefaultRequestHeaders.Add("Authorization", token);
            var response = await httpClient.PostAsync(url, _httpContent);
            if (response.IsSuccessStatusCode == false) return _failTokenResult;

            var result = await response.Content.ReadAsStringAsync();
            if (string.IsNullOrEmpty(result)) return _failTokenResult;

            return BuildTokenSuccessResult(result);
        }

        private TokenValidationResult BuildTokenSuccessResult(string json)
        {
            var obj = JObject.Parse(json);
            var claims = new List<Claim>();

            var grantType = string.Empty;
            var expiration = string.Empty;
            foreach (var item in obj)
            {
                var value = item.Value.ToString();
                if (item.Key.Equals(nameof(grantType), StringComparison.OrdinalIgnoreCase)) grantType = value;
                if (item.Key.Equals(ClaimTypes.Expiration, StringComparison.OrdinalIgnoreCase)) expiration = value;

                claims.Add(new Claim(item.Key, value));
            }

            var identity = new ClaimsIdentity(claims, grantType);
            var r = DateTime.TryParse(expiration, out DateTime expirationTime);
            if (r == false) expirationTime = DateTime.Now;

            return new TokenValidationResult
            {
                IsValid = true,
                ClaimsIdentity = identity,
                SecurityToken = _tokenValidation.GenerateAccessSecurityToken(claims.ToArray(), expirationTime.AddHours(-1), expirationTime),
            };
        }
    }
}