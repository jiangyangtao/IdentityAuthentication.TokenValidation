using IdentityAuthentication.Model.Handlers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace IdentityAuthentication.TokenValidation
{
    public class IdentityAuthenticationOptions : AuthenticationSchemeOptions
    {
        public string Authority { get; set; }

        internal static Uri AuthorityUrl { set; get; }

        public new IdentityAuthenticationEvents Events
        {
            get { return (IdentityAuthenticationEvents)base.Events!; }
            set { base.Events = value; }
        }


        public override void Validate() { }

        public override void Validate(string scheme) => Validate();

        public new string? ClaimsIssuer { get; }


        public new Type? EventsType { get; }


        public new string? ForwardDefault { get; }


        public new string? ForwardAuthenticate { get; }


        public new string? ForwardChallenge { get; }


        public new string? ForwardForbid { get; }


        public new string? ForwardSignIn { get; }


        public new string? ForwardSignOut { get; }


        public new Func<HttpContext, string?>? ForwardDefaultSelector { get; }

        public Uri GetAuthorityUri()
        {
            if (string.IsNullOrEmpty(Authority)) throw new NullReferenceException($"{nameof(Authority)} is null or empty");

            return new Uri(Authority);
        }
    }
}
