﻿using Newtonsoft.Json.Linq;

namespace billpg.HashBackCore
{
    /// <summary>
    /// A single request from a Caller to an Issuer.
    /// </summary>
    public class CallerRequest
    {
        public const string VERSION_3_0 = "HASHBACK-PUBLIC-DRAFT-3-0";
        public const string VERSION_3_1 = "HASHBACK-PUBLIC-DRAFT-3-1-UNDERDEV";

        public string Version { get; } = "";
        public string TypeOfResponse { get; } = "";
        public string IssuerUrl { get; } = "";
        public long Now { get; }
        public string Unus { get; } = "";
        public int Rounds { get; }
        public string VerifyUrl { get; } = "";

        private CallerRequest(
            string version, string typeOfResponse,
            string issuerUrl,long now,
            string unus, int rounds, 
            string verifyUrl )
        {
            this.Version = version;
            this.TypeOfResponse = typeOfResponse;
            this.IssuerUrl = issuerUrl;
            this.Now = now;
            this.Unus = unus;
            this.Rounds = rounds;
            this.VerifyUrl = verifyUrl;
        }

        private const string propNameHashBack = "HashBack";
        private const string propNameTypeOfResponse = "TypeOfResponse";
        private const string propNameIssuerUrl = "IssuerUrl";
        private const string propNameNow = "Now";
        private const string propNameUnus = "Unus";
        private const string propNameRounds = "Rounds";
        private const string propNameVerifyUrl = "VerifyUrl";

        public static CallerRequest Parse(JObject json)
        {
            /* Utility functions to load a required property. */
            string LoadRequiredString(string propName)
            {
                string? value = json[propName]?.Value<string>();
                if (value == null)
                    throw BadRequestException.Required(propName);
                return value;
            }
            long LoadRequiredLong(string propName)
            {
                long? value = json[propName]?.Value<long>();
                if (value.HasValue == false)
                    throw BadRequestException.Required(propName);
                return value.Value;
            }
            int LoadRequiredInt(string propName)
            {
                int? value = json[propName]?.Value<int>();
                if (value.HasValue == false)
                    throw BadRequestException.Required(propName);
                return value.Value;
            }

            /* Load version and check value. */
            string version = LoadRequiredString(propNameHashBack);
            if (version != VERSION_3_0 && version != VERSION_3_1)
                throw BadRequestException.BadVersion();

            /* Load the remaining properties. The range 
             * of acceptable values will be checked by caller. */
            string typeOfResponse = LoadRequiredString(propNameTypeOfResponse);
            string issuerUrl = LoadRequiredString(propNameIssuerUrl);
            long now = LoadRequiredLong(propNameNow);
            string unus = LoadRequiredString(propNameUnus);
            int rounds = LoadRequiredInt(propNameRounds);
            string verifyUrl = LoadRequiredString(propNameVerifyUrl);

            /* Return completed object. */
            return new CallerRequest(
                version, typeOfResponse, issuerUrl, now, unus, rounds, verifyUrl);
        }

    }
}