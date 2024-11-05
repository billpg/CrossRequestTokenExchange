using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;

namespace LibHashBackAuth
{
    public class GeneratedAuth
    {
        public string AuthHeader { get; }
        public string VerificationHash { get; }
        public Guid VerificationId { get; }

        public GeneratedAuth(Guid verificationId, string authHeader, string verificationHash)
        {
            this.VerificationId = verificationId;
            this.AuthHeader = authHeader;
            this.VerificationHash = verificationHash;
        }
    }

    public class GeneratorHashBackAuth
    {
        /// <summary>
        /// Clock service delegate type.
        /// Callers might reconfigure the clock source instead of the
        /// machine's clock.
        /// </summary>
        /// <returns>Returns "now" in 1970/Unix notation.</returns>
        public delegate long ClockServiceFn();

        /// <summary>
        /// Verify URL generation delegate type.
        /// </summary>
        /// <param name="id">The ID that will be embedded in the URL.</param>
        /// <returns>Completed Verify URL.</returns>
        public delegate Uri VerifyUrlServiceFn(Guid id);

        /// <summary>
        /// Gets or sets the value to use as the Host property. Should match
        /// the remote server's Host name. (If not set, must use the 
        /// version of GenerateAuthHeader that take a host parameter.)
        /// </summary>
        public string? Host { get; set; }
            = null;

        /// <summary>
        /// The clock service that will generate the timestamp to use
        /// as the JSON's "Now" property. Defaults to the machine's
        /// clock. The caller may replace it.
        /// </summary>
        public ClockServiceFn ClockService { get; set; }
            = DefaultClockService;

        /// <summary>
        /// Default clock provider.
        /// </summary>
        /// <returns>The clock in 1970/Unix notation.</returns>
        private static long DefaultClockService()
            => InternalTools.NowInUnixTime(); 
        
        /// <summary>
        /// Gets or sets the number of PBKDF2 rounds to use when
        /// generating the verification hash.
        /// </summary>
        public int Rounds { get; set; }
            = 1;

        /// <summary>
        /// Service that will generate verify URLs. Must be set before
        /// use. Note that extension function SetVerifyByQueryString
        /// is recommended.
        /// </summary>
        public VerifyUrlServiceFn VerifyUrlService =
            id => throw new NotImplementedException();

        /// <summary>
        /// Generate a HashBack authentication header with a random ID
        /// and the value of the Host property, which must be set prior to use.
        /// </summary>
        /// <returns>The authentication request.</returns>
        public GeneratedAuth GenerateAuthHeader()
            => GenerateAuthHeader(Guid.NewGuid());

        /// <summary>
        /// Generate a HashBack authentication header with the verification
        /// hash required. Will use the value of the Host roperty to generate
        /// the underlying JSON.
        /// </summary>
        /// <param name="id">ID of request. Will be used in verification URL.</param>
        /// <returns>Generated request details.</returns>
        public GeneratedAuth GenerateAuthHeader(Guid id)
        {
            /* Check this.Host is set. */
            if (this.Host == null)
                throw new ApplicationException(
                    "Called GenerateAuthHeader without setting Host property.");

            /* Call version that takes a Host parameter. */
            return GenerateAuthHeader(id, this.Host);
        }

        /// <summary>
        /// Generate a HashBack authentication header with the supplied host
        /// and a random ID.
        /// </summary>
        /// <param name="host">Name of remote host to include in request.</param>
        /// <returns>Generated request details.</returns>
        public GeneratedAuth GenerateAuthHeader(string host)
            => GenerateAuthHeader(Guid.NewGuid(), host);

        /// <summary>
        /// Generate a HashBack authentication header with the supplied host
        /// and ID.
        /// </summary>
        /// <param name="id">Supplied request ID.</param>
        /// <param name="host">Name of remote host to include in request.</param>
        /// <returns>Generated request details.</returns>
        public GeneratedAuth GenerateAuthHeader(Guid id, string host)
        {
            /* Start a JSON object that will become the header. */
            var authAsJson = new JObject
            {
                ["Version"] = InternalTools.versionBillpg40Draft,
                ["Host"] = host,
                ["Now"] = this.ClockService(),
                ["Unus"] = InternalTools.GenerateUnus(),
                ["Rounds"] = this.Rounds,
                ["Verify"] = this.VerifyUrlService(id)
            };

            /* Turn the JSON into a string, then bytes, then base-64. */
            var authAsString = authAsJson.ToString();
            var authAsBytes = Encoding.UTF8.GetBytes(authAsString);
            var authAsBase64 = Convert.ToBase64String(authAsBytes);

            /* Hash the bytes. */
            var verificationHash = InternalTools.CalculateHash(authAsBytes, this.Rounds);

            /* Return the auth header and the verification hash. */
            return new GeneratedAuth(id, "HashBack " + authAsBase64, verificationHash);
        } 
    }

    public static class GeneratorExtensions
    {
        public static void SetVerifyByQueryString(this GeneratorHashBackAuth gen, string baseUrl, string name)
        {
            /* Set the verify-url-service handler. */
            gen.VerifyUrlService = InternalService;
            Uri InternalService(Guid id)
            {
                /* Call the helper to set the query string parameter. */
                string updatedUrl = QueryHelpers.AddQueryString(
                    baseUrl,
                    name,
                    id.ToString().ToUpperInvariant());

                /* Return in a Uri object. */
                return new Uri(updatedUrl);
            }
        }

        public static void SetVerifyByFileInFolder(this GeneratorHashBackAuth gen, string folderUrl, string fileExt)
        {
            /* Parse the folder URL. */
            Uri parsedFolderUrl = new Uri(folderUrl);

            /* If needed, regenerate the URL object to add a slash to the end of the path. */
            if (parsedFolderUrl.LocalPath.EndsWith("/") == false)
            {
                var builder = new UriBuilder(parsedFolderUrl);
                builder.Path += "/";
                parsedFolderUrl = builder.Uri;
            }

            /* If needed, add a dot to the file-ext. */
            if (fileExt.StartsWith(".") == false)
                fileExt = "." + fileExt;

            /* Set the verify-url-service handler. */
            gen.VerifyUrlService = InternalService;
            Uri InternalService(Guid id)
                => new Uri(parsedFolderUrl, $"{id.ToString().ToUpperInvariant()}{fileExt}");
        }
    }
}
