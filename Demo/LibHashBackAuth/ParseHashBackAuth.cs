
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LibHashBackAuth
{
    public enum ParseState
    {
        NotValid,
        NeedsVerification
    }

    public class ParseResult
    {
        public readonly ParseState State;
        public readonly string? ErrorText;
        public readonly Uri? VerifyUrl;
        public readonly string? ExpectedHash;

        public ParseResult(ParseState state, string? errorText, Uri? verifyUrl, string? expectedHash)
        {
            this.State = state;
            this.ErrorText = errorText;
            this.VerifyUrl = verifyUrl;
            this.ExpectedHash = expectedHash;
        }

        internal static ParseResult NotValid(string errorText)
            => new ParseResult(ParseState.NotValid, errorText, null, null);

        internal static ParseResult Verification(Uri verifyAsUrl, string expectedHash)
            => new ParseResult(ParseState.NeedsVerification, null, verifyAsUrl, expectedHash);
    }

    public class ParseHashBackAuth
    {
        public Func<string,string?> IsHostValid = null!;
        public Func<long,string?> IsNowValid = null!;
        public Func<int,string?> IsRoundsValid = null!;
        public Func<Uri,string?> IsVerifyValid = null!;
        private readonly UnusTracker unusTracker = new UnusTracker();

        public void SetRequiredHost(string requiredHost)
        {
            this.IsHostValid = IsMatch;
            string? IsMatch(string suppliedHost)
                => requiredHost == suppliedHost 
                    ? null
                    : $"Host property must be \"{requiredHost}\".";
        }

        public void SetClockService(Func<long> clockService, int allowSeconds)
        {
            this.IsNowValid = IsValid;
            string? IsValid(long suppliedNow)
            {
                /* Read the clock. */
                long actualNow = clockService();

                /* Is it too far in either direction? */
                if (suppliedNow < actualNow - allowSeconds)
                    return "Supplied Now property is too far in the past.";
                if (suppliedNow > actualNow + allowSeconds)
                    return "Supplied Now property is too far in the future.";

                /* Otherwise, it is valid. */
                return null;
            }
        }

        public void SetRoundsLimit(int minRounds, int maxRounds)
        {
            this.IsRoundsValid = IsBetweenRange;
            string? IsBetweenRange(int suppliedRounds)
            {
                /* Too few? */
                if (suppliedRounds < minRounds)
                    return GenerateError("small");

                /* Too big? */
                if (suppliedRounds > maxRounds)
                    return GenerateError("large");

                /* Just right. */
                return null;
            }

            string GenerateError(string tooWhat)
                => $"Rounds property is too {tooWhat}." +
                $" Valid range: {minRounds}-{maxRounds}.";
        }

        public ParseHashBackAuth()
        {
            this.IsHostValid = _ => "Host property is not valid.";
            SetClockService(InternalTools.NowInUnixTime, 9);
            SetRoundsLimit(1, 99);
            this.IsVerifyValid = _ => "Verify property is not valid.";
        }

        public ParseResult Parse(string authHeader)
        {
            /* Shortcut nulls. */
            if (string.IsNullOrEmpty(authHeader))
                return ParseResult.NotValid("Header is null/missing.");

            /* Remove "HashBack" header prefix if present and continue without the prefix. */
            var headerBySpace = authHeader.Split(
                " \r\n\t".ToCharArray(), 
                StringSplitOptions.RemoveEmptyEntries)
                .ToList();
            if (headerBySpace.Count > 1 && InternalTools.IsEqualNoCase(headerBySpace[0], "HashBack"))
                authHeader = string.Concat(headerBySpace.Skip(1));

            /* Is the header already a JSON object? */
            byte[] headerAsBytes;
            if (authHeader.Contains('{'))
            {
                /* Store the bytes now the header has any spaces removed.
                 * These will be needed for hashing later. */
                headerAsBytes = Encoding.ASCII.GetBytes(authHeader);
            }

            /* Otherwise, base-64 decode the header. */
            else
            {
                /* Decode the base-64 into bytes, keeping them for hashing later. */
                headerAsBytes = InternalTools.FlexBase64Decode(authHeader);

                /* Store the (possibly) JSON stting back into the header. */
                authHeader = Encoding.UTF8.GetString(headerAsBytes);
            }

            /* Attempt to decode the header per JSON. */
            JObject headerAsJson;
            try
            {
                headerAsJson = JObject.Parse(authHeader);
            }
            catch (Exception ex) /* TODO: Catch only bad-json error. */
            {
                return ParseResult.NotValid("Supplier JSON is invalid. " + ex.Message);
            }

            /* Start pulling out JSON properties, starting with Version. */
            string? suppliedVersion = headerAsJson["Version"]?.Value<string>();
            if (suppliedVersion == null)
                return ParseResult.NotValid("Version property is missing.");
            if (suppliedVersion != InternalTools.versionBillpg40Draft)
                return ParseResult.NotValid(
                    $"Only Version={InternalTools.versionBillpg40Draft} is supported.");

            /* Host. */
            string? suppliedHost = headerAsJson["Host"]?.Value<string>();
            if (suppliedHost == null)
                return ParseResult.NotValid("Host property is missing.");
            string? hostError = this.IsHostValid(suppliedHost);
            if (hostError != null)
                return ParseResult.NotValid(hostError);

            /* Now */
            long? suppliedNow = headerAsJson["Now"]?.Value<long>();
            if (suppliedNow.HasValue == false)
                return ParseResult.NotValid("Now property is missing.");
            string? nowError = this.IsNowValid(suppliedNow.Value);
            if (nowError != null)
                return ParseResult.NotValid(nowError);

            /* Unus */
            string? suppliedUnus = headerAsJson["Unus"]?.Value<string>();
            if (suppliedUnus == null)
                return ParseResult.NotValid("Unus property is missing.");
            byte[]? unusAsBytes = DecodeUnus(suppliedUnus);
            if (unusAsBytes == null)
                return ParseResult.NotValid("Unus property is not valid.");
            if (unusTracker.IsReused(unusAsBytes))
                return ParseResult.NotValid("Unus property has been reused.");

            /* Rounds */
            int? suppliedRounds = headerAsJson["Rounds"]?.Value<int>();
            if (suppliedRounds.HasValue == false)
                return ParseResult.NotValid("Rounds property is missing.");
            string? roundsError = this.IsRoundsValid(suppliedRounds.Value);
            if (roundsError != null)
                return ParseResult.NotValid(roundsError);

            /* Verify */
            string? suppliedVerify = headerAsJson["Verify"]?.Value<string>();
            if (suppliedVerify == null)
                return ParseResult.NotValid("Verify property is missing.");
            Uri? verifyAsUrl = TryParseUrl(suppliedVerify);
            if (verifyAsUrl == null)
                return ParseResult.NotValid("Verify property is not a valid URL.");
            string? verifyError = this.IsVerifyValid(verifyAsUrl);
            if (verifyError != null)
                return ParseResult.NotValid(verifyError);

            /* All properties have been validated. 
             * Now find the expected hash from the original bytes. */
            string expectedHash = InternalTools.CalculateHash(headerAsBytes, suppliedRounds.Value);

            /* Return collected properties as success result. */
            return ParseResult.Verification(verifyAsUrl, expectedHash);
        }



        private static Uri? TryParseUrl(string url)
        {
            try
            {
                return new Uri(url);
            }
            catch (Exception) /* TODO Replace with URL parse exception. */
            {
                return null;
            }
        }

        private static byte[]? DecodeUnus(string unus)
        {
            /* Attempt to decode base64, returning null if not. */
            byte[] unusAsBytes;
            try
            {
                unusAsBytes = Convert.FromBase64String(unus);
            }
            catch (FormatException)
            {
                return null;
            }

            /* Return null if not exactly expected length. */
            if (unusAsBytes.Length != 128 / 8)
                return null;

            /* Return array as passed tests. */
            return unusAsBytes;
        }
    }
}
