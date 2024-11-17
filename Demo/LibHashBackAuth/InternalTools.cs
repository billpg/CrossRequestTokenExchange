
using Newtonsoft.Json.Linq;
using System.Data;
using System.Reflection.Metadata.Ecma335;
using System.Security.Cryptography;
using System.Text;

namespace LibHashBackAuth
{
    /// <summary>
    /// Tools to assist with HashBack parsing and generation.
    /// </summary>
    internal static class InternalTools
    {
        /// <summary>
        /// The expected value of the version string,
        /// copied from draft 4.0.
        /// </summary>
        internal const string versionBillpg40Draft
            = "BILLPG_DRAFT_4.0";

        /// <summary>
        /// A copy of public-draft 4.0's fixed salt in byte array form.
        /// </summary>
        internal static readonly IList<byte> fixedSalt
            = new List<byte>
            {
                113, 218, 98, 9, 6, 165, 151, 157,
                46, 28, 229, 16, 66, 91, 91, 72,
                150, 246, 69, 83, 216, 235, 21, 239,
                162, 229, 139, 163, 6, 73, 175, 201
            }.AsReadOnly();


        internal static string CalculateHash(byte[] headerAsBytes, int rounds)
        {
            /* Perform the PBKDF2 argorithm as required by draft spec 4.0. */
            byte[] hashAsBytes = Rfc2898DeriveBytes.Pbkdf2(
                password: headerAsBytes.ToArray(),
                salt: fixedSalt.ToArray(),
                hashAlgorithm: HashAlgorithmName.SHA256,
                iterations: rounds,
                outputLength: 256 / 8);

            /* Return hash in BASE-64. */
            return Convert.ToBase64String(hashAsBytes);
        }

        /// <summary>
        /// Object returning the current time when called.
        /// </summary>
        internal static Func<long> NowInUnixTime
            => NowInUnixTimePrivate;

        /// <summary>
        /// Private implmentation of NowInUnixTime.
        /// </summary>
        /// <returns>Number of seconds between the epoch and "now".</returns>
        private static long NowInUnixTimePrivate()
        {
            /* Pull out the current time in absolute ticks. */
            long nowInAbsTicks = DateTime.UtcNow.ToUniversalTime().Ticks;

            /* Return after coverting absolute ticks into unix time as seconds. */
            return AbsoluteTicksToUnixTime(nowInAbsTicks);
        }

        private static long AbsoluteTicksToUnixTime(long absTicks)
        {
            /* Find number of ticks since Unix Epoch. */
            long ticksSinceEpoch = absTicks - DateTime.UnixEpoch.Ticks;

            /* Divide to get seconds and return. */
            return ticksSinceEpoch / TimeSpan.TicksPerSecond;
        }

        /// <summary>
        /// Compare two strings for equality, ignoring case for invarient culture.
        /// </summary>
        /// <param name="x">First string.</param>
        /// <param name="y">Second string.</param>
        /// <returns>True if x and y are equal after ignoring case.</returns>
        internal static bool IsEqualNoCase(string x, string y)
            => string.Equals(x, y, StringComparison.InvariantCultureIgnoreCase);

        /// <summary>
        /// Base64 decoder, allowing with or without trailing equals and
        /// JWT's alternative characters.
        /// </summary>
        /// <param name="b64">Base-64 encoded string.</param>
        /// <returns>Decoded bytes.</returns>
        internal static byte[] FlexBase64Decode(string b64)
        {
            /* Start a StringBuilder to receive the fixed base64. */
            var enc = new StringBuilder(b64);

            /* Loop through in reverse order. */
            for (int i=enc.Length-1; i>=0; i--)
            {
                /* Grab the character at this pint. */
                char atIndex = enc[i];

                /* Remove spaces and equals. */
                if (atIndex == '=' || char.IsWhiteSpace(atIndex))
                    enc.Remove(i, 1);

                /* Swap JWT's alternatives. */
                else if (atIndex == '-')
                    enc[i] = '+';
                else if (atIndex == '_')
                    enc[i] = '/';

                /* Otherwise, leave unchanged. */
            }

            /* Shortcut empty strings. */
            if (enc.Length == 0)
                return Array.Empty<byte>();

            /* Add sufficient equalses as expected by base64. */
            int paddingLength = (4 - enc.Length % 4) % 4;
            enc.Append(new string('=', paddingLength));

            /* Return bytes. */
            return Convert.FromBase64String(enc.ToString());
        }

        internal static string GenerateUnus()
        {
            /* Generate 128 cryptographic quality random bits. */
            using var rnd = RandomNumberGenerator.Create();
            byte[] randomBytes = new byte[128 / 8];
            rnd.GetBytes(randomBytes);

            /* Encode those bytes as BASE64, including the trailing equals. */
            return Convert.ToBase64String(randomBytes);
        }

        /// <summary>
        /// Attempt to parse the supplied string as a URL, returning null
        /// if not valid
        /// </summary>
        /// <param name="url">String to parse.</param>
        /// <returns>Parsed URL or NULL.</returns>
        internal static Uri? TryParseUrl(string url)
        {
            /* Attempt to parse the string, and if valid, return it. */
            try
            {
                return new Uri(url);
            }   
            /* Catch either exception that means "the URL is invalid"
             * and return null. (Other exceptions, allow to fall.) */
            catch (Exception ex) 
                when (ex is UriFormatException || ex is FormatException)
            {
                /* Not valid, so return null. */                
                return null;
            }
        }

        /// <summary>
        /// Validates supplied Unus value, returning zero if
        /// not valid, or a non-zero hash value suitable for 
        /// reuse checking if valid.
        /// </summary>
        /// <param name="unus">Supplied Unus value.</param>
        /// <returns>Zero if not valid. Non-zero hash is valid.</returns>
        internal static long ValidateUnusAndHash(string unus)
        {
            /* Attempt to decode base64, returning zero if not. */
            byte[] unusAsBytes;
            try
            {
                unusAsBytes = Convert.FromBase64String(unus);
            }
            catch (FormatException)
            {
                return 0;
            }

            /* Return zero if not exactly expected length. */
            if (unusAsBytes.Length != 128 / 8)
                return 0;

            /* Loop through each byte index in unus, XORing that byte into its
             * place in the hash. Jumping the shifting place by 3 means the 
             * last byte XORs with bits 48-55. */
            long hash = 0;
            for (int unusIndex = 0; unusIndex < unus.Length; unusIndex++)
                hash ^= ((long)unus[unusIndex]) << (unusIndex * 3);

            /* Completed hash. Add a fixed number so the decimal form is the same
             * length. (16 zeros just exceeds the maximum from the above loop.) */
            return hash + 10000000000000000L;
        }
    }
}