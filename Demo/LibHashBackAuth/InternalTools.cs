
using System.Data;
using System.Reflection.Metadata.Ecma335;
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
        internal static readonly IList<byte> FIXED_SALT
            = new List<byte>
            {
                113, 218, 98, 9, 6, 165, 151, 157,
                46, 28, 229, 16, 66, 91, 91, 72,
                150, 246, 69, 83, 216, 235, 21, 239,
                162, 229, 139, 163, 6, 73, 175, 201
            }.AsReadOnly();

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
    }
}