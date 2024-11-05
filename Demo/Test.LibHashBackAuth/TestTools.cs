using LibHashBackAuth;
using Microsoft.VisualStudio.TestPlatform.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace Test.LibHashBackAuth
{
    internal static class TestTools
    {    
        internal class ParserCapture
        {
            public string? CapturedHost { get; private set; } = null;
            public string? HostError { get; set; } = null;
            public long? CapturedNow { get; private set; } = null;
            public string? NowError { get; set; } = null;
            public int? CapturedRounds { get; private set; } = null;
            public string? RoundsError { get; set; } = null;
            public Uri? CapturedVerify { get; private set; } = null;
            public string? VerifyError { get; set; } = null;

            internal static ParserCapture Set(ParseHashBackAuth parser)
            {
                var capture = new ParserCapture();
                parser.IsHostValid = capture.isHostValid;
                parser.IsNowValid = capture.isNowValid;
                parser.IsRoundsValid = capture.isRoundsValid;
                parser.IsVerifyValid = capture.isVerifyValid;
                return capture;
            }

            private string? isHostValid(string suppliedHost)
            {
                this.CapturedHost = suppliedHost;
                return this.HostError;
            }

            private string? isNowValid(long suppliedNow)
            {
                this.CapturedNow = suppliedNow;
                return this.NowError;
            }

            private string? isRoundsValid(int suppliedRounds)
            {
                this.CapturedRounds = suppliedRounds;
                return this.RoundsError;
            }

            private string? isVerifyValid(Uri suppliedVerify)
            {
                this.CapturedVerify = suppliedVerify;
                return this.VerifyError;
            }
        }

    /// <summary>
    /// Configure a parser to expect fixed supplied values.
    /// </summary>
    /// <param name="parser">Parser object to configre.</param>
    /// <param name="expectedHost">Only acceptable host string.</param>
    /// <param name="expectedNow">Only acceptable Now value.</param>
    /// <param name="expectedVarify">Only acceptable Verify string.</param>
    internal static void ConfigurePerExpectedValues(
            ParseHashBackAuth parser, string expectedHost,
            long expectedNow, string expectedVarify)
        {
            /* The Host property must have this string. */
            parser.SetRequiredHost(expectedHost);
            parser.IsNowValid = TestClock;
            string? TestClock(long clock)
                => clock == expectedNow ? null : "Clock is wrong.";
            parser.IsVerifyValid = TestVerifyUrl;
            string? TestVerifyUrl(Uri url)
                => url.ToString() == expectedVarify ? null : "no!!";
        }

        private static void ConfigureAcceptAnything(ParseHashBackAuth parser)
        {
            parser.IsHostValid = x => null;
            parser.IsNowValid = x => null;
            parser.IsRoundsValid = x => null;
            parser.IsVerifyValid = x => null;
        }


        /// <summary>
        /// A reference to the normally private CalculateHash function.
        /// </summary>
        private static readonly MethodInfo calculateHashInternal
           = typeof(ParseHashBackAuth)
              .GetMethods(BindingFlags.Static | BindingFlags.NonPublic)
              .Single(fn => fn.Name == "CalculateHash");

        /// <summary>
        /// Call through to the hash function.
        /// </summary>
        /// <param name="auth">Bytes to hash.</param>
        /// <param name="rounds">Number of PBKDF2 rounds.</param>
        /// <returns>Hash string.</returns>
        internal static string CalculateHash(byte[] auth, int rounds)
        {
            string? hash = calculateHashInternal.Invoke(null, [auth, rounds]) as string;
            if (hash == null)
                throw new NullReferenceException();
            return hash;
        }


        /// <summary>
        /// Handy collection of the two Boolean values.
        /// </summary>
        internal static readonly IList<bool> TrueAndFalse
            = new List<bool> { true, false }.AsReadOnly();

        internal static IEnumerable<(Tx x, Ty y)> 
            CrossJoin<Tx, Ty>(this IEnumerable<Tx> xs, IEnumerable<Ty> ys)
        {
            foreach (Tx x in xs)
                foreach (Ty y in ys)
                    yield return (x, y);
        }

        internal static IEnumerable<(Tx x, Ty y, Tz z)> 
            CrossJoin<Tx, Ty, Tz>(IEnumerable<Tx> xs, IEnumerable<Ty> ys, IEnumerable<Tz> zs)
        {
            foreach (Tx x in xs)
                foreach (Ty y in ys)
                    foreach (Tz z in zs)
                        yield return (x, y, z);
        }
    }
}
