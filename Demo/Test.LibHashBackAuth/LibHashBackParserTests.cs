using LibHashBackAuth;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using System;
using System.Reflection.Metadata.Ecma335;
using System.Security.Cryptography;
using System.Text;

namespace Test.LibHashBackAuth
{
    [TestClass]
    public class LibHashBackParserTests
    {
        [TestMethod]
        public void ParseSampleFromReadMe_NoMods()
            => ParseReadMeSampleInternal();

        [TestMethod]
        public void ParseSampleFromReadMe_NoEquals()
            => ParseReadMeSampleInternal(trimEquals: true);

        [TestMethod]
        public void ParseSampleFromReadMe_AddSpaces()
            => ParseReadMeSampleInternal(addSpaces: true);

        [TestMethod]
        public void ParseSampleFromReadMe_AsJson()
            => ParseReadMeSampleInternal(decodeBase64: true);

        [TestMethod]
        public void ParseSampleFromReadMe_WithPrefix()
            => ParseReadMeSampleInternal(addPrefix: "HashBack");

        [TestMethod]
        public void ParseSampleFromReadMe_WithAllCapsPrefix()
            => ParseReadMeSampleInternal(addPrefix: "HASHBACK");

        [TestMethod]
        public void ParseSampleFromReadMe_WithAllLowerCasePrefix()
            => ParseReadMeSampleInternal(addPrefix: "hashback");

        [TestMethod]
        public void ParseSampleFromReadMe_AddSpaces_WithPrefix()
            => ParseReadMeSampleInternal(addSpaces: true, addPrefix: "HashBack");

        [TestMethod]
        public void ParseSampleFromReadMe_AsJson_WithPrefix()
            => ParseReadMeSampleInternal(decodeBase64: true, addPrefix: "HashBack");

        private void ParseReadMeSampleInternal(
            bool addSpaces = false,
            bool decodeBase64 = false,
            bool trimEquals = false,
            string? addPrefix = null)
        {
            /* Initialise parser and configure it with a capture object. */
            var parser = new ParseHashBackAuth();
            var capture = TestTools.ParserCapture.Set(parser);

            /* Start with the string copy/pasted from the draft README. */
            string authHeader =
                "eyJWZXJzaW9uIjoiQklMTFBHX0RSQUZUXzQuMCIsIkhvc3QiOiJzZXJ2ZXIuZXhhbXBsZSIsIk5v" +
                "dyI6NTI5Mjk3MjAwLCJVbnVzIjoiUnBndDRGYzVuTURxMTRMT3BzL2hZUT09IiwiUm91bmRzIjox" +
                "LCJWZXJpZnkiOiJodHRwczovL2NsaWVudC5leGFtcGxlL2hhc2hiYWNrP2lkPS05MjU3NjkifQ==";

            /* Add spaces to the auth header? */
            if (addSpaces)
            {
                var rnd = new Random("Deterministic".GetHashCode());
                for (int i = 1; i < authHeader.Length; i += rnd.Next(50))
                    authHeader = authHeader.Insert(i, "\r\n    ");
            }

            /* Decode the base 64? */
            if (decodeBase64)
                authHeader = Encoding.ASCII.GetString(Convert.FromBase64String(authHeader));

            /* Trim the trailing equalses? */
            if (trimEquals)
                authHeader = authHeader.TrimEnd('=');

            /* Add "HashBack" to header? */
            if (addPrefix != null)
                authHeader = addPrefix + " " + authHeader;

            /* Call parser. */
            var result = parser.Parse(authHeader);

            /* Check response. */
            Assert.IsTrue(result.IsVerificationNeeded);
            Assert.AreEqual("https://client.example/hashback?id=-925769", result.VerifyUrl?.ToString());
            Assert.AreEqual("8UkPR3Vxjmj/xVe7inMT+O7ALKclnPILlt7puKQUGGI=", result.ExpectedHash);

            /* Check captured values. */
            Assert.AreEqual("server.example", capture.CapturedHost);
            Assert.AreEqual(529297200, capture.CapturedNow);
            Assert.AreEqual(1, capture.CapturedRounds);
            Assert.AreEqual(new Uri("https://client.example/hashback?id=-925769"), capture.CapturedVerify);
        }

        [TestMethod]
        public void ParseWithJWT_ZeroPadding_UsePlus()
            => ParseWithJWT_Shared(0, false, true);

        [TestMethod]
        public void ParseWithJWT_ZeroPadding_UseSlash()
            => ParseWithJWT_Shared(0, true, false);

        [TestMethod]
        public void ParseWithJWT_ZeroPadding()
            => ParseWithJWT_Shared(0, true, true);

        [TestMethod]
        public void ParseWithJWT_OnePadding()
            => ParseWithJWT_Shared(1, true, true);

        [TestMethod]
        public void ParseWithJWT_TwoPadding()
            => ParseWithJWT_Shared(2, true, true);

        [TestMethod]
        public void ParseWithJWT_ThreePadding()
            => ParseWithJWT_Shared(3, true, true);

        [TestMethod]
        public void ParseWithJWT_FourPadding()
            => ParseWithJWT_Shared(4, true, true);

        [TestMethod]
        public void ParseWithJWT_FivePadding()
            => ParseWithJWT_Shared(5, true, true);

        private void ParseWithJWT_Shared(int verifyPadding, bool plusToMinus, bool slashToUnderscore)
        {
            /* Generate a string to use as the Verify property.
             * By using a variety of padding lengths, one of them
             * will have each numbers of equals on the end. */
            string expectedVerify =
                "//rutabaga.example/"
                + new string('x', verifyPadding)
                + "/";

            /* Build a vaid HashBack authentication request, but 
             * with a Host property that can be relied upon to
             * produce a / and + when Base64 encoded. */
            const string TestHostString = ">>>>>>??????";
            var authAsJson = TestTools.MakeJsonRequest(
                host: TestHostString,
                verify: expectedVerify);

            /* Convert this JSON to string, then bytes, then Base64. */
            var authAsString = authAsJson.ToString();
            var authAsBytes = Encoding.ASCII.GetBytes(authAsString);
            var authAsHeader = "HashBack " + Convert.ToBase64String(authAsBytes);

            /* Check the magic Host string worked. */
            Assert.IsTrue(authAsHeader.Contains('/'));
            Assert.IsTrue(authAsHeader.Contains('+'));

            /* Replace the / and + with JWT equivalents if 
             * this test case requires that. */
            if (plusToMinus)
                authAsHeader = authAsHeader.Replace('+', '-');
            if (slashToUnderscore)
                authAsHeader = authAsHeader.Replace('/', '_');

            /* Set up a parser object with a capturing verify object
             * that returns no-error signals to the caller. */
            var parser = new ParseHashBackAuth();
            var capture = TestTools.ParserCapture.Set(parser);

            /* Run the parser against the generated and modified auth header. */
            var result = parser.Parse(authAsHeader);

            /* Check the result was accepted. */
            Assert.IsTrue(result.IsVerificationNeeded);
            Assert.IsNull(result.ErrorText);

            /* Hash the bytes according to the HashBack rules. */
            Assert.AreEqual(TestTools.CalculateHash(authAsBytes, 1), result.ExpectedHash);

            /* Check the captured values called by the parser are as expected. */
            Assert.AreEqual(TestHostString, capture.CapturedHost);
            Assert.AreEqual(100, capture.CapturedNow);
            Assert.AreEqual(1, capture.CapturedRounds);
            Assert.AreEqual("file:" + expectedVerify, capture.CapturedVerify?.ToString());
        }

        /// <summary>
        /// Generates a HashBack auth header, but with a repeatable Unus property.
        /// (For testing the Unus-reuse detector.)
        /// </summary>
        /// <param name="unusNumber">Which of a sequence to create.</param>
        /// <returns>Completed auth header value.</returns>
        private static string BuildJsonWithRepeatableUnus(int unusNumber)
        {
            /* Generate bytes using a repeatable method. (Only need 128 bits.) */
            var hashInput = Encoding.ASCII.GetBytes("RepeatableUnus" + unusNumber);
            var unusAsBytes = SHA256.HashData(hashInput);
            var unusAsBase64 = Convert.ToBase64String(unusAsBytes, 0, 16);

            /* Generate JSON using fixed values except Unus. */
            var authAsJson = TestTools.MakeJsonRequest(unus: unusAsBase64);

            /* Convert JSON to string, then bytes, then base-64. */
            var jsonAsString = authAsJson.ToString(Newtonsoft.Json.Formatting.None);
            var jsonAsBytes = Encoding.ASCII.GetBytes(jsonAsString);
            var jsonAsBase64 = Convert.ToBase64String(jsonAsBytes);

            /* Return completed string. */
            return "HashBack " + jsonAsBase64;
        }

        [TestMethod]
        public void UnusReuseDetector()
        {
            /* Start a parser that will accept all inputs. */
            var parser = new ParseHashBackAuth();
            TestTools.ParserCapture.Set(parser);

            /* Loop, parsing two thousand JSON strings,
             * filling up the reuse-detection collector,
             * checking it responds as valid each time. */
            for (int i = 0; i < 2000; i++)
            {
                var result = parser.Parse(BuildJsonWithRepeatableUnus(i));
                Assert.IsNull(result.ErrorText);
                Assert.IsNotNull(result.VerifyUrl);
                Assert.IsNotNull(result.ExpectedHash);
            }

            /* An Unus string from the first thousand should be okay. */
            var result920 = parser.Parse(BuildJsonWithRepeatableUnus(920));
            Assert.IsNull(result920.ErrorText);
            Assert.IsNotNull(result920.VerifyUrl);
            Assert.IsNotNull(result920.ExpectedHash);

            /* An Unus string from the second thousand should be off limits. */
            var result1984 = parser.Parse(BuildJsonWithRepeatableUnus(920));
            Assert.AreEqual("Unus property has been reused.", result1984.ErrorText);
            Assert.IsNull(result1984.VerifyUrl);
            Assert.IsNull(result1984.ExpectedHash);
        }

        [TestMethod]
        public void ParserRejectsEmptyString()
        {
            /* Call parser with an empty string. */
            var result = new ParseHashBackAuth().Parse("");

            /* Expect a specific error back. */
            Assert.AreEqual("Header is null/missing.", result.ErrorText);
        }

        [TestMethod]
        public void ParserRejectsCRLF()
        {
            /* Call parser with an empty string. */
            var result = new ParseHashBackAuth().Parse("\r\n");

            /* Expect a specific error back. */
            Assert.AreEqual("Supplied JSON is invalid." +
                " Error reading JObject from JsonReader." +
                " Path '', line 0, position 0.",
                result.ErrorText);
        }

        [TestMethod]
        public void ParserRejectsAuthorizationHashBackOnly()
        {
            /* Invoke parser but there's no base-64 block at all. */
            var result = new ParseHashBackAuth().Parse("HashBack");

            /* Expect a specific error back, because "HashBack"
             * also happens to be a valid base-64 block. */
            Assert.AreEqual("Supplied JSON is invalid." +
                " Unexpected character encountered while parsing value:" +
                " \u001d. Path '', line 0, position 0.",
                result.ErrorText);
        }

        [TestMethod]
        public void ParserRejectsBadJson()
        {
            /* Invoke parser, supplying a series of open-curly-braces. */
            var result = new ParseHashBackAuth().Parse("HashBack {{{{");

            /* Expect a specific error back. */
            Assert.AreEqual(
                "Supplied JSON is invalid." +
                " Invalid property identifier character:" +
                " {. Path '', line 1, position 1.",
                result.ErrorText);
        }

        [TestMethod]
        public void ParserRejectsMissingJsonProperties()
        {
            var propertyNames = new string[]
            {
                "Version", "Host", "Now",
                "Unus", "Rounds", "Verify"
            };

            foreach (string propName in propertyNames)
            {
                ParseExpectingError(
                    j => j.Remove(propName), p => { },
                    $"{propName} property is missing.");
            }
        }

        [TestMethod]
        public void ParserRejectsWrongVersion()
            => ParseExpectingError(
                j => j["Version"] = "RUTABAGA_1.0", p => { },
                "Only Version=BILLPG_DRAFT_4.0 is supported.");

        [TestMethod]
        public void ParserRejectsEmptyUnus()
            => ParseExpectingInvalidUnus("");

        [TestMethod]
        public void ParserRejectsShortUnus()
            => ParseExpectingInvalidUnus("Rutabaga");

        [TestMethod]
        public void ParserRejectsLongUnus()
            => ParseExpectingInvalidUnus("RutabagaRutabagaRutabagaRutabaga");

        [TestMethod]
        public void ParserRejectsNotBase64Unus()
            => ParseExpectingInvalidUnus("-=-=-=-=-=-=");

        private void ParseExpectingInvalidUnus(string unus)
            => ParseExpectingError(
                j => j["Unus"] = unus, p => { },
                "Unus property is not valid.");

        [TestMethod]
        public void ParseRejectsWrongHost()
            => ParseExpectingError(
                j => { },
                p => p.SetRequiredHost("different.example"),
                "Host property must be \"different.example\".");

        [TestMethod]
        public void ParseRejectsFarPast()
            => ParseExpectingError(
                j => j["Now"] = 100,
                p => p.SetClockService(TestTools.FixedNow(99999), 10),
                "Supplied Now property is too far in the past.");

        [TestMethod]
        public void ParseRejectsFarFuture()
            => ParseExpectingError(
                j => j["Now"] = 99999,
                p => p.SetClockService(TestTools.FixedNow(100), 10),
                "Supplied Now property is too far in the future.");

        [TestMethod]
        public void ParseRejectsTooFewRounds()
            => ParseExpectingError(
                j => { },
                p => p.SetRoundsLimit(2,9),
                "Rounds property is too small. Valid range: 2-9.");

        [TestMethod]
        public void ParseRejectsTooManyRounds()
            => ParseExpectingError(
                j => j["Rounds"] = 10,
                p => p.SetRoundsLimit(2, 9),
                "Rounds property is too large. Valid range: 2-9.");

        [TestMethod]
        public void ParseRejectsEmptyVerify()
            => ParseRejectsInvalidVerifyUrl("");

        [TestMethod]
        public void ParseRejectsBadVerify()
            => ParseRejectsInvalidVerifyUrl("Not-A-URL!");

        [TestMethod]
        public void ParseRejectsUnknownVerifyUrlScheme()
            => ParseRejectsInvalidVerifyUrl("!://example.com/x.txt");

        [TestMethod]
        public void ParseRejectsVerifyTooManySlashes()
            => ParseRejectsInvalidVerifyUrl("https:///example.com/x.txt");

        [TestMethod]
        public void ParseRejectsVerifyOnlyOneSlash()
            => ParseRejectsInvalidVerifyUrl("https:/example.com/x.txt");

        private void ParseRejectsInvalidVerifyUrl(string url)
            => ParseExpectingError(
                j => j["Verify"] = url,
                p => { },
                "Verify property is not a valid URL.");

        [TestMethod]
        public void ParseRejectsAnyInvalidVerifyUrl()
            => ParseExpectingError(
                j => { },
                p => p.IsVerifyValid = url => "no!",
                "no!");
        
        private void ParseExpectingError(
            Action<JObject> modJson, 
            Action<ParseHashBackAuth> modParser, 
            string expectedErrorText)
        {
            /* Make a JSON object but modify it per the caller. */
            var auth = TestTools.MakeJsonRequest();
            modJson(auth);
            var authAsBase64 = TestTools.JObjectToBase64(auth);

            /* Invoke parser with "accept anything" handlers,
             * allowing the call to make a last minute change. */
            var parser = new ParseHashBackAuth();
            TestTools.ParserCapture.Set(parser);
            modParser(parser);
            var result = parser.Parse(authAsBase64);

            /* Check expected error. */
            Assert.AreEqual(expectedErrorText, result.ErrorText);
            Assert.IsNull(result.VerifyUrl);
            Assert.IsNull(result.ExpectedHash);
        }
    }
}
