using LibHashBackAuth;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.WebRequestMethods;

namespace Test.LibHashBackAuth
{
    [TestClass]
    public class LibHashBackGeneratorTests
    {
        /// <summary>
        /// A random GUID, generated in advance for use in tests.
        /// </summary>
        private const string testGuid =
            "372F758B-8EAE-4505-A150-586D4B64803E";

        [TestMethod]
        public void SetVerifyByQueryString_FirstParam()
        {
            var gen = new GeneratorHashBackAuth();
            gen.SetVerifyByQueryString("https://client.example/auth", "id");
            var url = gen.VerifyUrlService(new Guid(testGuid));
            Assert.AreEqual(new Uri($"https://client.example/auth?id={testGuid}"), url);
        }

        [TestMethod]
        public void SetVerifyByQueryString_SecondParam()
        {
            var gen = new GeneratorHashBackAuth();
            gen.SetVerifyByQueryString("https://client.example/auth?x=y", "id");
            var url = gen.VerifyUrlService(new Guid(testGuid));
            Assert.AreEqual(new Uri($"https://client.example/auth?x=y&id={testGuid}"), url);
        }

        [TestMethod]
        public void SetVerifyByFileInFolder_MissingSlash()
        {
            var gen = new GeneratorHashBackAuth();
            gen.SetVerifyByFileInFolder("https://client.example/auth", ".txt");
            var url = gen.VerifyUrlService(new Guid(testGuid));
            Assert.AreEqual(new Uri($"https://client.example/auth/{testGuid}.txt"), url);
        }

        [TestMethod]
        public void SetVerifyByFileInFolder_RemoveQueryString()
        {
            var gen = new GeneratorHashBackAuth();
            gen.SetVerifyByFileInFolder("https://client.example/hello/world?abc=123", ".txt");
            var url = gen.VerifyUrlService(new Guid(testGuid));
            Assert.AreEqual(new Uri($"https://client.example/hello/world/{testGuid}.txt"), url);
        }

        [TestMethod]
        public void SetVerifyByFileInFolder_DomainRoot()
        {
            var gen = new GeneratorHashBackAuth();
            gen.SetVerifyByFileInFolder("https://client.example/", ".txt");
            var url = gen.VerifyUrlService(new Guid(testGuid));
            Assert.AreEqual(new Uri($"https://client.example/{testGuid}.txt"), url);
        }

        [TestMethod]
        public void SetVerifyByFileInFolder_MissingDot()
        {
            var gen = new GeneratorHashBackAuth();
            gen.SetVerifyByFileInFolder("https://client.example/auth/", "txt");
            var url = gen.VerifyUrlService(new Guid(testGuid));
            Assert.AreEqual(new Uri($"https://client.example/auth/{testGuid}.txt"), url);
        }

        [TestMethod]
        public void Generator_RoundTrip()
        {
            /* Generate an auth header. */
            var gen = new GeneratorHashBackAuth();
            gen.SetVerifyByQueryString("https://example.com/", "id");
            var auth = gen.GenerateAuthHeader("server.example");

            /* Parse the header. */
            var parser = new ParseHashBackAuth();
            var capture = TestTools.ParserCapture.Set(parser);
            var result = parser.Parse(auth.AuthHeader);

            /* Check they match. */
            Assert.AreEqual(result.ExpectedHash, auth.VerificationHash);

            /* Check the captures, confirming the generator included
             * the right strings. (Not checking Now because it varies.) */
            Assert.AreEqual("server.example", capture.CapturedHost);
            Assert.AreEqual(1, capture.CapturedRounds);
            Assert.AreEqual(
                "https://example.com/?id=" 
                + auth.VerificationId.ToString().ToUpperInvariant(), 
                capture.CapturedVerify?.ToString());
        }
    }
}
