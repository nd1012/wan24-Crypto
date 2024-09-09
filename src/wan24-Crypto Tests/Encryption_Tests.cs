using wan24.Crypto.Tests;
using wan24.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Encryption_Tests : TestBase
    {
        [TestMethod]
        public async Task All_Tests() => await EncryptionTests.TestAllAlgorithms();
    }
}
