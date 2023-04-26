using wan24.Crypto.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Encryption_Tests
    {
        [TestMethod]
        public async Task All_Tests() => await EncryptionTests.TestAllAlgorithms();
    }
}
