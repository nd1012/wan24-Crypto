using wan24.Crypto.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Hybrid_Tests
    {
        [TestMethod]
        public void Asymmetric_Tests()
        {
            HybridTests.AllAsymmetricTests();
        }

        [TestMethod]
        public void MAC_Tests()
        {
            HybridTests.AllMacTests();
        }

        [TestMethod]
        public void KDF_Tests()
        {
            HybridTests.AllKdfTests();
        }

        [TestMethod]
        public void Sync_Encryption_Tests()
        {
            HybridTests.AllSyncEncryptionTests();
        }

        [TestMethod]
        public async Task Async_Encryption_Tests()
        {
            await HybridTests.AllAsyncEncryptionTests();
        }
    }
}
