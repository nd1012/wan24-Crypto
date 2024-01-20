using wan24.Core;
using wan24.Crypto;
using wan24.Crypto.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Kdf_Tests
    {
        [TestMethod]
        public void All_Tests() => KdfTests.TestAllAlgorithms();

        [TestMethod]
        public void KdfHelper_Tests()
        {
            Assert.AreEqual(KdfPbKdf2Algorithm.ALGORITHM_NAME, KdfHelper.DefaultAlgorithm.Name);
            Assert.AreEqual(KdfHelper.DefaultAlgorithm.SaltLength, TestData.Key.Stretch(64).Salt.Length);
            Assert.AreEqual(KdfHelper.DefaultAlgorithm, KdfHelper.GetAlgorithm(KdfHelper.DefaultAlgorithm.Name));
            Assert.AreEqual(KdfHelper.DefaultAlgorithm, KdfHelper.GetAlgorithm(KdfHelper.DefaultAlgorithm.Value));
        }

        [TestMethod]
        public void Options_Tests()
        {
            KdfPbKdf2Options kdfOptions = new();
            CryptoOptions options = new();
            options.WithKdf(KdfPbKdf2Algorithm.ALGORITHM_NAME, kdfOptions: kdfOptions);
            KdfHelper.Stretch("test".GetBytes(), len: 32, options: options);
        }
    }
}
