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
    }
}
