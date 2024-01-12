using wan24.Crypto;
using wan24.Crypto.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Hashing_Tests
    {
        [TestMethod]
        public async Task All_Tests() => await HashingTests.TestAllAlgorithms();

        [TestMethod]
        public void HashHelper_Tests()
        {
            Assert.AreEqual(HashSha3_512Algorithm.ALGORITHM_NAME, HashHelper.DefaultAlgorithm.Name);
            Assert.AreEqual(HashHelper.DefaultAlgorithm.HashLength, TestData.Data.Hash().Length);
            Assert.AreEqual(HashHelper.DefaultAlgorithm, HashHelper.GetAlgorithm(HashHelper.DefaultAlgorithm.Name));
            Assert.AreEqual(HashHelper.DefaultAlgorithm, HashHelper.GetAlgorithm(HashHelper.DefaultAlgorithm.Value));
        }
    }
}
