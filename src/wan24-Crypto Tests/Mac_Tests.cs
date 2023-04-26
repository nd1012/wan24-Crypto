using wan24.Crypto;
using wan24.Crypto.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Mac_Tests
    {
        [TestMethod]
        public async Task All_Tests() => await MacTests.TestAllAlgorithms();

        [TestMethod]
        public void MacHelper_Tests()
        {
            Assert.AreEqual(MacHmacSha512Algorithm.ALGORITHM_NAME, MacHelper.DefaultAlgorithm.Name);
            Assert.AreEqual(MacHelper.DefaultAlgorithm.MacLength, TestData.Data.Hash().Length);
            Assert.AreEqual(MacHelper.DefaultAlgorithm, MacHelper.GetAlgorithm(MacHelper.DefaultAlgorithm.Name));
            Assert.AreEqual(MacHelper.DefaultAlgorithm, MacHelper.GetAlgorithm(MacHelper.DefaultAlgorithm.Value));
        }
    }
}
