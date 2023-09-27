using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class CryptoRandomStream_Tests
    {
        [TestMethod]
        public void General_Tests()
        {
            byte[] rnd = new byte[20];
            Assert.AreEqual(rnd.Length, CryptoRandomStream.Instance.Read(rnd));
            Assert.IsTrue(!rnd.All(b => b == 0));
        }

        [TestMethod]
        public async Task GeneralAsync_Tests()
        {
            byte[] rnd = new byte[20];
            Assert.AreEqual(rnd.Length, await CryptoRandomStream.Instance.ReadAsync(rnd));
            Assert.IsTrue(!rnd.All(b => b == 0));
        }
    }
}
