using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class AsymmetricKeyPool_Tests
    {
        [TestMethod]
        public void General_Tests()
        {
            using AsymmetricKeyPool<AsymmetricEcDiffieHellmanPrivateKey> pool = new(3);
            pool.StartAsync().Wait();
            Thread.Sleep(200);
            using AsymmetricEcDiffieHellmanPrivateKey key = pool.GetOne();
            Assert.IsTrue(pool.Created >= 3);
            Assert.AreEqual(0, pool.CreatedOnDemand);
        }

        [TestMethod]
        public async Task GeneralAsync_Tests()
        {
            AsymmetricKeyPool<AsymmetricEcDiffieHellmanPrivateKey> pool = new(3);
            await using (pool)
            {
                await pool.StartAsync();
                await Task.Delay(200);
                using AsymmetricEcDiffieHellmanPrivateKey key = await pool.GetOneAsync();
                Assert.IsTrue(pool.Created >= 3);
                Assert.AreEqual(0, pool.CreatedOnDemand);
            }
        }
    }
}
