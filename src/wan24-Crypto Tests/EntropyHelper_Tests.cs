using Microsoft.Extensions.Logging;
using wan24.Crypto;
using wan24.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class EntropyHelper_Tests : TestBase
    {
        private const int LEN = 256;
        private static readonly byte[] NoEntropy = new byte[LEN];

        [TestMethod, Timeout(1000)]
        public void Shannon_Tests()
        {
            Logger.LogInformation("Shannon bit entropy for no entropy: {entropy}", EntropyHelper.ShannonBitEntropy(NoEntropy));
            Logger.LogInformation("Shannon byte entropy for no entropy: {entropy}", EntropyHelper.ShannonByteEntropy(NoEntropy));
            Logger.LogInformation("Shannon bit entropy for {len} RND: {entropy}", LEN, EntropyHelper.ShannonBitEntropy(RND.GetBytes(LEN)));
            Logger.LogInformation("Shannon byte entropy for {len} RND: {entropy}", LEN, EntropyHelper.ShannonByteEntropy(RND.GetBytes(LEN)));
            Logger.LogInformation("Current bit min.: {min}", EntropyHelper.MinShannonBitEntropy);
            Logger.LogInformation("Current byte min.: {min}", EntropyHelper.MinShannonByteEntropy);

            Assert.AreEqual(0, EntropyHelper.ShannonBitEntropy(NoEntropy));
            Assert.AreEqual(0, EntropyHelper.ShannonByteEntropy(NoEntropy));

            EntropyMonitor monitor = new(Rng.Instance)
            {
                Algorithms = EntropyHelper.Algorithms.ShannonBit,
                MaxRetries = int.MaxValue
            };
            Assert.IsTrue(EntropyHelper.ShannonBitEntropy(monitor.GetBytes(LEN)) >= EntropyHelper.MinShannonBitEntropy);

            monitor = new(Rng.Instance)
            {
                Algorithms = EntropyHelper.Algorithms.ShannonByte
            };
            Assert.IsTrue(EntropyHelper.ShannonByteEntropy(monitor.GetBytes(LEN)) >= EntropyHelper.MinShannonByteEntropy);
        }

        [TestMethod, Timeout(1000)]
        public void Renyi_Tests()
        {
            Logger.LogInformation("Renyi entropy for no entropy: {entropy}", EntropyHelper.RenyiEntropy(NoEntropy));
            Logger.LogInformation("Renyi entropy for {len} RND: {entropy}", LEN, EntropyHelper.RenyiEntropy(RND.GetBytes(LEN)));
            Logger.LogInformation("Current min.: {min}", EntropyHelper.MinRenyiEntropy);

            Assert.IsTrue(EntropyHelper.RenyiEntropy(NoEntropy) <= EntropyHelper.MinRenyiEntropy);

            EntropyMonitor monitor = new(Rng.Instance)
            {
                Algorithms = EntropyHelper.Algorithms.Renyi
            };
            Assert.IsTrue(EntropyHelper.RenyiEntropy(monitor.GetBytes(LEN)) >= EntropyHelper.MinRenyiEntropy);
        }

        [TestMethod, Timeout(1000)]
        public void Min_Tests()
        {
            Logger.LogInformation("Min entropy for no entropy: {entropy}", EntropyHelper.MinEntropy(NoEntropy));
            Logger.LogInformation("Min entropy for {len} RND: {entropy}", LEN, EntropyHelper.MinEntropy(RND.GetBytes(LEN)));
            Logger.LogInformation("Current min.: {min}", EntropyHelper.MinMinEntropy);

            Assert.IsTrue(EntropyHelper.MinEntropy(NoEntropy) <= EntropyHelper.MinMinEntropy);

            EntropyMonitor monitor = new(Rng.Instance)
            {
                Algorithms = EntropyHelper.Algorithms.Min
            };
            Assert.IsTrue(EntropyHelper.MinEntropy(monitor.GetBytes(LEN)) >= EntropyHelper.MinMinEntropy);
        }

        [TestMethod, Timeout(1000)]
        public void Permutation_Tests()
        {
            Logger.LogInformation("Permutation entropy for no entropy: {entropy}", EntropyHelper.PermutationEntropy(NoEntropy));
            Logger.LogInformation("Permutation entropy for {len} RND: {entropy}", LEN, EntropyHelper.PermutationEntropy(RND.GetBytes(LEN)));
            Logger.LogInformation("Current min.: {min}", EntropyHelper.MinPermutationEntropy);

            Assert.IsTrue(EntropyHelper.PermutationEntropy(NoEntropy) < EntropyHelper.MinPermutationEntropy);

            EntropyMonitor monitor = new(Rng.Instance)
            {
                Algorithms = EntropyHelper.Algorithms.Permutation
            };
            Assert.IsTrue(EntropyHelper.PermutationEntropy(monitor.GetBytes(LEN)) >= EntropyHelper.MinPermutationEntropy);
        }

        [TestMethod, Timeout(1000)]
        public void Kolmogorov_Tests()
        {
            Logger.LogInformation("Kolmogorov complexity for no entropy: {entropy}", EntropyHelper.KolmogorovComplexity(NoEntropy));
            Logger.LogInformation("Kolmogorov complexity for {len} RND: {entropy}", LEN, EntropyHelper.KolmogorovComplexity(RND.GetBytes(LEN)));
            Logger.LogInformation("Current min.: {min}", EntropyHelper.MinKolmogorovComplexity);

            // Not TRUE because of the GZip overhead
            //Assert.IsTrue(EntropyHelper.KolmogorovComplexity(NoEntropy) < EntropyHelper.MinKolmogorovComplexity);

            EntropyMonitor monitor = new(Rng.Instance)
            {
                Algorithms = EntropyHelper.Algorithms.Kolmogorov
            };
            Assert.IsTrue(EntropyHelper.KolmogorovComplexity(monitor.GetBytes(LEN)) >= EntropyHelper.MinKolmogorovComplexity);
        }
    }
}
