using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Hashing_Tests
    {
        public static readonly byte[] Data = new byte[] { 1, 2, 3 };

        [TestMethod]
        public void AllSync_Tests()
        {
            Assert.IsTrue(HashHelper.Algorithms.Count > 0);
            foreach (string name in HashHelper.Algorithms.Keys) Sync_Tests(name);
        }

        [TestMethod]
        public async Task AllAsync_Tests()
        {
            Assert.IsTrue(HashHelper.Algorithms.Count > 0);
            foreach (string name in HashHelper.Algorithms.Keys) await Async_Tests(name);
        }

        [TestMethod]
        public void HashHelper_Tests()
        {
            Assert.AreEqual(HashSha512Algorithm.ALGORITHM_NAME, HashHelper.DefaultAlgorithm.Name);
            Assert.AreEqual(HashHelper.DefaultAlgorithm.HashLength, Data.Hash().Length);
            Assert.AreEqual(HashHelper.DefaultAlgorithm, HashHelper.GetAlgorithm(HashHelper.DefaultAlgorithm.Name));
            Assert.AreEqual(HashHelper.DefaultAlgorithm, HashHelper.GetAlgorithm(HashHelper.DefaultAlgorithm.Value));
        }

        public void Sync_Tests(string name)
        {
            Console.WriteLine($"Synchronous hash {name} tests");
            HashAlgorithmBase algo = HashHelper.GetAlgorithm(name);
            using MemoryStream ms = new(Data);
            byte[] streamHash = algo.Hash(ms),
                memoryHash = Data.Hash(new()
                {
                    HashAlgorithm = name
                });
            Assert.AreEqual(algo.HashLength, streamHash.Length);
            Assert.AreEqual(algo.HashLength, memoryHash.Length);
            Assert.IsTrue(streamHash.SequenceEqual(memoryHash));
            using MemoryStream temp = new();
            HashStreams hashStreams = algo.GetHashStream(temp, options: new()
            {
                LeaveOpen = true
            });
            try
            {
                ms.Position = 0;
                ms.CopyTo(hashStreams.Stream);
                hashStreams.Stream.FlushFinalBlock();
                streamHash = hashStreams.Transform.Hash!;
                Assert.IsNotNull(streamHash);
                Assert.AreEqual(algo.HashLength, streamHash.Length);
                Assert.IsTrue(streamHash.SequenceEqual(memoryHash));
                Assert.AreEqual(Data.LongLength, temp.Length);
                byte[] data = new byte[temp.Length];
                temp.Position = 0;
                Assert.AreEqual(data.Length, temp.Read(data));
                Assert.IsTrue(Data.SequenceEqual(data));
            }
            finally
            {
                hashStreams.Dispose();
            }
            temp.SetLength(0);
            hashStreams = algo.GetHashStream(temp, options: new()
            {
                LeaveOpen = false
            });
            try
            {
                ms.Position = 0;
                ms.CopyTo(hashStreams.Stream);
                hashStreams.Stream.FlushFinalBlock();
                streamHash = hashStreams.Transform.Hash!;
                Assert.IsNotNull(streamHash);
                Assert.AreEqual(algo.HashLength, streamHash.Length);
                Assert.IsTrue(streamHash.SequenceEqual(memoryHash));
                Assert.AreEqual(Data.LongLength, temp.Length);
                hashStreams.Dispose();
                try
                {
                    temp.Position = 0;
                }
                catch (ObjectDisposedException)
                {
                }
            }
            finally
            {
                hashStreams.Dispose();
            }
        }

        public async Task Async_Tests(string name)
        {
            Console.WriteLine($"Asynchronous hash {name} tests");
            HashAlgorithmBase algo = HashHelper.GetAlgorithm(name);
            using MemoryStream ms = new(Data);
            byte[] streamHash = await algo.HashAsync(ms);
            Assert.AreEqual(algo.HashLength, streamHash.Length);
            Assert.IsTrue(streamHash.SequenceEqual(Data.Hash(new()
            {
                HashAlgorithm = name
            })));
        }
    }
}
