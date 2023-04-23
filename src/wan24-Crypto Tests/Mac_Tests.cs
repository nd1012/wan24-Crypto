using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Mac_Tests
    {
        public static readonly byte[] Data = new byte[] { 1, 2, 3 };
        public static readonly byte[] Key = new byte[] { 1, 2, 3 };

        [TestMethod]
        public void AllSync_Tests()
        {
            Assert.IsTrue(MacHelper.Algorithms.Count > 0);
            foreach (string name in MacHelper.Algorithms.Keys) Sync_Tests(name);
        }

        [TestMethod]
        public async Task AllAsync_Tests()
        {
            Assert.IsTrue(MacHelper.Algorithms.Count > 0);
            foreach (string name in MacHelper.Algorithms.Keys) await Async_Tests(name);
        }

        [TestMethod]
        public void MacHelper_Tests()
        {
            Assert.AreEqual(MacHmacSha512Algorithm.ALGORITHM_NAME, MacHelper.DefaultAlgorithm.Name);
            Assert.AreEqual(MacHelper.DefaultAlgorithm.MacLength, Data.Hash().Length);
            Assert.AreEqual(MacHelper.DefaultAlgorithm, MacHelper.GetAlgorithm(MacHelper.DefaultAlgorithm.Name));
            Assert.AreEqual(MacHelper.DefaultAlgorithm, MacHelper.GetAlgorithm(MacHelper.DefaultAlgorithm.Value));
            Assert.AreEqual(MacHelper.DefaultAlgorithm.Name, MacHelper.GetAlgorithmName(MacHelper.DefaultAlgorithm.Value));
            Assert.AreEqual(MacHelper.DefaultAlgorithm.Value, MacHelper.GetAlgorithmValue(MacHelper.DefaultAlgorithm.Name));
        }

        public void Sync_Tests(string name)
        {
            Console.WriteLine($"Synchronous MAC {name} tests");
            MacAlgorithmBase algo = MacHelper.GetAlgorithm(name);
            using MemoryStream ms = new(Data);
            byte[] streamMac = algo.Mac(ms, Key),
                memoryMac = Data.Mac(Key, new()
                {
                    MacAlgorithm = name
                });
            Assert.AreEqual(algo.MacLength, streamMac.Length);
            Assert.AreEqual(algo.MacLength, memoryMac.Length);
            Assert.IsTrue(streamMac.SequenceEqual(memoryMac));
            using MemoryStream temp = new();
            MacStreams macStreams = algo.GetMacStream(Key, temp, options: new()
            {
                LeaveOpen = true
            });
            try
            {
                ms.Position = 0;
                ms.CopyTo(macStreams.Stream);
                macStreams.Stream.FlushFinalBlock();
                streamMac = macStreams.Transform.Hash!;
                Assert.IsNotNull(streamMac);
                Assert.AreEqual(algo.MacLength, streamMac.Length);
                Assert.IsTrue(streamMac.SequenceEqual(memoryMac));
                Assert.AreEqual(Data.LongLength, temp.Length);
                byte[] data = new byte[temp.Length];
                temp.Position = 0;
                Assert.AreEqual(data.Length, temp.Read(data));
                Assert.IsTrue(Data.SequenceEqual(data));
            }
            finally
            {
                macStreams.Dispose();
            }
            temp.SetLength(0);
            macStreams = algo.GetMacStream(Key, temp, options: new()
            {
                LeaveOpen = false
            });
            try
            {
                ms.Position = 0;
                ms.CopyTo(macStreams.Stream);
                macStreams.Stream.FlushFinalBlock();
                streamMac = macStreams.Transform.Hash!;
                Assert.IsNotNull(streamMac);
                Assert.AreEqual(algo.MacLength, streamMac.Length);
                Assert.IsTrue(streamMac.SequenceEqual(memoryMac));
                Assert.AreEqual(Data.LongLength, temp.Length);
                macStreams.Dispose();
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
                macStreams.Dispose();
            }
        }

        public async Task Async_Tests(string name)
        {
            Console.WriteLine($"Asynchronous MAC {name} tests");
            MacAlgorithmBase algo = MacHelper.GetAlgorithm(name);
            using MemoryStream ms = new(Data);
            byte[] streamMac = await algo.MacAsync(ms, Key);
            Assert.AreEqual(algo.MacLength, streamMac.Length);
            Assert.IsTrue(streamMac.SequenceEqual(Data.Mac(Key, new()
            {
                MacAlgorithm = name
            })));
        }
    }
}
