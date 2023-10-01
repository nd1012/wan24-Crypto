using wan24.Core;
using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class RandomDataGenerator_Tests
    {
        [TestMethod, Timeout(3000)]
        public void General_Tests()
        {
            using RandomDataGenerator rnd = new(
                1024, 
                (buffer) => buffer.Fill(1), 
                (buffer) =>
                {
                    buffer.Span.Fill(1);
                    return Task.CompletedTask;
                }
                );
            rnd.StartAsync().Wait();
            byte[] data = rnd.GetBytes(20);
            Assert.IsTrue(data.All(b => b == 1));
            data.Clear();
            rnd.FillBytes(data);
            Assert.IsTrue(data.All(b => b == 1));
        }

        [TestMethod, Timeout(3000)]
        public async Task GeneralAsync_Tests()
        {
            RandomDataGenerator rnd = new(
                1024,
                (buffer) => buffer.Fill(1),
                (buffer) =>
                {
                    buffer.Span.Fill(1);
                    return Task.CompletedTask;
                }
                );
            await using (rnd)
            {
                rnd.StartAsync().Wait();
                byte[] data = await rnd.GetBytesAsync(20);
                Assert.IsTrue(data.All(b => b == 1));
                data.Clear();
                await rnd.FillBytesAsync(data);
                Assert.IsTrue(data.All(b => b == 1));
            }
        }
    }
}
