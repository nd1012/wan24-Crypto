using wan24.Crypto;
using wan24.Crypto.Tests;
using wan24.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Extensions_Tests : TestBase
    {
        [TestMethod]
        public void Padding_Tests()
        {
            using MemoryStream ms = new();
            ms.WriteByte(0);
            ms.AddPadding(4);
            Assert.AreEqual(4, ms.Length);
        }

        [TestMethod]
        public async Task PaddingAsync_Tests()
        {
            using MemoryStream ms = new();
            ms.WriteByte(0);
            await ms.AddPaddingAsync(4);
            Assert.AreEqual(4, ms.Length);
        }

        [TestMethod]
        public void ValidateMac_Tests()
        {
            using MemoryStream ms = new(TestData.Data);
            byte[] mac = ms.Mac(TestData.Key);
            ms.Position = 0;
            Assert.IsTrue(ms.ValidateMac(mac, TestData.Key));
            Array.Clear(mac);
            Assert.IsFalse(ms.ValidateMac(mac, TestData.Key));
        }

        [TestMethod]
        public async Task ValidateMacAsync_Tests()
        {
            using MemoryStream ms = new(TestData.Data);
            byte[] mac = await ms.MacAsync(TestData.Key);
            ms.Position = 0;
            Assert.IsTrue(await ms.ValidateMacAsync(mac, TestData.Key));
            Array.Clear(mac);
            Assert.IsFalse(await ms.ValidateMacAsync(mac, TestData.Key));
        }
    }
}
