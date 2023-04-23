using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class Extensions_Tests
    {
        public static readonly byte[] Data = new byte[] { 1, 2, 3 };
        public static readonly byte[] Key = new byte[] { 1, 2, 3 };

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
            using MemoryStream ms = new(Data);
            byte[] mac = ms.Mac(Key);
            ms.Position = 0;
            Assert.IsTrue(ms.ValidateMac(mac, Key));
            Array.Clear(mac);
            Assert.IsFalse(ms.ValidateMac(mac, Key));
        }

        [TestMethod]
        public async Task ValidateMacAsync_Tests()
        {
            using MemoryStream ms = new(Data);
            byte[] mac = await ms.MacAsync(Key);
            ms.Position = 0;
            Assert.IsTrue(await ms.ValidateMacAsync(mac, Key));
            Array.Clear(mac);
            Assert.IsFalse(await ms.ValidateMacAsync(mac, Key));
        }
    }
}
