using System.Security.Cryptography;
using wan24.Core;
using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class ObjectEncrypton_Tests
    {
        [TestMethod]
        public void General_Tests()
        {
            byte[] pwd = RandomNumberGenerator.GetBytes(32);
            EncryptedObject obj = new();

            // Encrypt
            obj.EncryptObject(pwd);
            Assert.IsNotNull(obj.RandomDataEncryptionKey);
            Assert.AreNotEqual(0, obj.RandomDataEncryptionKey.Length);
            Assert.IsTrue(obj.ReadOnlyRawData.SequenceEqual(obj.RawData));
            Assert.IsFalse(obj.ReadOnlyRawData.SequenceEqual(obj.EncryptedValue));

            // Decrypt
            obj.DecryptObject(pwd);
            Assert.IsNotNull(obj.RandomDataEncryptionKey);
            Assert.AreNotEqual(0, obj.RandomDataEncryptionKey.Length);
            Assert.IsTrue(obj.ReadOnlyRawData.SequenceEqual(obj.RawData));
            Assert.IsTrue(obj.ReadOnlyRawData.SequenceEqual(obj.EncryptedValue));
        }

        public sealed class EncryptedObject : IEncryptProperties
        {
            public EncryptedObject()
            {
                ReadOnlyRawData = RandomNumberGenerator.GetBytes(1000);
                RawData = ReadOnlyRawData.CloneArray();
                EncryptedValue = RawData.CloneArray();
            }

            [Dek]
            public byte[]? RandomDataEncryptionKey { get; set; }

            public byte[] ReadOnlyRawData { get; }

            public byte[] RawData { get; set; }

            [Encrypt]
            public byte[] EncryptedValue { get; set; }
        }
    }
}
