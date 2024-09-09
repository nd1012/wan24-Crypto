using System.Security.Cryptography;
using wan24.Core;
using wan24.Crypto;
using wan24.Tests;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class ObjectEncrypton_Tests : TestBase
    {
        [TestMethod]
        public void General_Tests()
        {
            EncryptedObject obj = new();

            // Encrypt
            obj.AutoEncryptObject();
            Assert.IsTrue(obj.IsEncrypted);
            Assert.IsNotNull(obj.RandomDataEncryptionKey);
            Assert.AreNotEqual(0, obj.RandomDataEncryptionKey.Length);
            Assert.IsTrue(obj.ReadOnlyRawData.SequenceEqual(obj.RawData));
            Assert.IsFalse(obj.ReadOnlyRawData.SequenceEqual(obj.EncryptedValue));

            // Encrypt encrypted object
            Assert.ThrowsException<InvalidOperationException>(() => obj.AutoEncryptObject());

            // Decrypt
            obj.AutoDecryptObject();
            Assert.IsFalse(obj.IsEncrypted);
            Assert.IsNotNull(obj.RandomDataEncryptionKey);
            Assert.AreNotEqual(0, obj.RandomDataEncryptionKey.Length);
            Assert.IsTrue(obj.ReadOnlyRawData.SequenceEqual(obj.RawData));
            Assert.IsTrue(obj.ReadOnlyRawData.SequenceEqual(obj.EncryptedValue));

            // Decrypt unencrypted object
            Assert.ThrowsException<InvalidOperationException>(() => obj.AutoDecryptObject());
        }

        public sealed class EncryptedObject : IEncryptPropertiesKek, IEncryptPropertiesExt
        {
            private readonly byte[] Kek;

            public EncryptedObject()
            {
                Kek = RandomNumberGenerator.GetBytes(32);
                ReadOnlyRawData = RandomNumberGenerator.GetBytes(1000);
                RawData = ReadOnlyRawData.CloneArray();
                EncryptedValue = RawData.CloneArray();
            }

            public bool IsEncrypted { get; private set; }

            [Dek]
            public byte[]? RandomDataEncryptionKey { get; set; }

            public byte[] ReadOnlyRawData { get; }

            public byte[] RawData { get; set; }

            [Encrypt]
            public byte[] EncryptedValue { get; set; }

            SecureByteArray IEncryptPropertiesKek.GetKeyEncryptionKey() => new(Kek.CloneArray());

            void IEncryptPropertiesExt.AfterDecrypt(byte[]? pwd, byte[]? dataEncryptionKey, CryptoOptions? options) => IsEncrypted = false;

            void IEncryptPropertiesExt.AfterEncrypt(byte[]? pwd, int dekLength, byte[]? dataEncryptionKey, CryptoOptions? options) => IsEncrypted = true;

            void IEncryptPropertiesExt.BeforeDecrypt(byte[]? pwd, byte[]? dataEncryptionKey, CryptoOptions? options)
            {
                if (!IsEncrypted) throw new InvalidOperationException();
            }

            void IEncryptPropertiesExt.BeforeEncrypt(byte[]? pwd, int dekLength, byte[]? dataEncryptionKey, CryptoOptions? options)
            {
                if (IsEncrypted) throw new InvalidOperationException();
            }
        }
    }
}
