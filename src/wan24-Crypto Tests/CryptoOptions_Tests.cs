using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using wan24.Compression;
using wan24.Crypto;
using wan24.StreamSerializerExtensions;

namespace wan24_Crypto_Tests
{
    [TestClass]
    public class CryptoOptions_Tests
    {
        [TestMethod]
        public void General_Tests()
        {
            CryptoOptions options = EncryptionHelper.GetDefaultOptions();
            options.Compression = CompressionHelper.GetDefaultOptions();
            options.HashAlgorithm = HashHelper.DefaultAlgorithm.Name;
            options.AsymmetricAlgorithm = AsymmetricHelper.DefaultKeyExchangeAlgorithm.Name;
            options.MaximumAge = TimeSpan.FromDays(1);
            options.MaximumTimeOffset = TimeSpan.FromMinutes(5);
            using MemoryStream ms = new();
            ms.WriteSerialized(options);
            ms.Position = 0;
            CryptoOptions options2 = ms.ReadSerialized<CryptoOptions>();
            Assert.AreEqual(options.Flags, options2.Flags);
            options.ValidateAlgorithms();
            options.ValidateRequirements();
            Assert.AreEqual(options.Algorithm, options2.Algorithm);
            Assert.AreEqual(options.MacAlgorithm, options2.MacAlgorithm);
            Assert.AreEqual(options.KdfAlgorithm, options2.KdfAlgorithm);
            Assert.AreEqual(options.KdfIterations, options2.KdfIterations);
            Assert.AreEqual(options.AsymmetricAlgorithm, options2.AsymmetricAlgorithm);
            Assert.AreEqual(options.AsymmetricKeyBits, options2.AsymmetricKeyBits);
            Assert.AreEqual(options.HashAlgorithm, options2.HashAlgorithm);
            //TODO Will be fixed with the next wan24-Compression library version
            //Assert.AreEqual(options.Compression.Algorithm, options2.Compression?.Algorithm);
            Assert.AreEqual(options.MaximumAge.Value.TotalMilliseconds, options2.MaximumAge?.TotalMilliseconds);
            Assert.AreEqual(options.MaximumTimeOffset.Value.TotalMilliseconds, options2.MaximumTimeOffset?.TotalMilliseconds);
        }
        [TestMethod]
        public async Task GeneralAsync_Tests()
        {
            CryptoOptions options = EncryptionHelper.GetDefaultOptions();
            options.Compression = CompressionHelper.GetDefaultOptions();
            options.HashAlgorithm = HashHelper.DefaultAlgorithm.Name;
            options.AsymmetricAlgorithm = AsymmetricHelper.DefaultKeyExchangeAlgorithm.Name;
            options.MaximumAge = TimeSpan.FromDays(1);
            options.MaximumTimeOffset = TimeSpan.FromMinutes(5);
            using MemoryStream ms = new();
            await ms.WriteSerializedAsync(options);
            ms.Position = 0;
            CryptoOptions options2 = await ms.ReadSerializedAsync<CryptoOptions>();
            Assert.AreEqual(options.Flags, options2.Flags);
            options.ValidateAlgorithms();
            options.ValidateRequirements();
            Assert.AreEqual(options.Algorithm, options2.Algorithm);
            Assert.AreEqual(options.MacAlgorithm, options2.MacAlgorithm);
            Assert.AreEqual(options.KdfAlgorithm, options2.KdfAlgorithm);
            Assert.AreEqual(options.KdfIterations, options2.KdfIterations);
            Assert.AreEqual(options.AsymmetricAlgorithm, options2.AsymmetricAlgorithm);
            Assert.AreEqual(options.AsymmetricKeyBits, options2.AsymmetricKeyBits);
            Assert.AreEqual(options.HashAlgorithm, options2.HashAlgorithm);
            //TODO Will be fixed with the next wan24-Compression library version
            //Assert.AreEqual(options.Compression.Algorithm, options2.Compression?.Algorithm);
            Assert.AreEqual(options.MaximumAge.Value.TotalMilliseconds, options2.MaximumAge?.TotalMilliseconds);
            Assert.AreEqual(options.MaximumTimeOffset.Value.TotalMilliseconds, options2.MaximumTimeOffset?.TotalMilliseconds);
        }
    }
}
