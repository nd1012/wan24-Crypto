using System.Security.Cryptography;
using wan24.Core;
using wan24.Crypto;

namespace wan24_Crypto_Tests
{
    public sealed record class EncryptionDummyAlgorithm : EncryptionAlgorithmBase
    {
        public const string ALGORITHM_NAME = "DUMMY";
        public const int ALGORITHM_VALUE = int.MaxValue;
        public const int KEY_SIZE = 32;
        public const int IV_SIZE = 16;
        public const int BLOCK_SIZE = 1;
        public const string DISPLAY_NAME = "TEST DUMMY";

        static EncryptionDummyAlgorithm() => Instance = new();

        public EncryptionDummyAlgorithm() : base(ALGORITHM_NAME, ALGORITHM_VALUE) { }

        public static EncryptionDummyAlgorithm Instance { get; }

        public override int KeySize => KEY_SIZE;

        public override int IvSize => IV_SIZE;

        public override int BlockSize => BLOCK_SIZE;

        public override bool RequireMacAuthentication => false;

        public override bool IsPostQuantum => true;

        public override string DisplayName => DISPLAY_NAME;

        public override long MaxCipherDataLength => long.MaxValue;

        public override long MaxKeyUsageCount => long.MaxValue;

        public override byte[] EnsureValidKeyLength(byte[] key) => GetValidLengthKey(key, KEY_SIZE);

        public override bool IsKeyLengthValid(int len) => len == KEY_SIZE;

        /// <inheritdoc/>
        protected override ICryptoTransform GetEncryptor(Stream cipherData, CryptoOptions options)
        {
            try
            {
                cipherData.Write(RandomNumberGenerator.GetBytes(IV_SIZE));
                return new DummyCryptoTransform();
            }
            catch (wan24.Crypto.CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw wan24.Crypto.CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        protected override async Task<ICryptoTransform> GetEncryptorAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken)
        {
            try
            {
                await cipherData.WriteAsync(RandomNumberGenerator.GetBytes(IV_SIZE), cancellationToken).DynamicContext();
                return new DummyCryptoTransform();
            }
            catch (wan24.Crypto.CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw wan24.Crypto.CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        protected override ICryptoTransform GetDecryptor(Stream cipherData, CryptoOptions options)
        {
            try
            {
                ReadFixedIvBytes(cipherData, options);
                return new DummyCryptoTransform();
            }
            catch (wan24.Crypto.CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw wan24.Crypto.CryptographicException.From(ex);
            }
        }

        /// <inheritdoc/>
        protected override async Task<ICryptoTransform> GetDecryptorAsync(Stream cipherData, CryptoOptions options, CancellationToken cancellationToken)
        {
            try
            {
                await ReadFixedIvBytesAsync(cipherData, options, cancellationToken).DynamicContext();
                return new DummyCryptoTransform();
            }
            catch (wan24.Crypto.CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw wan24.Crypto.CryptographicException.From(ex);
            }
        }
    }
}
