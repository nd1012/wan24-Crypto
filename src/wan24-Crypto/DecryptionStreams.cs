using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Decryption streams
    /// </summary>
    public sealed record class DecryptionStreams : DisposableRecordBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="cryptoStream">Crypto stream</param>
        /// <param name="transform">Crypto transform</param>
        public DecryptionStreams(Stream cryptoStream, ICryptoTransform transform) : base()
        {
            CryptoStream = cryptoStream;
            Transform = transform;
        }

        /// <summary>
        /// Crypto stream (written data will be written encrypted to the MAC or the cipher stream (while the MAC stream writes to the cipher stream))
        /// </summary>
        public Stream CryptoStream { get; }

        /// <summary>
        /// Crypto transform
        /// </summary>
        public ICryptoTransform Transform { get; }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            CryptoStream.Dispose();
            Transform.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await CryptoStream.DisposeAsync().DynamicContext();
            Transform.Dispose();
        }
    }
}
