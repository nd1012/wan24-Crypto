using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Encryption streams
    /// </summary>
    public sealed class EncryptionStreams : DisposableBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="cryptoStream">Crypto stream (written data will be written encrypted to the MAC or the target cipher stream (while the MAC stream writes to the target cipher stream))</param>
        /// <param name="transform">Crypto transform</param>
        /// <param name="mac">MAC streams</param>
        public EncryptionStreams(Stream cryptoStream, ICryptoTransform transform, MacStreams? mac) : base()
        {
            CryptoStream = cryptoStream;
            Transform = transform;
            Mac = mac;
        }

        /// <summary>
        /// Crypto stream (written data will be written encrypted to the MAC or the target cipher stream (while the MAC stream writes to the target cipher stream))
        /// </summary>
        public Stream CryptoStream { get; }

        /// <summary>
        /// Crypto transform
        /// </summary>
        public ICryptoTransform Transform { get; }

        /// <summary>
        /// MAC streams
        /// </summary>
        public MacStreams? Mac { get; }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            CryptoStream.Dispose();
            Transform.Dispose();
            Mac?.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await CryptoStream.DisposeAsync().DynamicContext();
            Transform.Dispose();
            if (Mac is not null) await Mac.DisposeAsync().DynamicContext();
        }
    }
}
