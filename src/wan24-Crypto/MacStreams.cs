using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// MAC streams
    /// </summary>
    public sealed class MacStreams : DisposableBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="transform">Transform</param>
        public MacStreams(CryptoStream stream, KeyedHashAlgorithm transform) : base()
        {
            Stream = stream;
            Transform = transform;
        }

        /// <summary>
        /// Stream
        /// </summary>
        public CryptoStream Stream { get; }

        /// <summary>
        /// Transform
        /// </summary>
        public KeyedHashAlgorithm Transform { get; }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Stream.Dispose();
            Transform.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await Stream.DisposeAsync().DynamicContext();
            Transform.Dispose();
        }
    }
}
