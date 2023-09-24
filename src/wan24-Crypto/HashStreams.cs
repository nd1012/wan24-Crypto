using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Hash streams
    /// </summary>
    public sealed class HashStreams : DisposableBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="transform">Transform</param>
        public HashStreams(CryptoStream stream, HashAlgorithm transform) : base()
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
        public HashAlgorithm Transform { get; }

        /// <summary>
        /// Hash
        /// </summary>
        public byte[] Hash => Transform.Hash ?? throw new InvalidOperationException();

        /// <summary>
        /// Finalize the hash
        /// </summary>
        public void FinalizeHash()
        {
            Stream.Dispose();
            Transform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        }

        /// <summary>
        /// Finalize the hash
        /// </summary>
        public async Task FinalizeHashAsync()
        {
            await Stream.DisposeAsync().DynamicContext();
            Transform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        }

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
