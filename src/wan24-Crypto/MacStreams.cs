using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// MAC streams
    /// </summary>
    public sealed record class MacStreams : DisposableRecordBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="transform">Transform</param>
        public MacStreams(in CryptoStream stream, in KeyedHashAlgorithm transform) : base()
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

        /// <summary>
        /// MAC
        /// </summary>
        public byte[] Mac => Transform.Hash ?? throw new InvalidOperationException();

        /// <summary>
        /// Finalize the MAC
        /// </summary>
        /// <param name="transformFinal">Transform the final block?</param>
        public void FinalizeMac(in bool transformFinal = true)
        {
            Stream.Dispose();
            //FIXME No problems with MAC as with hash yet - just in case
            if (transformFinal) Transform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        }

        /// <summary>
        /// Finalize the MAC
        /// </summary>
        /// <param name="transformFinal">Transform the final block?</param>
        public async Task FinalizeMacAsync(bool transformFinal = true)
        {
            await Stream.DisposeAsync().DynamicContext();
            //FIXME No problems with MAC as with hash yet - just in case
            if (transformFinal) Transform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
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
