using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Hash streams
    /// </summary>
    public sealed record class HashStreams : DisposableRecordBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="transform">Transform</param>
        public HashStreams(in CryptoStream stream, in HashAlgorithm transform) : base()
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
        /// <param name="transformFinal">Transform the final block?</param>
        public void FinalizeHash(in bool transformFinal = false)
        {
            Stream.Dispose();
            //FIXME Shouldn't be required, since the CryptoStream should transform the final block when disposed - but it doesn't work always :(
            if (transformFinal) Transform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        }

        /// <summary>
        /// Finalize the hash
        /// </summary>
        /// <param name="transformFinal">Transform the final block?</param>
        public async Task FinalizeHashAsync(bool transformFinal = false)
        {
            await Stream.DisposeAsync().DynamicContext();
            //FIXME Shouldn't be required, since the CryptoStream should transform the final block when disposed - but it doesn't work always :(
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
