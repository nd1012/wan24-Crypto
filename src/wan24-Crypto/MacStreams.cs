﻿using System.Security.Cryptography;
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

        /// <summary>
        /// MAC
        /// </summary>
        public byte[] Mac => Transform.Hash ?? throw new InvalidOperationException();

        /// <summary>
        /// Finalize the MAC
        /// </summary>
        public void FinalizeMac()
        {
            Stream.Dispose();
            Transform.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        }

        /// <summary>
        /// Finalize the MAC
        /// </summary>
        public async Task FinalizeMacAsync()
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
