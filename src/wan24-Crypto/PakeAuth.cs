﻿using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// PAKE authentication information (needs to be sent to the server, wrapped using a PFS protocol!)
    /// </summary>
    public sealed class PakeAuth : DisposableStreamSerializerBase
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="identifier">Identifier</param>
        /// <param name="key">Key</param>
        /// <param name="signature">Signature</param>
        /// <param name="random">Random bytes</param>
        internal PakeAuth(byte[] identifier, byte[] key, byte[] signature, byte[] random) : this()
        {
            Identifier = identifier;
            Key = key;
            Signature = signature;
            Random = random;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public PakeAuth() : base(VERSION) { }

        /// <summary>
        /// Identifier
        /// </summary>
        public byte[] Identifier { get; private set; } = null!;

        /// <summary>
        /// Key
        /// </summary>
        public byte[] Key { get; private set; } = null!;

        /// <summary>
        /// Signature
        /// </summary>
        public byte[] Signature { get; private set; } = null!;

        /// <summary>
        /// Random bytes
        /// </summary>
        public byte[] Random { get; private set; } = null!;

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Identifier.Clear();
            Key.Clear();
            Signature.Clear();
            Random.Clear();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            await base.DisposeCore().DynamicContext();
            Identifier.Clear();
            Key.Clear();
            Signature.Clear();
            Random.Clear();
        }

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
            => stream.WriteBytes(Identifier)
                .WriteBytes(Key)
                .WriteBytes(Signature)
                .WriteBytes(Random);

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteBytesAsync(Identifier, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(Key, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(Signature, cancellationToken).DynamicContext();
            await stream.WriteBytesAsync(Random, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            Identifier = stream.ReadBytes(version, minLen: 1, maxLen: byte.MaxValue).Value;
            Key = stream.ReadBytes(version, minLen: 1, maxLen: byte.MaxValue).Value;
            Signature = stream.ReadBytes(version, minLen: 1, maxLen: byte.MaxValue).Value;
            Random = stream.ReadBytes(version, minLen: 1, maxLen: byte.MaxValue).Value;
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            Identifier = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            Key = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            Signature = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            Random = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
        }

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="signup"><see cref="PakeAuth"/></param>
        public static implicit operator byte[](PakeAuth signup) => signup.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Serialized data</param>
        public static explicit operator PakeAuth(byte[] data) => data.ToObject<PakeAuth>();
    }
}