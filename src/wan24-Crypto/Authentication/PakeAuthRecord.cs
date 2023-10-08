using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto.Authentication
{
    /// <summary>
    /// PAKE authentication record (keep the contents secret!)
    /// </summary>
    public sealed record class PakeAuthRecord : StreamSerializerRecordBase, IPakeAuthRecord
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Protected secret
        /// </summary>
        private byte[]? _Secret = null;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="identifier">Identifier (will be cleared!)</param>
        /// <param name="rawSecret">Raw secret (will be cleared!)</param>
        /// <param name="key">Key (will be cleared!)</param>
        /// <param name="signatureKey">Signature key (will be cleared!)</param>
        public PakeAuthRecord(in byte[] identifier, in byte[] rawSecret, in byte[] key, in byte[]? signatureKey = null) : this()
        {
            Identifier = identifier;
            RawSecret = rawSecret;
            Key = key;
            SignatureKey = signatureKey!;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="signup">Signup</param>
        /// <param name="signatureKey">Signature key (will be cleared!)</param>
        public PakeAuthRecord(in PakeSignup signup, in byte[] signatureKey) : this()
        {
            Identifier = signup.Identifier.CloneArray();
            RawSecret = signup.Secret.CloneArray();
            Key = signup.Key.CloneArray();
            SignatureKey = signatureKey;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="existing">Existing record (will be cloned)</param>
        public PakeAuthRecord(in IPakeAuthRecord existing) : this()
        {
            Identifier = existing.Identifier.CloneArray();
            RawSecret = existing.RawSecret.CloneArray();
            Key = existing.Key.CloneArray();
            SignatureKey = existing.SignatureKey.CloneArray();
        }

        /// <summary>
        /// Constructor
        /// </summary>
        public PakeAuthRecord() : base(VERSION) { }

        /// <inheritdoc/>
        public byte[] Identifier { get; internal set; } = null!;

        /// <inheritdoc/>
        [SensitiveData]
        public byte[] Key { get; internal set; } = null!;

        /// <inheritdoc/>
        [SensitiveData]
        public byte[] RawSecret { get; internal set; } = null!;

        /// <inheritdoc/>
        [SensitiveData]
        public byte[] Secret => _Secret ??= RawSecret.Xor(Key);

        /// <inheritdoc/>
        [SensitiveData]
        public byte[] SignatureKey { get; internal set; } = null!;

        /// <summary>
        /// Set the signature key, if not set yet
        /// </summary>
        /// <param name="signatureKey">Signature key (will be cleared!)</param>
        public void SetSignatureKey(in byte[] signatureKey)
        {
            if (SignatureKey is not null) throw new InvalidOperationException();
            SignatureKey = signatureKey;
        }

        /// <summary>
        /// Clear the contents
        /// </summary>
        public void Clear()
        {
            _Secret?.Clear();
            Identifier?.Clear();
            RawSecret?.Clear();
            Key?.Clear();
            SignatureKey?.Clear();
        }

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            stream.WriteBytes(Identifier);
            stream.Write(RawSecret);
            stream.Write(Key);
            stream.Write(SignatureKey);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteBytesAsync(Identifier, cancellationToken).DynamicContext();
            await stream.WriteAsync(RawSecret, cancellationToken).DynamicContext();
            await stream.WriteAsync(Key, cancellationToken).DynamicContext();
            await stream.WriteAsync(SignatureKey, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            Identifier = stream.ReadBytes(version, minLen: 1, maxLen: byte.MaxValue).Value;
            RawSecret = new byte[Identifier.Length];
            if (stream.Read(RawSecret) != RawSecret.Length) throw new IOException("Failed to read the raw secret");
            Key = new byte[Identifier.Length];
            if (stream.Read(Key) != Key.Length) throw new IOException("Failed to read the authentication key");
            SignatureKey = new byte[Identifier.Length];
            if (stream.Read(SignatureKey) != SignatureKey.Length) throw new IOException("Failed to read the signature key");
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            Identifier = (await stream.ReadBytesAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
            RawSecret = new byte[Identifier.Length];
            if (await stream.ReadAsync(RawSecret, cancellationToken).DynamicContext() != RawSecret.Length) throw new IOException("Failed to read the raw secret");
            Key = new byte[Identifier.Length];
            if (await stream.ReadAsync(Key, cancellationToken).DynamicContext() != Key.Length) throw new IOException("Failed to read the authentication key");
            SignatureKey = new byte[Identifier.Length];
            if (await stream.ReadAsync(SignatureKey, cancellationToken).DynamicContext() != SignatureKey.Length) throw new IOException("Failed to read the signature key");
        }

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="signup"><see cref="PakeRecord"/></param>
        public static implicit operator byte[](in PakeAuthRecord signup) => signup.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Serialized data</param>
        public static explicit operator PakeAuthRecord(in byte[] data) => data.ToObject<PakeAuthRecord>();

        /// <summary>
        /// Create a random PAKE authentication record
        /// </summary>
        /// <param name="pake">PAKE instance</param>
        /// <param name="options">Options</param>
        /// <param name="valueLength">PAKE values length in bytes</param>
        /// <returns>Record</returns>
        public static PakeAuthRecord CreateRandom(in Pake? pake = null, in CryptoOptions? options = null, int? valueLength = null)
        {
            using Pake? ownPake = pake is null ? new(options) : null;
            Pake usedPake = pake ?? ownPake!;
            valueLength ??= MacHelper.GetAlgorithm(usedPake.Options.MacAlgorithm!).MacLength;
            PakeAuthRecord res = new()
            {
                Identifier = RND.GetBytes(valueLength.Value)
            };
            byte[]? expandedKey = null;
            try
            {
                expandedKey = RND.GetBytes(res.Identifier.Length);
                res.Key = usedPake.CreateAuthKey(res.Identifier, expandedKey);
                res.RawSecret = usedPake.CreateSecret(res.Key, expandedKey);
                res.SignatureKey = usedPake.CreateSignatureKey(res.Key, res.RawSecret);
                return res;
            }
            catch
            {
                res.Clear();
                throw;
            }
            finally
            {
                expandedKey?.Clear();
            }
        }

        /// <summary>
        /// Create a random PAKE authentication record
        /// </summary>
        /// <param name="pake">PAKE instance</param>
        /// <param name="options">Options</param>
        /// <param name="valueLength">PAKE values length in bytes</param>
        /// <returns>Record</returns>
        public static async Task<PakeAuthRecord> CreateRandomAsync(Pake? pake = null, CryptoOptions? options = null, int? valueLength = null)
        {
            using Pake? ownPake = pake is null ? new(options) : null;
            Pake usedPake = pake ?? ownPake!;
            valueLength ??= MacHelper.GetAlgorithm(usedPake.Options.MacAlgorithm!).MacLength;
            PakeAuthRecord res = new()
            {
                Identifier = await RND.GetBytesAsync(valueLength.Value).DynamicContext()
            };
            byte[]? expandedKey = null;
            try
            {
                expandedKey = await RND.GetBytesAsync(res.Identifier.Length).DynamicContext();
                res.Key = usedPake.CreateAuthKey(res.Identifier, expandedKey);
                res.RawSecret = usedPake.CreateSecret(res.Key, expandedKey);
                res.SignatureKey = usedPake.CreateSignatureKey(res.Key, res.RawSecret);
                return res;
            }
            catch
            {
                res.Clear();
                throw;
            }
            finally
            {
                expandedKey?.Clear();
            }
        }
    }
}
