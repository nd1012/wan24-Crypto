using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Private key suite (for storing long term keys)
    /// </summary>
    public sealed record class PrivateKeySuite : DisposableStreamSerializerRecordBase, ICloneable, IKeyExchange
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 3;

        /// <summary>
        /// An object for thread synchronization for accessing <see cref="KeyExchangeKey"/>
        /// </summary>
        private readonly object SyncKeyExchangeKey = new();
        /// <summary>
        /// An object for thread synchronization for accessing <see cref="CounterKeyExchangeKey"/>
        /// </summary>
        private readonly object SyncCounterKeyExchangeKey = new();
        /// <summary>
        /// An object for thread synchronization for accessing <see cref="SignatureKey"/>
        /// </summary>
        private readonly object SyncSignatureKey = new();
        /// <summary>
        /// An object for thread synchronization for accessing <see cref="CounterSignatureKey"/>
        /// </summary>
        private readonly object SyncCounterSignatureKey = new();
        /// <summary>
        /// An object for thread synchronization for accessing <see cref="SymmetricKey"/>
        /// </summary>
        private readonly object SyncSymmetricKey = new();
        /// <summary>
        /// Public key suite
        /// </summary>
        private PublicKeySuite? _Public = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public PrivateKeySuite() : base(VERSION) { }

        /// <summary>
        /// Key exchange private key (will be disposed)
        /// </summary>
        [SensitiveData]
        public IKeyExchangePrivateKey? KeyExchangeKey { get; set; }

        /// <summary>
        /// Key exchange private key usage count
        /// </summary>
        [Range(0, long.MaxValue)]
        public long KeyExchangeKeyUsageCount { get; set; }

        /// <summary>
        /// Key exchange private key usage count maximum
        /// </summary>
        [Range(0, long.MaxValue)]
        public long MaxKeyExchangeKeyUsageCount { get; set; } = long.MaxValue;

        /// <summary>
        /// Counter key exchange private key (will be disposed)
        /// </summary>
        [SensitiveData]
        public IKeyExchangePrivateKey? CounterKeyExchangeKey { get; set; }

        /// <summary>
        /// Counter key exchange private key usage count
        /// </summary>
        [Range(0, long.MaxValue)]
        public long CounterKeyExchangeKeyUsageCount { get; set; }

        /// <summary>
        /// Counter key exchange private key usage count maximum
        /// </summary>
        [Range(0, long.MaxValue)]
        public long MaxCounterKeyExchangeKeyUsageCount { get; set; } = long.MaxValue;

        /// <summary>
        /// Signature private key (will be disposed)
        /// </summary>
        [SensitiveData]
        public ISignaturePrivateKey? SignatureKey { get; set; }

        /// <summary>
        /// Signature private key usage count
        /// </summary>
        [Range(0, long.MaxValue)]
        public long SignatureKeyUsageCount { get; set; }

        /// <summary>
        /// Signature private key usage count maximum
        /// </summary>
        [Range(0, long.MaxValue)]
        public long MaxSignatureKeyUsageCount { get; set; } = long.MaxValue;

        /// <summary>
        /// Counter signature private key (will be disposed)
        /// </summary>
        [SensitiveData]
        public ISignaturePrivateKey? CounterSignatureKey { get; set; }

        /// <summary>
        /// Counter signature private key usage count
        /// </summary>
        [Range(0, long.MaxValue)]
        public long CounterSignatureKeyUsageCount { get; set; }

        /// <summary>
        /// Counter signature private key usage count maximum
        /// </summary>
        [Range(0, long.MaxValue)]
        public long MaxCounterSignatureKeyUsageCount { get; set; } = long.MaxValue;

        /// <summary>
        /// Signed public key (will be disposed)
        /// </summary>
        public AsymmetricSignedPublicKey? SignedPublicKey { get; set; }

        /// <summary>
        /// Signed public counter key (will be disposed)
        /// </summary>
        public AsymmetricSignedPublicKey? SignedPublicCounterKey { get; set; }

        /// <summary>
        /// Symmetric key (will be cleared)
        /// </summary>
        [SensitiveData, CountLimit(1, byte.MaxValue)]
        public byte[]? SymmetricKey { get; set; }

        /// <summary>
        /// Symmetric key usage count
        /// </summary>
        [Range(0, long.MaxValue)]
        public long SymmetricKeyUsageCount { get; set; }

        /// <summary>
        /// Symmetric key usage count
        /// </summary>
        [Range(0, long.MaxValue)]
        public long MaxSymmetricKeyUsageCount { get; set; } = long.MaxValue;

        /// <summary>
        /// Public key suite (will be disposed when this instance is being disposed)
        /// </summary>
        public PublicKeySuite Public => IfUndisposed(() => _Public ??= new()
        {
            KeyExchangeKey = KeyExchangeKey?.PublicKey.GetCopy(),
            CounterKeyExchangeKey = CounterKeyExchangeKey?.PublicKey.GetCopy(),
            SignatureKey = (ISignaturePublicKey?)SignatureKey?.PublicKey.GetCopy(),
            CounterSignatureKey = (ISignaturePublicKey?)CounterSignatureKey?.PublicKey.GetCopy(),
            SignedPublicKey = SignedPublicKey?.GetCopy(),
            SignedPublicCounterKey = SignedPublicCounterKey?.GetCopy()
        });

        /// <summary>
        /// If the private key suite has been used
        /// </summary>
        public bool WasUsed { get; private set; }

        /// <summary>
        /// Serialize and encrypt this private key suite for physical cold storage
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher</returns>
        public byte[] Encrypt(byte[] key, CryptoOptions? options = null) => ((byte[])this).Encrypt(key, options);

        /// <summary>
        /// Create crypto options
        /// </summary>
        /// <returns>Options</returns>
        public CryptoOptions CreateOptions()
        {
            EnsureUndisposed();
            CryptoOptions res = new();
            res.ApplyPrivateKeySuite(this);
            return res;
        }

        /// <inheritdoc/>
        public (byte[] Key, byte[] KeyExchangeData) GetKeyExchangeData()
        {
            EnsureUndisposed();
            return KeyExchangeKey?.GetKeyExchangeData() ?? throw new InvalidOperationException();
        }

        /// <inheritdoc/>
        public byte[] DeriveKey(byte[] keyExchangeData)
        {
            EnsureUndisposed();
            CountKeyExchangeKeyUsage();
            return KeyExchangeKey.DeriveKey(keyExchangeData) ?? throw new InvalidOperationException();
        }

        /// <summary>
        /// Count an asymmetric key usage
        /// </summary>
        /// <param name="key">Key</param>
        public void CountAsymmetricKeyUsage(in IAsymmetricPrivateKey key)
        {
            if (key == KeyExchangeKey) CountKeyExchangeKeyUsage();
            else if (key == CounterKeyExchangeKey) CountCounterKeyExchangeKeyUsage();
            else if (key == SignatureKey) CountSignatureKeyUsage();
            else if (key == CounterSignatureKey) CountCounterSignatureKeyUsage();
            else throw new ArgumentException("Unknown key", nameof(key));
        }

        /// <summary>
        /// Count key exchange key usage (thread-safe)
        /// </summary>
        /// <returns>Key</returns>
        [MemberNotNull(nameof(KeyExchangeKey))]
        public IKeyExchangePrivateKey CountKeyExchangeKeyUsage()
        {
            EnsureUndisposed();
            if (KeyExchangeKey is null) throw new InvalidOperationException();
            lock (SyncKeyExchangeKey)
            {
                if (KeyExchangeKeyUsageCount >= MaxKeyExchangeKeyUsageCount) throw new KeyUsageExceededException();
                if (KeyExchangeKeyUsageCount > KeyExchangeKey.Algorithm.MaxKeyUsageCount) throw new KeyUsageExceededException();
                KeyExchangeKeyUsageCount++;
            }
            WasUsed = true;
            return KeyExchangeKey;
        }

        /// <summary>
        /// Count counter key exchange key usage (thread-safe)
        /// </summary>
        /// <returns>Key</returns>
        [MemberNotNull(nameof(CounterKeyExchangeKey))]
        public IKeyExchangePrivateKey CountCounterKeyExchangeKeyUsage()
        {
            EnsureUndisposed();
            if (CounterKeyExchangeKey is null) throw new InvalidOperationException();
            lock (SyncCounterKeyExchangeKey)
            {
                if (CounterKeyExchangeKeyUsageCount >= MaxCounterKeyExchangeKeyUsageCount) throw new KeyUsageExceededException();
                if (CounterKeyExchangeKeyUsageCount > CounterKeyExchangeKey.Algorithm.MaxKeyUsageCount) throw new KeyUsageExceededException();
                CounterKeyExchangeKeyUsageCount++;
            }
            WasUsed = true;
            return CounterKeyExchangeKey;
        }

        /// <summary>
        /// Count signature key usage (thread-safe)
        /// </summary>
        /// <returns>Key</returns>
        [MemberNotNull(nameof(SignatureKey))]
        public ISignaturePrivateKey CountSignatureKeyUsage()
        {
            EnsureUndisposed();
            if (SignatureKey is null) throw new InvalidOperationException();
            lock (SyncSignatureKey)
            {
                if (SignatureKeyUsageCount >= MaxSignatureKeyUsageCount) throw new KeyUsageExceededException();
                if (SignatureKeyUsageCount > SignatureKey.Algorithm.MaxKeyUsageCount) throw new KeyUsageExceededException();
                SignatureKeyUsageCount++;
            }
            WasUsed = true;
            return SignatureKey;
        }

        /// <summary>
        /// Count counter signature key usage (thread-safe)
        /// </summary>
        /// <returns>Key</returns>
        [MemberNotNull(nameof(CounterSignatureKey))]
        public ISignaturePrivateKey CountCounterSignatureKeyUsage()
        {
            EnsureUndisposed();
            if (CounterSignatureKey is null) throw new InvalidOperationException();
            lock (SyncCounterSignatureKey)
            {
                if (CounterSignatureKeyUsageCount >= MaxCounterSignatureKeyUsageCount) throw new KeyUsageExceededException();
                if (CounterSignatureKeyUsageCount > CounterSignatureKey.Algorithm.MaxKeyUsageCount) throw new KeyUsageExceededException();
                CounterSignatureKeyUsageCount++;
            }
            WasUsed = true;
            return CounterSignatureKey;
        }

        /// <summary>
        /// Count counter signature key usage (thread-safe)
        /// </summary>
        /// <param name="usageLimit">Usage limit</param>
        /// <returns>Key</returns>
        public byte[] CountSymmetricKeyUsage(in ILimitKeyUsageCount? usageLimit = null)
        {
            EnsureUndisposed();
            if (SymmetricKey is null) throw new InvalidOperationException();
            lock (SyncSymmetricKey)
            {
                if (SymmetricKeyUsageCount >= MaxSymmetricKeyUsageCount) throw new KeyUsageExceededException();
                if (usageLimit is not null && SymmetricKeyUsageCount > usageLimit.MaxKeyUsageCount) throw new KeyUsageExceededException();
                SymmetricKeyUsageCount++;
            }
            WasUsed = true;
            return SymmetricKey;
        }

        /// <summary>
        /// Get a copy of this instance
        /// </summary>
        /// <returns>Instance copy</returns>
        public PrivateKeySuite GetCopy() => IfUndisposed(() => new PrivateKeySuite()
        {
            _Public = _Public?.GetCopy(),
            KeyExchangeKey = (IKeyExchangePrivateKey?)KeyExchangeKey?.GetCopy(),
            KeyExchangeKeyUsageCount = KeyExchangeKeyUsageCount,
            MaxKeyExchangeKeyUsageCount = MaxKeyExchangeKeyUsageCount,
            CounterKeyExchangeKey = (IKeyExchangePrivateKey?)CounterKeyExchangeKey?.GetCopy(),
            CounterKeyExchangeKeyUsageCount = CounterKeyExchangeKeyUsageCount,
            MaxCounterKeyExchangeKeyUsageCount = MaxCounterKeyExchangeKeyUsageCount,
            SignatureKey = (ISignaturePrivateKey?)SignatureKey?.GetCopy(),
            SignatureKeyUsageCount = SignatureKeyUsageCount,
            CounterSignatureKey = (ISignaturePrivateKey?)CounterSignatureKey?.GetCopy(),
            CounterSignatureKeyUsageCount = CounterSignatureKeyUsageCount,
            MaxCounterSignatureKeyUsageCount = MaxCounterSignatureKeyUsageCount,
            SignedPublicKey = SignedPublicKey?.GetCopy(),
            SignedPublicCounterKey = SignedPublicCounterKey?.GetCopy(),
            SymmetricKey = (byte[]?)SymmetricKey?.Clone(),
            SymmetricKeyUsageCount = SymmetricKeyUsageCount,
            MaxSymmetricKeyUsageCount = MaxSymmetricKeyUsageCount
        });

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            _Public?.Dispose();
            KeyExchangeKey?.Dispose();
            CounterKeyExchangeKey?.Dispose();
            SignatureKey?.Dispose();
            CounterSignatureKey?.Dispose();
            SignedPublicKey?.Dispose();
            SignedPublicCounterKey?.Dispose();
            SymmetricKey?.Clear();
        }

        /// <inheritdoc/>
        protected override Task DisposeCore()
        {
            _Public?.Dispose();
            KeyExchangeKey?.Dispose();
            CounterKeyExchangeKey?.Dispose();
            SignatureKey?.Dispose();
            CounterSignatureKey?.Dispose();
            SignedPublicKey?.Dispose();
            SignedPublicCounterKey?.Dispose();
            SymmetricKey?.Clear();
            return Task.CompletedTask;
        }

        /// <inheritdoc/>
        object ICloneable.Clone() => GetCopy();

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            stream.WriteBytesNullable(KeyExchangeKey?.Export())
                .WriteNumber(KeyExchangeKeyUsageCount)
                .WriteNumber(MaxKeyExchangeKeyUsageCount)
                .WriteBytesNullable(CounterKeyExchangeKey?.Export())
                .WriteNumber(CounterKeyExchangeKeyUsageCount)
                .WriteNumber(MaxCounterKeyExchangeKeyUsageCount)
                .WriteBytesNullable(SignatureKey?.Export())
                .WriteNumber(SignatureKeyUsageCount)
                .WriteNumber(MaxSignatureKeyUsageCount)
                .WriteBytesNullable(CounterSignatureKey?.Export())
                .WriteNumber(CounterSignatureKeyUsageCount)
                .WriteNumber(MaxCounterSignatureKeyUsageCount)
                .WriteSerializedNullable(SignedPublicKey)
                .WriteSerializedNullable(SignedPublicCounterKey)
                .WriteBytesNullable(SymmetricKey)
                .WriteNumber(SymmetricKeyUsageCount)
                .WriteNumber(MaxSymmetricKeyUsageCount);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            await stream.WriteBytesNullableAsync(KeyExchangeKey?.Export(), cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(KeyExchangeKeyUsageCount, cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(MaxKeyExchangeKeyUsageCount, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(CounterKeyExchangeKey?.Export(), cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(CounterKeyExchangeKeyUsageCount, cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(MaxCounterKeyExchangeKeyUsageCount, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(SignatureKey?.Export(), cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(SignatureKeyUsageCount, cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(MaxSignatureKeyUsageCount, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(CounterSignatureKey?.Export(), cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(CounterSignatureKeyUsageCount, cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(MaxCounterSignatureKeyUsageCount, cancellationToken).DynamicContext();
            await stream.WriteSerializedNullableAsync(SignedPublicKey, cancellationToken).DynamicContext();
            await stream.WriteSerializedNullableAsync(SignedPublicCounterKey, cancellationToken).DynamicContext();
            await stream.WriteBytesNullableAsync(SymmetricKey, cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(SymmetricKeyUsageCount, cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(MaxSymmetricKeyUsageCount, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            byte[]? keyData = stream.ReadBytesNullable(version, minLen: 1, maxLen: short.MaxValue)?.Value;
            try
            {
                if (keyData is not null) KeyExchangeKey = AsymmetricKeyBase.Import<IKeyExchangePrivateKey>(keyData);
                switch (SerializedObjectVersion!.Value)// Object version switch
                {
                    case 3:
                        KeyExchangeKeyUsageCount = stream.ReadNumber<long>(version);
                        MaxKeyExchangeKeyUsageCount = stream.ReadNumber<long>(version);
                        break;
                }
                keyData = stream.ReadBytesNullable(version, minLen: 1, maxLen: short.MaxValue)?.Value;
                if (keyData is not null) CounterKeyExchangeKey = AsymmetricKeyBase.Import<IKeyExchangePrivateKey>(keyData);
                switch (SerializedObjectVersion!.Value)// Object version switch
                {
                    case 3:
                        CounterKeyExchangeKeyUsageCount = stream.ReadNumber<long>(version);
                        MaxCounterKeyExchangeKeyUsageCount = stream.ReadNumber<long>(version);
                        break;
                }
                keyData = stream.ReadBytesNullable(version, minLen: 1, maxLen: short.MaxValue)?.Value;
                if (keyData is not null) SignatureKey = AsymmetricKeyBase.Import<ISignaturePrivateKey>(keyData);
                switch (SerializedObjectVersion!.Value)// Object version switch
                {
                    case 3:
                        SignatureKeyUsageCount = stream.ReadNumber<long>(version);
                        MaxSignatureKeyUsageCount = stream.ReadNumber<long>(version);
                        break;
                }
                keyData = stream.ReadBytesNullable(version, minLen: 1, maxLen: short.MaxValue)?.Value;
                if (keyData is not null) CounterSignatureKey = AsymmetricKeyBase.Import<ISignaturePrivateKey>(keyData);
                switch (SerializedObjectVersion!.Value)// Object version switch
                {
                    case 3:
                        CounterSignatureKeyUsageCount = stream.ReadNumber<long>(version);
                        MaxCounterSignatureKeyUsageCount = stream.ReadNumber<long>(version);
                        break;
                }
            }
            catch
            {
                keyData?.Clear();
                throw;
            }
            SignedPublicKey = stream.ReadSerializedNullable<AsymmetricSignedPublicKey>(version);
            switch (SerializedObjectVersion!.Value)// Object version switch
            {
                case 2:
                case 3:
                    SignedPublicCounterKey = stream.ReadSerializedNullable<AsymmetricSignedPublicKey>(version);
                    break;
            }
            SymmetricKey = stream.ReadBytesNullable(version, minLen: 1, maxLen: byte.MaxValue)?.Value;
            switch (SerializedObjectVersion!.Value)// Object version switch
            {
                case 3:
                    SymmetricKeyUsageCount = stream.ReadNumber<long>(version);
                    MaxSymmetricKeyUsageCount = stream.ReadNumber<long>(version);
                    break;
            }
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            byte[]? keyData = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: short.MaxValue, cancellationToken: cancellationToken).DynamicContext())?.Value;
            IAsymmetricKey? key = null;
            try
            {
                if (keyData is not null) KeyExchangeKey = AsymmetricKeyBase.Import<IKeyExchangePrivateKey>(keyData);
                switch (SerializedObjectVersion!.Value)// Object version switch
                {
                    case 3:
                        KeyExchangeKeyUsageCount = await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext();
                        MaxKeyExchangeKeyUsageCount = await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext();
                        break;
                }
                keyData = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: short.MaxValue, cancellationToken: cancellationToken).DynamicContext())?.Value;
                if (keyData is not null) CounterKeyExchangeKey = AsymmetricKeyBase.Import<IKeyExchangePrivateKey>(keyData);
                switch (SerializedObjectVersion!.Value)// Object version switch
                {
                    case 3:
                        CounterKeyExchangeKeyUsageCount = await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext();
                        MaxCounterKeyExchangeKeyUsageCount = await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext();
                        break;
                }
                keyData = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: short.MaxValue, cancellationToken: cancellationToken).DynamicContext())?.Value;
                if (keyData is not null) SignatureKey = AsymmetricKeyBase.Import<ISignaturePrivateKey>(keyData);
                switch (SerializedObjectVersion!.Value)// Object version switch
                {
                    case 3:
                        SignatureKeyUsageCount = await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext();
                        MaxSignatureKeyUsageCount = await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext();
                        break;
                }
                keyData = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: short.MaxValue, cancellationToken: cancellationToken).DynamicContext())?.Value;
                if (keyData is not null) CounterSignatureKey = AsymmetricKeyBase.Import<ISignaturePrivateKey>(keyData);
                switch (SerializedObjectVersion!.Value)// Object version switch
                {
                    case 3:
                        CounterSignatureKeyUsageCount = await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext();
                        MaxCounterSignatureKeyUsageCount = await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext();
                        break;
                }
            }
            catch
            {
                key?.Dispose();
                keyData?.Clear();
                throw;
            }
            SignedPublicKey = await stream.ReadSerializedNullableAsync<AsymmetricSignedPublicKey>(version, cancellationToken).DynamicContext();
            switch (SerializedObjectVersion!.Value)// Object version switch
            {
                case 2:
                    SignedPublicCounterKey = await stream.ReadSerializedNullableAsync<AsymmetricSignedPublicKey>(version, cancellationToken).DynamicContext();
                    break;
            }
            SymmetricKey = (await stream.ReadBytesNullableAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext())?.Value;
            switch (SerializedObjectVersion!.Value)// Object version switch
            {
                case 3:
                    SymmetricKeyUsageCount = await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext();
                    MaxSymmetricKeyUsageCount = await stream.ReadNumberAsync<long>(version, cancellationToken: cancellationToken).DynamicContext();
                    break;
            }
        }

        /// <summary>
        /// Cast as public key suite
        /// </summary>
        /// <param name="suite">Private key suite</param>
        public static implicit operator PublicKeySuite(PrivateKeySuite suite) => suite.Public;

        /// <summary>
        /// Cast as asymmetric signed public key
        /// </summary>
        /// <param name="suite">Private key suite</param>
        public static implicit operator AsymmetricSignedPublicKey(PrivateKeySuite suite) => suite.SignedPublicKey ?? throw new InvalidOperationException("No signed public key");

        /// <summary>
        /// Cast as serialized data
        /// </summary>
        /// <param name="suite">Private key suite</param>
        public static implicit operator byte[](PrivateKeySuite suite) => suite.ToBytes();

        /// <summary>
        /// Cast from serialized data
        /// </summary>
        /// <param name="data">Data</param>
        public static explicit operator PrivateKeySuite(byte[] data) => data.ToObject<PrivateKeySuite>();

        /// <summary>
        /// Create a private key suite with new key exchange, signature and symmetric keys
        /// </summary>
        /// <returns>Private key suite</returns>
        public static PrivateKeySuite Create() => new PrivateKeySuite()
            .WithKeyExchangeKey()
            .WithSignatureKey()
            .WithSymmetricKey();

        /// <summary>
        /// Create a private key suite with new key exchange, signature and symmetric keys (and new counter algorithm keys)
        /// </summary>
        /// <returns>Private key suite</returns>
        public static PrivateKeySuite CreateWithCounterAlgorithms() => new PrivateKeySuite()
            .WithKeyExchangeKey()
            .WithCounterKeyExchangeKey()
            .WithSignatureKey()
            .WithCounterSignatureKey()
            .WithSymmetricKey();

        /// <summary>
        /// Decrypt a private key suite cipher and deserialize to a private key suite instance
        /// </summary>
        /// <param name="cipher">Cipher</param>
        /// <param name="key">Key</param>
        /// <param name="options">Options</param>
        /// <returns>Private key suite</returns>
        public static PrivateKeySuite Decrypt(byte[] cipher, byte[] key, CryptoOptions? options = null) => (PrivateKeySuite)cipher.Decrypt(key, options);
    }
}
