using System.Runtime.CompilerServices;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Fast PAKE authentication client (NOT thread-safe!)
    /// </summary>
    public sealed class FastPakeAuthClient : DisposableBase
    {
        /// <summary>
        /// Key
        /// </summary>
        private readonly SecureValue Key;
        /// <summary>
        /// Secret
        /// </summary>
        private readonly SecureValue Secret;
        /// <summary>
        /// Signature key
        /// </summary>
        private readonly SecureValue SignatureKey;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Key (will be disposed!)</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time; default is <see cref="SecureValue.DefaultEncryptTimeout"/>)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example; default is <see cref="SecureValue.DefaultRecryptTimeout"/>)</param>
        /// <param name="options">PAKE options (will be cleared!)</param>
        /// <param name="cryptoOptions">Options for encryption (will be cleared!)</param>
        public FastPakeAuthClient(
            in ISymmetricKeySuite key,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in CryptoOptions? options = null,
            CryptoOptions? cryptoOptions = null
            )
            : base(asyncDisposing: false)
        {
            cryptoOptions ??= Pake.DefaultCryptoOptions;
            Pake = new(key, options, cryptoOptions);
            Key = new(Pake.CreateAuthKey(), encryptTimeout, recryptTimeout, cryptoOptions.Clone());
            Secret = new(Pake.CreateSecret(Key), encryptTimeout, recryptTimeout, cryptoOptions.Clone());
            SignatureKey = new(Pake.CreateSignatureKey(Key, Secret), encryptTimeout, recryptTimeout, cryptoOptions.Clone());
        }

        /// <summary>
        /// External thread synchronizaion
        /// </summary>
        public SemaphoreSync Sync { get; } = new();

        /// <summary>
        /// PAKE instance
        /// </summary>
        public Pake Pake { get; }

        /// <summary>
        /// Identifier
        /// </summary>
        public byte[] Identifier
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => Pake.Identifier;
        }

        /// <summary>
        /// Has a session key?
        /// </summary>
        public bool HasSession
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => Pake.HasSession;
        }

        /// <summary>
        /// Session key (available after authentication; will be cleared!)
        /// </summary>
        [SensitiveData]
        public byte[] SessionKey
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => Pake.SessionKey;
        }

        /// <summary>
        /// Create an authentication
        /// </summary>
        /// <param name="payload">Payload (max. <see cref="ushort.MaxValue"/> length; will be cleared!)</param>
        /// <param name="encryptPayload">Encrypt the payload?</param>
        /// <returns>Authentication (send this to the server and don't forget to dispose!)</returns>
        public PakeAuth CreateAuth(byte[]? payload = null, in bool encryptPayload = false)
        {
            EnsureUndisposed();
            if (Pake.Key?.Identifier is null) throw CryptographicException.From(new InvalidOperationException("Initialized for server operation or missing identifier"));
            byte[] random = RND.GetBytes(Pake.Key.ExpandedKey.Length),
                randomMac = null!,
                key = null!,
                signatureKey = null!,
                secret = null!,
                signature = null!;
            try
            {
                signatureKey = SignatureKey;
                randomMac = random.Mac(signatureKey, Pake.Options);
                if (encryptPayload && payload is not null)
                {
                    byte[] temp = payload;
                    try
                    {
                        payload = payload.Encrypt(randomMac, Pake.CryptoOptions);
                    }
                    finally
                    {
                        temp.Clear();
                    }
                }
                key = Key;
                secret = Secret;
                signature = Pake.SignAndCreateSessionKey(signatureKey, key, random, payload ?? Array.Empty<byte>(), secret);// MAC
                return new PakeAuth(Identifier.CloneArray(), Key.Value.Xor(randomMac), signature, random, payload);
            }
            catch (Exception ex)
            {
                random.Clear();
                signature?.Clear();
                payload?.Clear();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                randomMac?.Clear();
                key?.Clear();
                secret?.Clear();
                signatureKey?.Clear();
            }
        }

        /// <summary>
        /// Clear the session key
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void ClearSessionKey() => Pake.ClearSessionKey();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Pake.Dispose();
            Secret.Dispose();
            Key.Dispose();
            SignatureKey.Dispose();
            Sync.Dispose();
        }
    }
}
