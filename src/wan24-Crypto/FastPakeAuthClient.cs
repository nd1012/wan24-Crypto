using wan24.Core;
using wan24.Crypto.Authentication;
using static wan24.Core.TranslationHelper;

namespace wan24.Crypto
{
    /// <summary>
    /// Fast PAKE authentication client (will skip KDF after initialization)
    /// </summary>
    public sealed class FastPakeAuthClient : DisposableBase, IStatusProvider
    {
        /// <summary>
        /// PAKE instance
        /// </summary>
        private readonly Pake Pake = null!;
        /// <summary>
        /// Authentication counter
        /// </summary>
        private volatile int _AuthCount = 0;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Key (will be disposed!)</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time; default is <see cref="SecureValue.DefaultEncryptTimeout"/>)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example; default is <see cref="SecureValue.DefaultRecryptTimeout"/>)</param>
        /// <param name="options">PAKE options (will be cleared!)</param>
        /// <param name="cryptoOptions">Options for encryption (will be cleared!)</param>
        /// <param name="name">Client name</param>
        public FastPakeAuthClient(
            in ISymmetricKeySuite key,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in CryptoOptions? options = null,
            in CryptoOptions? cryptoOptions = null,
            in string? name = null
            )
            : base()
        {
            byte[] authKey = null!,
                secret = null!;
            try
            {
                options?.ValidateAlgorithms();
                cryptoOptions?.ValidateAlgorithms();
                Name = name;
                Pake = new(key, options, cryptoOptions);
                Key = new(Pake.CreateAuthKey(), encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth client {GUID} (\"{Name}\") key"
                };
                authKey = Key;
                Secret = new(Pake.CreateSecret(authKey), encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth client {GUID} (\"{Name}\") secret"
                };
                secret = Secret;
                SignatureKey = new(Pake.CreateSignatureKey(authKey, secret), encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth client {GUID} (\"{Name}\") signature key"
                };
            }
            catch (Exception ex)
            {
                Dispose();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                authKey?.Clear();
                secret?.Clear();
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="pake">PAKE instance (will be disposed!)</param>
        /// <param name="signup">PAKE signup (should be disposed!)</param>
        /// <param name="sessionKey">Session key (should be cleared!)</param>
        /// <param name="payload">Payload</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time; default is <see cref="SecureValue.DefaultEncryptTimeout"/>)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example; default is <see cref="SecureValue.DefaultRecryptTimeout"/>)</param>
        /// <param name="name">Client name</param>
        /// <param name="payloadFactory">Payload factory</param>
        public FastPakeAuthClient(
            in Pake pake,
            out PakeSignup signup,
            out byte[] sessionKey,
            byte[]? payload = null,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in string? name = null,
            in Pake.PayloadFactory_Delegate? payloadFactory = null
            )
            : base()
        {
            byte[] authKey = null!,
                secret = null!,
                random = null!,
                signatureKey = null!,
                signature = null!;
            try
            {
                Name = name;
                Pake = pake;
                if (pake.Key?.Identifier is null) throw new ArgumentException("Initialized for server operation", nameof(pake));
                Key = new(Pake.CreateAuthKey(), encryptTimeout, recryptTimeout, pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth client {GUID} (\"{Name}\") key"
                };
                authKey = Key;
                Secret = new(Pake.CreateSecret(authKey), encryptTimeout, recryptTimeout, pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth client {GUID} (\"{Name}\") secret"
                };
                secret = Secret;
                SignatureKey = new(Pake.CreateSignatureKey(authKey, secret), encryptTimeout, recryptTimeout, pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth client {GUID} (\"{Name}\") signature key"
                };
                signatureKey = SignatureKey;
                random = RND.GetBytes(pake.Key.ExpandedKey.Length);
                if (payloadFactory is not null) payload = payloadFactory(Pake, random, payload);
                (signature, sessionKey) = pake.SignAndCreateSessionKey2(signatureKey, authKey, random, payload ?? [], secret);// MAC
                pake.ClearSessionKey();
                signup = new PakeSignup(pake.Key.Identifier.CloneArray(), secret, authKey, signature, random, payload);
            }
            catch (Exception ex)
            {
                random?.Clear();
                signature?.Clear();
                payload?.Clear();
                authKey?.Clear();
                secret?.Clear();
                Dispose();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                signatureKey?.Clear();
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Key (will be disposed!)</param>
        /// <param name="authKey">Authentication key (will be cleared!)</param>
        /// <param name="secret">Secret (will be cleared!)</param>
        /// <param name="signatureKey">Signature key (will be cleared!)</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time; default is <see cref="SecureValue.DefaultEncryptTimeout"/>)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example; default is <see cref="SecureValue.DefaultRecryptTimeout"/>)</param>
        /// <param name="options">PAKE options (will be cleared!)</param>
        /// <param name="cryptoOptions">Options for encryption (will be cleared!)</param>
        /// <param name="name">Client name</param>
        public FastPakeAuthClient(
            in ISymmetricKeySuite key,
            in byte[] authKey,
            in byte[] secret,
            in byte[] signatureKey,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in CryptoOptions? options = null,
            in CryptoOptions? cryptoOptions = null,
            in string? name = null
            )
            : base()
        {
            try
            {
                options?.ValidateAlgorithms();
                cryptoOptions?.ValidateAlgorithms();
                Name = name;
                Pake = new(key, options, cryptoOptions);
                Key = new(authKey, encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth client {GUID} (\"{Name}\") key"
                };
                Secret = new(secret, encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth client {GUID} (\"{Name}\") secret"
                };
                SignatureKey = new(signatureKey, encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth client {GUID} (\"{Name}\") signature key"
                };
            }
            catch (Exception ex)
            {
                Dispose();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="record">PAKE authentication record</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time; default is <see cref="SecureValue.DefaultEncryptTimeout"/>)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example; default is <see cref="SecureValue.DefaultRecryptTimeout"/>)</param>
        /// <param name="options">PAKE options (will be cleared!)</param>
        /// <param name="cryptoOptions">Options for encryption (will be cleared!)</param>
        /// <param name="name">Client name</param>
        public FastPakeAuthClient(
            in IPakeAuthRecord record,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in CryptoOptions? options = null,
            in CryptoOptions? cryptoOptions = null,
            in string? name = null
            )
            : base()
        {
            try
            {
                options?.ValidateAlgorithms();
                cryptoOptions?.ValidateAlgorithms();
                Name = name;
                Pake = new(new SymmetricKeySuite(cryptoOptions, record.Identifier.CloneArray(), []), options, cryptoOptions);
                Key = new(record.Key.CloneArray(), encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth client {GUID} (\"{Name}\") key"
                };
                Secret = new(record.RawSecret.CloneArray(), encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth client {GUID} (\"{Name}\") secret"
                };
                SignatureKey = new(record.SignatureKey.CloneArray(), encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth client {GUID} (\"{Name}\") signature key"
                };
            }
            catch (Exception ex)
            {
                Dispose();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// GUID
        /// </summary>
        public string GUID { get; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Name
        /// </summary>
        public string? Name { get; set; }

        /// <summary>
        /// Authentication count (including errors)
        /// </summary>
        public int AuthCount => _AuthCount;

        /// <summary>
        /// Key
        /// </summary>
        public SecureValue Key { get; } = null!;

        /// <summary>
        /// Secret
        /// </summary>
        public SecureValue Secret { get; } = null!;

        /// <summary>
        /// Signature key
        /// </summary>
        public SecureValue SignatureKey { get; } = null!;

        /// <inheritdoc/>
        public IEnumerable<Status> State
        {
            get
            {
                yield return new(__("GUID"), GUID, __("Unique ID of this PAKE client"));
                yield return new(__("Name"), Name, __("Name of this PAKE client"));
                yield return new(__("Identifier"), Convert.ToHexString(Pake.Identifier), __("Client identifier"));
                yield return new(__("Count"), _AuthCount, __("Authentication count since initialization"));
            }
        }

        /// <summary>
        /// Create an authentication
        /// </summary>
        /// <param name="payload">Payload (max. <see cref="ushort.MaxValue"/> length; will be cleared!)</param>
        /// <param name="encryptPayload">Encrypt the payload?</param>
        /// <param name="payloadFactory">Payload factory</param>
        /// <returns>Authentication (send this to the server and don't forget to dispose!) and session key (should be cleared!)</returns>
        public (PakeAuth Auth, byte[] SessionKey) CreateAuth(
            byte[]? payload = null, 
            in bool encryptPayload = false, 
            in Pake.PayloadFactory_Delegate? payloadFactory = null
            )
        {
            byte[] random = null!,
                randomMac = null!,
                key = null!,
                signatureKey = null!,
                secret = null!,
                signature = null!,
                sessionKey = null!;
            try
            {
                EnsureUndisposed();
                _AuthCount++;
                if (Pake.Key?.Identifier is null) throw CryptographicException.From(new InvalidOperationException("Initialized for server operation or missing identifier"));
                random = RND.GetBytes(Pake.Key.Identifier.Length);
                if (payloadFactory is not null) payload = payloadFactory(Pake, random, payload);
                signatureKey = SignatureKey;
                randomMac = random.Mac(signatureKey, Pake.Options);
                if (encryptPayload && payload is not null)
                {
                    byte[] temp = payload;
                    try
                    {
                        payload = Pake.EncryptPayload(payload, randomMac);
                    }
                    finally
                    {
                        temp.Clear();
                    }
                }
                key = Key;
                secret = Secret;
                (signature, sessionKey) = Pake.SignAndCreateSessionKey2(signatureKey, key, random, payload ?? [], secret);// MAC
                return (new PakeAuth(Pake.Key.Identifier.CloneArray(), key.CloneArray().Xor(randomMac), signature, random, payload), sessionKey);
            }
            catch (Exception ex)
            {
                random?.Clear();
                signature?.Clear();
                payload?.Clear();
                sessionKey?.Clear();
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
        /// Create an authentication
        /// </summary>
        /// <param name="payload">Payload (max. <see cref="ushort.MaxValue"/> length; will be cleared!)</param>
        /// <param name="encryptPayload">Encrypt the payload?</param>
        /// <param name="payloadFactory">Payload factory</param>
        /// <returns>Authentication (send this to the server and don't forget to dispose!) and session key (should be cleared!)</returns>
        public async Task<(PakeAuth Auth, byte[] SessionKey)> CreateAuthAsync(
            byte[]? payload = null, 
            bool encryptPayload = false,
            Pake.PayloadFactory_Delegate? payloadFactory = null
            )
        {
            byte[] random = null!,
                randomMac = null!,
                key = null!,
                signatureKey = null!,
                secret = null!,
                signature = null!,
                sessionKey = null!;
            try
            {
                EnsureUndisposed();
                _AuthCount++;
                if (Pake.Key?.Identifier is null)
                    throw await CryptographicException.FromAsync(new InvalidOperationException("Initialized for server operation or missing identifier")).DynamicContext();
                random = await RND.GetBytesAsync(Pake.Key.Identifier.Length).DynamicContext();
                if (payloadFactory is not null) payload = payloadFactory(Pake, random, payload);
                signatureKey = SignatureKey;
                randomMac = random.Mac(signatureKey, Pake.Options);
                if (encryptPayload && payload is not null)
                {
                    byte[] temp = payload;
                    try
                    {
                        payload = Pake.EncryptPayload(payload, randomMac);
                    }
                    finally
                    {
                        temp.Clear();
                    }
                }
                key = Key;
                secret = Secret;
                (signature, sessionKey) = Pake.SignAndCreateSessionKey2(signatureKey, key, random, payload ?? [], secret);// MAC
                return (new PakeAuth(Pake.Key.Identifier.CloneArray(), key.CloneArray().Xor(randomMac), signature, random, payload), sessionKey);
            }
            catch (Exception ex)
            {
                random?.Clear();
                signature?.Clear();
                payload?.Clear();
                sessionKey?.Clear();
                if (ex is CryptographicException) throw;
                throw await CryptographicException.FromAsync(ex).DynamicContext();
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
        /// Create a PAKE authentication record from this instance
        /// </summary>
        /// <returns>Record (don't forget to clear!)</returns>
        public PakeAuthRecord CreateAuthRecord()
        {
            EnsureUndisposed();
            return new(Pake.Key!.Identifier!.CloneArray(), Secret, Key, SignatureKey);
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Secret?.Dispose();
            Key?.Dispose();
            SignatureKey?.Dispose();
            Pake?.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            if (Secret is not null) await Secret.DisposeAsync().DynamicContext();
            if (Key is not null) await Key.DisposeAsync().DynamicContext();
            if (SignatureKey is not null) await SignatureKey.DisposeAsync().DynamicContext();
            if (Pake is not null) await Pake.DisposeAsync().DynamicContext();
        }
    }
}
