using wan24.Core;
using wan24.Crypto.Authentication;

namespace wan24.Crypto
{
    /// <summary>
    /// Fast PAKE authentication server (will skip KDF after initialization)
    /// </summary>
    public sealed class FastPakeAuthServer : DisposableBase, IStatusProvider
    {
        /// <summary>
        /// Authentication counter
        /// </summary>
        private volatile int _AuthCount = 0;
        /// <summary>
        /// Authentication error counter
        /// </summary>
        private volatile int _AuthErrorCount = 0;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="pake">PAKE instance (will be disposed!)</param>
        /// <param name="auth">Authentication (will be disposed!)</param>
        /// <param name="payload">Payload (should be cleared!)</param>
        /// <param name="sessionKey">Session key (should be cleared!)</param>
        /// <param name="decryptPayload">Decrypt the payload (if any)?</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time; default is <see cref="SecureValue.DefaultEncryptTimeout"/>)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example; default is <see cref="SecureValue.DefaultRecryptTimeout"/>)</param>
        /// <param name="name">Server name</param>
        public FastPakeAuthServer(
            in Pake pake,
            in PakeAuth auth,
            out byte[] payload,
            out byte[] sessionKey,
            in bool decryptPayload = false,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in string? name = null
            )
            : base()
        {
            payload = null!;
            sessionKey = null!;
            byte[]? randomMac = null;
            try
            {
                Name = name;
                if (pake.Key is not null) throw CryptographicException.From(new ArgumentException("Initialized for client operation", nameof(pake)));
                if (pake.Identity is null) throw CryptographicException.From(new ArgumentException("Identity record required", nameof(pake)));
                Pake = pake;
                // Decrypt the payload
                if (decryptPayload && auth.Payload.Length != 0)
                {
                    if (Pake.Identity is null) throw CryptographicException.From(new InvalidOperationException("Unknown identity"));
                    randomMac = auth.Random.Mac(Pake.Identity.SignatureKey, Pake.Options);
                    try
                    {
                        payload = pake.DecryptPayload(auth.Payload, randomMac);
                    }
                    finally
                    {
                        randomMac.Clear();
                    }
                }
                // Run pre-actions
                Pake.PakeServerEventArgs e = new(auth, payload);
                Pake.RaiseOnAuth(e);
                if (e.NewIdentity is not null)
                {
                    Pake.ClearIdentity();
                    Pake.Identity = e.NewIdentity;
                }
                // Validate pre-conditions
                if (Pake.Identity is null) throw CryptographicException.From(new InvalidOperationException("Unknown identity"));
                if (!Pake.Identity.Identifier.SlowCompare(auth.Identifier)) throw CryptographicException.From(new InvalidDataException("Identity mismatch"));
                byte[] key = null!,
                    secret = null!,
                    signatureKey = null!,
                    signature = null!;
                int len = auth.Identifier.Length;
                try
                {
                    // Validate the auth values lengths
                    if (auth.Key.Length != len || auth.Signature.Length != len || auth.Random.Length != len)
                        throw CryptographicException.From(new InvalidDataException("Value lengths invalid"));
                    // Apply RNG seeding
                    if (((Pake.CryptoOptions.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.Random) == RngSeedingTypes.Random)
                        RND.AddSeed(auth.Random);
                    // Extract key and secret
                    randomMac ??= auth.Random.Mac(Pake.Identity.SignatureKey);
                    key = auth.Key.CloneArray().Xor(randomMac);
                    secret = Pake.Identity.Secret.CloneArray().Xor(key);
                    // Validate the signature and create the session key (MAC)
                    signature = Pake.SignAndCreateSessionKey(Pake.Identity.SignatureKey, key, auth.Random, auth.Payload, secret);
                    if (!auth.Signature.SlowCompare(signature))
                        throw CryptographicException.From(new InvalidDataException("Signature validation failed"));
                    // Validate the signature key (KDF)
                    signatureKey = Pake.CreateSignatureKey(key, secret);
                    if (!Pake.Identity.SignatureKey.SlowCompare(signatureKey))
                        throw CryptographicException.From(new InvalidDataException("Authentication key validation failed"));
                    // Store the session key
                    sessionKey = Pake.SessionKey.CloneArray();
                    // Store the authentication key and the secret to this instance
                    Key = new(key, encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                    {
                        Name = $"Fast PAKE auth server {GUID} (\"{Name}\") key"
                    };
                    Secret = new(secret, encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                    {
                        Name = $"Fast PAKE auth server {GUID} (\"{Name}\") secret"
                    };
                    SignatureKey = new(signatureKey, encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                    {
                        Name = $"Fast PAKE auth server {GUID} (\"{Name}\") signature key"
                    };
                }
                catch
                {
                    key?.Clear();
                    secret?.Clear();
                    throw;
                }
                finally
                {
                    signatureKey?.Clear();
                    signature?.Clear();
                }
            }
            catch (Exception ex)
            {
                payload?.Clear();
                Dispose();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                auth.Dispose();
                randomMac?.Clear();
            }
            FastPakeAuthServerTable.Servers[GUID] = this;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="signup">Signup (will be disposed!)</param>
        /// <param name="identity">Identity (should be cleared!)</param>
        /// <param name="payload">Payload (should be cleared!)</param>
        /// <param name="sessionKey">Session key (should be cleared!)</param>
        /// <param name="pake">PAKE instance (will be disposed!)</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example)</param>
        /// <param name="name">Server name</param>
        public FastPakeAuthServer(
            in PakeSignup signup,
            out PakeRecord identity, 
            out byte[] payload,
            out byte[] sessionKey,
            in Pake? pake = null,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in string? name = null
            )
            : base()
        {
            payload = signup.Payload.CloneArray();
            sessionKey = null!;
            identity = null!;
            try
            {
                _AuthCount = 1;
                Name = name;
                Pake = pake ?? new();
                if (Pake.Key is not null) throw CryptographicException.From(new ArgumentException("Initialized for client operation", nameof(pake)));
                byte[] signatureKey = null!,
                    signature = null!;
                int len = MacHelper.GetAlgorithm(Pake.Options.MacAlgorithm!).MacLength;
                try
                {
                    // Validate the signup values lengths
                    if (signup.Identifier.Length != len || signup.Secret.Length != len || signup.Key.Length != len || signup.Signature.Length != len || signup.Random.Length != len)
                        throw CryptographicException.From(new InvalidDataException("Value lengths invalid"));
                    // Reset the PAKE instance
                    Pake.ClearSessionKey();
                    Pake.ClearIdentity();
                    // Apply RNG seeding
                    if (((Pake.CryptoOptions.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.Random) == RngSeedingTypes.Random)
                        RND.AddSeed(signup.Random);
                    // Create the identity (KDF)
                    signatureKey = Pake.CreateSignatureKey(signup.Key, signup.Secret);
                    Pake.Identity = new PakeRecord(signup, signatureKey);
                    Pake.PakeServerEventArgs e = new(signup);
                    Pake.RaiseOnSignup(e);
                    if (e.NewIdentity is not null)
                    {
                        Pake.ClearIdentity();
                        Pake.Identity = e.NewIdentity;
                    }
                    // Validate the signature and create the session key (MAC)
                    signature = Pake.SignAndCreateSessionKey(signatureKey, signup.Key, signup.Random, signup.Payload, signup.Secret);
                    if (!signup.Signature.SlowCompare(signature))
                        throw CryptographicException.From(new InvalidDataException("Signature validation failed"));
                    // Create the session key
                    sessionKey = Pake.SessionKey.CloneArray();
                    // Create the identity
                    identity = new(signup.Identifier.CloneArray(), signup.Secret.CloneArray().Xor(signup.Key), signatureKey.CloneArray());
                    // Store the authentication key and the secret to this instance
                    Key = new(signup.Key.CloneArray(), encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                    {
                        Name = $"Fast PAKE auth server {GUID} (\"{Name}\") key"
                    };
                    Secret = new(signup.Secret.CloneArray(), encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                    {
                        Name = $"Fast PAKE auth server {GUID} (\"{Name}\") secret"
                    };
                    SignatureKey = new(signatureKey, encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                    {
                        Name = $"Fast PAKE auth server {GUID} (\"{Name}\") signature key"
                    };
                }
                catch
                {
                    payload.Clear();
                    signatureKey?.Clear();
                    identity?.Clear();
                    throw;
                }
                finally
                {
                    signature?.Clear();
                }
            }
            catch (Exception ex)
            {
                Dispose();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                signup.Dispose();
            }
            FastPakeAuthServerTable.Servers[GUID] = this;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="identity">Identity (will be cleared/disposed!)</param>
        /// <param name="authKey">Authentication key (will be cleared!)</param>
        /// <param name="secret">Secret (will be cleared!)</param>
        /// <param name="signatureKey">Signature key (will be cleared!)</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time; default is <see cref="SecureValue.DefaultEncryptTimeout"/>)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example; default is <see cref="SecureValue.DefaultRecryptTimeout"/>)</param>
        /// <param name="options">PAKE options (will be cleared!)</param>
        /// <param name="cryptoOptions">Options for encryption (will be cleared!)</param>
        /// <param name="name">Server name</param>
        public FastPakeAuthServer(
            in IPakeRecord identity,
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
                Name = name;
                Pake = new(identity, options, cryptoOptions);
                Key = new(authKey, encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth server {GUID} (\"{Name}\") key"
                };
                Secret = new(secret, encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth server {GUID} (\"{Name}\") secret"
                };
                SignatureKey = new(signatureKey, encryptTimeout, recryptTimeout, Pake.CryptoOptions.GetCopy())
                {
                    Name = $"Fast PAKE auth server {GUID} (\"{Name}\") signature key"
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
        /// External thread synchronization
        /// </summary>
        public SemaphoreSync Sync { get; } = new();

        /// <summary>
        /// Use the external thread synchronization during the <c>HandleAuth*</c> methods to synchronize any identity access?
        /// </summary>
        public bool UseSync { get; set; }

        /// <summary>
        /// GUID
        /// </summary>
        public string GUID { get; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Name
        /// </summary>
        public string? Name { get; set; }

        /// <summary>
        /// PAKE instance
        /// </summary>
        public Pake Pake { get; } = null!;

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

        /// <summary>
        /// Authentication count (including errors)
        /// </summary>
        public int AuthCount => _AuthCount;

        /// <summary>
        /// Authentication error count
        /// </summary>
        public int AuthErrorCount => _AuthErrorCount;

        /// <inheritdoc/>
        public IEnumerable<Status> State
        {
            get
            {
                yield return new("GUID", GUID, "Unique ID of the fast PAKE server");
                yield return new("Name", Name, "Name of the fast PAKE server");
                yield return new("Identifier", Convert.ToHexString(Pake.Identifier), "Peer identifier");
                yield return new("Count", _AuthCount, "Authentication count since initialization");
                yield return new("Errors", _AuthErrorCount, "Authentication error count since initialization");
            }
        }

        /// <summary>
        /// Handle an authentication
        /// </summary>
        /// <param name="auth">Authentication (will be disposed!)</param>
        /// <param name="decryptPayload">Decrypt the payload, if any? (for this the identity must be available already when calling this method!)</param>
        /// <returns>Payload and session key (should be cleared!)</returns>
        /// <exception cref="InvalidDataException">Invalid authentication record</exception>
        public (byte[] Payload, byte[] SessionKey) HandleAuth(in IPakeRequest auth, in bool decryptPayload = false)
        {
            byte[]? payload = null,
                randomMac = null,
                sessionKey = null;
            SemaphoreSyncContext? ssc = null;
            try
            {
                EnsureUndisposed();
                if (UseSync) ssc = Sync;
                _AuthCount++;
                // Decrypt the payload
                if (decryptPayload && auth.Payload.Length != 0)
                {
                    if (Pake.Identity is null) throw CryptographicException.From(new InvalidOperationException("Unknown identity"));
                    randomMac = auth.Random.Mac(Pake.Identity.SignatureKey, Pake.Options);
                    try
                    {
                        payload = Pake.DecryptPayload(auth.Payload, randomMac);
                    }
                    finally
                    {
                        randomMac.Clear();
                    }
                }
                // Run pre-actions
                Pake.PakeServerEventArgs e = new(auth, payload);
                Pake.RaiseOnAuth(e);
                if (e.NewIdentity is not null)
                {
                    Pake.ClearIdentity();
                    Pake.Identity = e.NewIdentity;
                }
                // Validate pre-conditions
                if (Pake.Identity is null) throw CryptographicException.From(new InvalidOperationException("Unknown identity"));
                if (!Pake.Identity.Identifier.SlowCompare(auth.Identifier)) throw CryptographicException.From(new InvalidDataException("Identity mismatch"));
                byte[] key = null!,
                    secret = null!,
                    signature = null!;
                int len = auth.Identifier.Length;
                try
                {
                    // Validate the auth values lengths
                    if (auth.Key.Length != len || auth.Signature.Length != len || auth.Random.Length != len)
                        throw CryptographicException.From(new InvalidDataException("Value lengths invalid"));
                    // Apply RNG seeding
                    if (((Pake.CryptoOptions.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.Random) == RngSeedingTypes.Random)
                        RND.AddSeed(auth.Random);
                    // Extract key and secret
                    randomMac ??= auth.Random.Mac(Pake.Identity.SignatureKey);
                    key = Key;
                    if (!auth.Key.Xor(randomMac).SlowCompare(key)) throw CryptographicException.From(new InvalidDataException("Authentication key invalid"));
                    // Validate the signature and create the session key (MAC)
                    secret = Secret;
                    (signature, sessionKey) = Pake.SignAndCreateSessionKey2(Pake.Identity.SignatureKey, key, auth.Random, auth.Payload, secret);
                    if (!auth.Signature.SlowCompare(signature))
                        throw CryptographicException.From(new InvalidDataException("Signature validation failed"));
                    return (payload ?? auth.Payload.CloneArray(), sessionKey);
                }
                finally
                {
                    signature?.Clear();
                    key?.Clear();
                    secret?.Clear();
                }
            }
            catch (Exception ex)
            {
                _AuthErrorCount++;
                Pake.RaiseOnAuthError(new(auth, payload, ex));
                payload?.Clear();
                sessionKey?.Clear();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                auth.Dispose();
                randomMac?.Clear();
                ssc?.Dispose();
            }
        }

        /// <summary>
        /// Handle an authentication
        /// </summary>
        /// <param name="auth">Authentication (will be disposed!)</param>
        /// <param name="decryptPayload">Decrypt the payload, if any? (for this the identity must be available already when calling this method!)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Payload and session key (should be cleared!)</returns>
        /// <exception cref="InvalidDataException">Invalid authentication record</exception>
        public async Task<(byte[] Payload, byte[] SessionKey)> HandleAuthAsync(IPakeRequest auth, bool decryptPayload = false, CancellationToken cancellationToken = default)
        {
            byte[]? payload = null,
                randomMac = null,
                sessionKey = null;
            SemaphoreSyncContext? ssc = null;
            try
            {
                EnsureUndisposed();
                if (UseSync) ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
                _AuthCount++;
                // Decrypt the payload
                if (decryptPayload && auth.Payload.Length != 0)
                {
                    if (Pake.Identity is null) throw await CryptographicException.FromAsync(new InvalidOperationException("Unknown identity")).DynamicContext();
                    randomMac = auth.Random.Mac(Pake.Identity.SignatureKey, Pake.Options);
                    try
                    {
                        payload = Pake.DecryptPayload(auth.Payload, randomMac);
                    }
                    finally
                    {
                        randomMac.Clear();
                    }
                }
                // Run pre-actions
                Pake.PakeServerEventArgs e = new(auth, payload);
                Pake.RaiseOnAuth(e);
                if (e.NewIdentity is not null)
                {
                    Pake.ClearIdentity();
                    Pake.Identity = e.NewIdentity;
                }
                // Validate pre-conditions
                if (Pake.Identity is null) throw await CryptographicException.FromAsync(new InvalidOperationException("Unknown identity")).DynamicContext();
                if (!Pake.Identity.Identifier.SlowCompare(auth.Identifier))
                    throw await CryptographicException.FromAsync(new InvalidDataException("Identity mismatch")).DynamicContext();
                byte[] key = null!,
                    secret = null!,
                    signature = null!;
                int len = auth.Identifier.Length;
                try
                {
                    // Validate the auth values lengths
                    if (auth.Key.Length != len || auth.Signature.Length != len || auth.Random.Length != len)
                        throw await CryptographicException.FromAsync(new InvalidDataException("Value lengths invalid")).DynamicContext();
                    // Apply RNG seeding
                    if (((Pake.CryptoOptions.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.Random) == RngSeedingTypes.Random)
                        await RND.AddSeedAsync(auth.Random, cancellationToken).DynamicContext();
                    // Extract key and secret
                    randomMac ??= auth.Random.Mac(Pake.Identity.SignatureKey);
                    key = Key;
                    if (!auth.Key.Xor(randomMac).SlowCompare(key))
                        throw await CryptographicException.FromAsync(new InvalidDataException("Authentication key invalid")).DynamicContext();
                    // Validate the signature and create the session key (MAC)
                    secret = Secret;
                    (signature, sessionKey) = Pake.SignAndCreateSessionKey2(Pake.Identity.SignatureKey, key, auth.Random, auth.Payload, secret);
                    if (!auth.Signature.SlowCompare(signature))
                        throw await CryptographicException.FromAsync(new InvalidDataException("Signature validation failed")).DynamicContext();
                    return (payload ?? auth.Payload.CloneArray(), sessionKey);
                }
                finally
                {
                    signature?.Clear();
                    key?.Clear();
                    secret?.Clear();
                }
            }
            catch (Exception ex)
            {
                _AuthErrorCount++;
                Pake.RaiseOnAuthError(new(auth, payload, ex));
                payload?.Clear();
                sessionKey?.Clear();
                if (ex is CryptographicException) throw;
                throw await CryptographicException.FromAsync(ex).DynamicContext();
            }
            finally
            {
                auth.Dispose();
                randomMac?.Clear();
                ssc?.Dispose();
            }
        }

        /// <summary>
        /// Create a PAKE authentication record from this instance
        /// </summary>
        /// <returns>Record (don't forget to clear!)</returns>
        public PakeAuthRecord CreateAuthRecord()
        {
            EnsureUndisposed();
            return new(Pake.Identity!.Identifier.CloneArray(), Secret, Key, SignatureKey);
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            FastPakeAuthServerTable.Servers.TryRemove(GUID, out _);
            using SemaphoreSync sync = Sync;
            using SemaphoreSyncContext ssc = sync;
            Pake?.Dispose();
            Secret?.Dispose();
            Key?.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            FastPakeAuthServerTable.Servers.TryRemove(GUID, out _);
            await using (Sync.DynamicContext())
            {
                using SemaphoreSyncContext ssc = await Sync.SyncContextAsync().DynamicContext();
                if (Secret is not null) await Secret.DisposeAsync().DynamicContext();
                if (Key is not null) await Key.DisposeAsync().DynamicContext();
                if (Pake is not null) await Pake.DisposeAsync().DynamicContext();
            }
        }
    }
}
