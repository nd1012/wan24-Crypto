using System.Runtime.CompilerServices;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Fast PAKE authentication server
    /// </summary>
    public sealed class FastPakeAuthServer : DisposableBase, IStatusProvider
    {
        /// <summary>
        /// Thread synchronizaion
        /// </summary>
        private readonly SemaphoreSync Sync = new();
        /// <summary>
        /// Key
        /// </summary>
        private readonly SecureValue Key = null!;
        /// <summary>
        /// Secret
        /// </summary>
        private readonly SecureValue Secret = null!;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="pake">PAKE instance (will be disposed!)</param>
        /// <param name="auth">Authentication (will be disposed!)</param>
        /// <param name="decryptPayload">Decrypt the payload (if any)?</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time; default is <see cref="SecureValue.DefaultEncryptTimeout"/>)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example; default is <see cref="SecureValue.DefaultRecryptTimeout"/>)</param>
        public FastPakeAuthServer(
            in Pake pake, 
            in PakeAuth auth, 
            in bool decryptPayload = false,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null
            ) : base(asyncDisposing: false)
        {
            byte[]? payload = null,
                randomMac = null;
            try
            {
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
                        payload = auth.Payload.Decrypt(randomMac, Pake.CryptoOptions);
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
                    // Extract key and secret
                    randomMac ??= auth.Random.Mac(Pake.Identity.SignatureKey);
                    key = auth.Key.CloneArray().Xor(randomMac);
                    secret = Pake.Identity.Secret.CloneArray().Xor(key);
                    // Validate the signature and create the session key (MAC)
                    signature = Pake.SignAndCreateSessionKey(Pake.Identity.SignatureKey, key, auth.Random, auth.Payload, secret);
                    if (!auth.Signature.SlowCompare(signature))
                        throw CryptographicException.From(new InvalidDataException("Signature validation failed"));
                    // Validate the signature key (KDF)
                    if (!Pake.SkipSignatureKeyValidation)
                    {
                        signatureKey = Pake.CreateSignatureKey(key, secret);
                        if (!Pake.Identity.SignatureKey.SlowCompare(signatureKey))
                            throw CryptographicException.From(new InvalidDataException("Authentication key validation failed"));
                    }
                    // Store the authentication key and the secret to this instance
                    Key = new(key, encryptTimeout, recryptTimeout, Pake.CryptoOptions.Clone())
                    {
                        Name = $"Fast PAKE auth server {GUID} (\"{Name}\") key"
                    };
                    Secret = new(secret, encryptTimeout, recryptTimeout, Pake.CryptoOptions.Clone())
                    {
                        Name = $"Fast PAKE auth server {GUID} (\"{Name}\") secret"
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
                Dispose();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                auth.Dispose();
                payload?.Clear();
                randomMac?.Clear();
            }
            FastPakeAuthServerTable.Servers[GUID] = this;
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="signup">Signup (will be disposed!)</param>
        /// <param name="pake">PAKE instance (will be disposed!)</param>
        /// <param name="encryptTimeout">Encrypt timeout (<see cref="TimeSpan.Zero"/> to keep encrypted all the time)</param>
        /// <param name="recryptTimeout">Re-crypt timeout (one minute, for example)</param>
        public FastPakeAuthServer(
            in PakeSignup signup, 
            in Pake? pake = null,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null
            ) : base(asyncDisposing: false)
        {
            try
            {
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
                    // Create the identity (KDF)
                    signatureKey = Pake.CreateSignatureKey(signup.Key, signup.Secret);
                    Pake.Identity = new PakeRecord(signup.Identifier.CloneArray(), signup.Secret.CloneArray().Xor(signup.Key), signatureKey);
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
                    // Store the authentication key and the secret to this instance
                    Key = new(signup.Key.CloneArray(), encryptTimeout, recryptTimeout, Pake.CryptoOptions.Clone())
                    {
                        Name = $"Fast PAKE auth server {GUID} (\"{Name}\") key"
                    };
                    Secret = new(signup.Secret.CloneArray(), encryptTimeout, recryptTimeout, Pake.CryptoOptions.Clone())
                    {
                        Name = $"Fast PAKE auth server {GUID} (\"{Name}\") secret"
                    };
                }
                catch
                {
                    signatureKey?.Clear();
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
        /// Authentication count (including errors)
        /// </summary>
        public long AuthCount { get; private set; }

        /// <summary>
        /// Authentication error count
        /// </summary>
        public long AuthErrorCount { get; private set; }

        /// <inheritdoc/>
        public IEnumerable<Status> State
        {
            get
            {
                yield return new("GUID", GUID, "Unique ID of the fast PAKE server");
                yield return new("Name", Name, "Name of the fast PAKE server");
                yield return new("Identifier", Convert.ToHexString(Identifier), "Peer identifier");
                yield return new("Count", AuthCount, "Authentication count since initialization");
                yield return new("Errors", AuthErrorCount, "Authentication error count since initialization");
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
                randomMac = null;
            try
            {
                EnsureUndisposed();
                using SemaphoreSyncContext ssc = Sync;
                AuthCount++;
                // Decrypt the payload
                if (decryptPayload && auth.Payload.Length != 0)
                {
                    if (Pake.Identity is null) throw CryptographicException.From(new InvalidOperationException("Unknown identity"));
                    randomMac = auth.Random.Mac(Pake.Identity.SignatureKey, Pake.Options);
                    try
                    {
                        payload = auth.Payload.Decrypt(randomMac, Pake.CryptoOptions);
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
                    // Extract key and secret
                    randomMac ??= auth.Random.Mac(Pake.Identity.SignatureKey);
                    key = Key;
                    if(!auth.Key.Xor(randomMac).SlowCompare(key)) throw CryptographicException.From(new InvalidDataException("Authentication key invalid"));
                    // Validate the signature and create the session key (MAC)
                    secret = Secret;
                    signature = Pake.SignAndCreateSessionKey(Pake.Identity.SignatureKey, key, auth.Random, auth.Payload, secret);
                    if (!auth.Signature.SlowCompare(signature))
                        throw CryptographicException.From(new InvalidDataException("Signature validation failed"));
                    return (payload ?? auth.Payload.CloneArray(), SessionKey.CloneArray());
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
                AuthErrorCount++;
                Pake.ClearSessionKey();
                Pake.RaiseOnAuthError(new(auth, payload, ex));
                payload?.Clear();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                auth.Dispose();
                randomMac?.Clear();
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
            FastPakeAuthServerTable.Servers.TryRemove(GUID, out _);
            Pake?.Dispose();
            Secret?.Dispose();
            Key?.Dispose();
            Sync.Dispose();
        }
    }
}
