using wan24.Core;

namespace wan24.Crypto
{
    // Construction
    public sealed partial class FastPakeAuthServer
    {
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
        /// <param name="payloadProcessor">Payload processor</param>
        public FastPakeAuthServer(
            in Pake pake,
            in PakeAuth auth,
            out byte[] payload,
            out byte[] sessionKey,
            in bool decryptPayload = false,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in string? name = null,
            in Pake.PayloadProcessor_Delegate? payloadProcessor = null
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
                if(payloadProcessor is not null)
                {
                    byte[] temp = payloadProcessor(Pake, auth.Random, payload);
                    payload.Clear();
                    payload = temp;
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
        /// <param name="payloadProcessor">Payload processor</param>
        public FastPakeAuthServer(
            in PakeSignup signup,
            out PakeRecord identity,
            out byte[] payload,
            out byte[] sessionKey,
            in Pake? pake = null,
            in TimeSpan? encryptTimeout = null,
            in TimeSpan? recryptTimeout = null,
            in string? name = null,
            in Pake.PayloadProcessor_Delegate? payloadProcessor = null
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
                if (payloadProcessor is not null)
                {
                    byte[] temp = payloadProcessor(Pake, signup.Random, payload);
                    payload.Clear();
                    payload = temp;
                }
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
                options?.ValidateAlgorithms();
                cryptoOptions?.ValidateAlgorithms();
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
    }
}
