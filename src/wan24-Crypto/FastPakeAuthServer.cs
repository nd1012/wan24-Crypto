using System.Runtime.CompilerServices;
using System.Security.Principal;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Fast PAKE authentication server (NOT thread-safe!)
    /// </summary>
    public sealed class FastPakeAuthServer : DisposableBase
    {
        /// <summary>
        /// Key
        /// </summary>
        private readonly SecureByteArray Key = null!;
        /// <summary>
        /// Secret
        /// </summary>
        private readonly SecureByteArray Secret = null!;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="pake">PAKE instance (will be disposed!)</param>
        /// <param name="auth">Authentication (will be disposed!)</param>
        /// <param name="decryptPayload">Decrypt the payload (if any)?</param>
        public FastPakeAuthServer(Pake pake, PakeAuth auth, bool decryptPayload = false) : base(asyncDisposing: false)
        {
            if (pake.Key is not null) throw CryptographicException.From(new ArgumentException("Initialized for client operation", nameof(pake)));
            if (pake.Identity is null) throw CryptographicException.From(new ArgumentException("Identity record required", nameof(pake)));
            Pake = pake;
            byte[]? payload = null;
            try
            {
                if (Key is not null) throw CryptographicException.From(new InvalidOperationException("Initialized for client operation"));
                // Decrypt the payload
                if (decryptPayload && auth.Payload.Length != 0)
                {
                    if (Pake.Identity is null) throw CryptographicException.From(new InvalidOperationException("Unknown identity"));
                    byte[] dek = auth.Random.Mac(Pake.Identity.SignatureKey, Pake.Options);
                    try
                    {
                        payload = auth.Payload.Decrypt(dek, Pake.Options);
                    }
                    finally
                    {
                        dek.Clear();
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
                byte[] identifier = Identifier;
                if (!identifier.SlowCompare(auth.Identifier)) throw CryptographicException.From(new InvalidDataException("Identity mismatch"));
                byte[] key = null!,
                    secret = null!,
                    randomMac = null!,
                    signatureKey = null!,
                    signature = null!;
                int len = identifier.Length;
                try
                {
                    // Validate the auth values lengths
                    if (auth.Key.Length != len || auth.Signature.Length != len || auth.Random.Length != len)
                        throw CryptographicException.From(new InvalidDataException("Value lengths invalid"));
                    // Extract key and secret
                    randomMac = auth.Random.CloneArray().Mac(Pake.Identity.SignatureKey);
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
                    // Store the authentication key and the secret to this instance
                    Key = new(key);
                    Secret = new(secret);
                }
                catch
                {
                    key?.Clear();
                    secret?.Clear();
                    throw;
                }
                finally
                {
                    randomMac?.Clear();
                    signatureKey?.Clear();
                    signature?.Clear();
                }
            }
            catch (Exception ex)
            {
                Pake.ClearSessionKey();
                Pake.RaiseOnAuthError(new(auth, payload, ex));
                Dispose();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                auth.Dispose();
                payload?.Clear();
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="signup">Signup (will be disposed!)</param>
        /// <param name="pake">PAKE instance (will be disposed!)</param>
        public FastPakeAuthServer(PakeSignup signup, Pake? pake = null) : base(asyncDisposing: false)
        {
            pake ??= new();
            if (pake.Key is not null) throw CryptographicException.From(new ArgumentException("Initialized for client operation", nameof(pake)));
            Pake = pake;
            try
            {
                if (Key is not null) throw CryptographicException.From(new InvalidOperationException("Initialized for client operation"));
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
                    Key = new(signup.Key.CloneArray());
                    Secret = new(signup.Secret.CloneArray());
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
                Pake.ClearSessionKey();
                Pake.ClearIdentity();
                Dispose();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                signup.Dispose();
            }
        }

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
        public byte[] SessionKey
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            get => Pake.SessionKey;
        }

        /// <summary>
        /// Handle an authentication
        /// </summary>
        /// <param name="auth">Authentication (will be disposed!)</param>
        /// <param name="decryptPayload">Decrypt the payload, if any? (for this the identity must be available already when calling this method!)</param>
        /// <returns>Payload</returns>
        /// <exception cref="InvalidDataException">Invalid authentication record</exception>
        public byte[] HandleAuth(IPakeRequest auth, bool decryptPayload = false)
        {
            byte[]? payload = null;
            try
            {
                EnsureUndisposed();
                // Decrypt the payload
                if (decryptPayload && auth.Payload.Length != 0)
                {
                    if (Pake.Identity is null) throw CryptographicException.From(new InvalidOperationException("Unknown identity"));
                    byte[] dek = auth.Random.Mac(Pake.Identity.SignatureKey, Pake.Options);
                    try
                    {
                        payload = auth.Payload.Decrypt(dek, Pake.Options);
                    }
                    finally
                    {
                        dek.Clear();
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
                byte[] identifier = Identifier;
                if (!identifier.SlowCompare(auth.Identifier)) throw CryptographicException.From(new InvalidDataException("Identity mismatch"));
                byte[] randomMac = null!,
                    signature = null!;
                int len = identifier.Length;
                try
                {
                    // Validate the auth values lengths
                    if (auth.Key.Length != len || auth.Signature.Length != len || auth.Random.Length != len)
                        throw CryptographicException.From(new InvalidDataException("Value lengths invalid"));
                    // Extract key and secret
                    randomMac = auth.Random.CloneArray().Mac(Pake.Identity.SignatureKey);
                    if(!auth.Key.Xor(randomMac).SlowCompare(Key.Span)) throw CryptographicException.From(new InvalidDataException("Authentication key invalid"));
                    // Validate the signature and create the session key (MAC)
                    signature = Pake.SignAndCreateSessionKey(Pake.Identity.SignatureKey, Key, auth.Random, auth.Payload, Secret);
                    if (!auth.Signature.SlowCompare(signature))
                        throw CryptographicException.From(new InvalidDataException("Signature validation failed"));
                    return auth.Payload.CloneArray();
                }
                finally
                {
                    randomMac?.Clear();
                    signature?.Clear();
                }
            }
            catch (Exception ex)
            {
                Pake.ClearSessionKey();
                Pake.RaiseOnAuthError(new(auth, payload, ex));
                payload?.Clear();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                auth.Dispose();
            }
        }

        /// <summary>
        /// Clear the session key
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void ClearSessionKey() => Pake?.ClearSessionKey();

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            Pake?.Dispose();
            Secret?.Dispose();
            Key?.Dispose();
        }
    }
}
