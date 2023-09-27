using System.Diagnostics.CodeAnalysis;
using wan24.Core;

namespace wan24.Crypto
{
    // Server
    public sealed partial class Pake
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="identity">Identity (initializes server operations; will be cleared (and disposed, if possible)!)</param>
        /// <param name="options">Options with KDF and MAC settings (will be cleared!)</param>
        /// <param name="cryptoOptions">Options for encryption (will be cleared!)</param>
        public Pake(in IPakeRecord identity, in CryptoOptions? options = null, in CryptoOptions? cryptoOptions = null) : this(options, cryptoOptions)
        {
            Key = null;
            Identity = identity;
        }

        /// <summary>
        /// Identity (will be cleared (and disposed, if possible)!)
        /// </summary>
        [SensitiveData]
        public IPakeRecord? Identity { get; internal set; }

        /// <summary>
        /// Handle a signup (server)
        /// </summary>
        /// <param name="signup">Signup (will be disposed!)</param>
        /// <returns>Payload</returns>
        /// <exception cref="InvalidDataException">Invalid signup record</exception>
        [MemberNotNull(nameof(Identity))]
        public byte[] HandleSignup(in PakeSignup signup)
        {
            try
            {
                EnsureUndisposed();
                if (Key is not null) throw CryptographicException.From(new InvalidOperationException("Initialized for client operation"));
                byte[] signatureKey = null!,
                    signature = null!;
                int len = MacHelper.GetAlgorithm(Options.MacAlgorithm!).MacLength;
                try
                {
                    // Validate the signup values lengths
                    if (signup.Identifier.Length != len || signup.Secret.Length != len || signup.Key.Length != len || signup.Signature.Length != len || signup.Random.Length != len)
                        throw CryptographicException.From(new InvalidDataException("Value lengths invalid"));
                    // Reset this instance
                    ClearSessionKey();
                    ClearIdentity();
                    // Create the identity (KDF)
                    signatureKey = CreateSignatureKey(signup.Key, signup.Secret);
                    Identity = new PakeRecord(signup.Identifier.CloneArray(), signup.Secret.CloneArray().Xor(signup.Key), signatureKey);
                    PakeServerEventArgs e = new(signup);
                    OnSignup?.Invoke(this, e);
                    if (e.NewIdentity is not null)
                    {
                        ClearIdentity();
                        Identity = e.NewIdentity;
                    }
                    // Validate the signature and create the session key (MAC)
                    signature = SignAndCreateSessionKey(signatureKey, signup.Key, signup.Random, signup.Payload, signup.Secret);
                    if (!signup.Signature.SlowCompare(signature))
                        throw CryptographicException.From(new InvalidDataException("Signature validation failed"));
                    return signup.Payload.CloneArray();
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
                ClearSessionKey();
                ClearIdentity();
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                signup.Dispose();
            }
        }

        /// <summary>
        /// Handle an authentication (server)
        /// </summary>
        /// <param name="auth">Authentication (will be disposed!)</param>
        /// <param name="decryptPayload">Decrypt the payload, if any? (for this the identity must be available already when calling this method!)</param>
        /// <param name="skipSignatureKeyValidation">Skip the signature key validation (KDF)?</param>
        /// <returns>Payload</returns>
        /// <exception cref="InvalidDataException">Invalid authentication record</exception>
        [MemberNotNull(nameof(Identity))]
        public byte[] HandleAuth(in IPakeRequest auth, in bool decryptPayload = false, in bool skipSignatureKeyValidation = false)
        {
            byte[]? payload = null,
                randomMac = null;
            try
            {
                EnsureUndisposed();
                if (Key is not null) throw CryptographicException.From(new InvalidOperationException("Initialized for client operation"));
                // Decrypt the payload
                if (decryptPayload && auth.Payload.Length != 0)
                {
                    if (Identity is null) throw CryptographicException.From(new InvalidOperationException("Unknown identity"));
                    randomMac = auth.Random.CloneArray().Mac(Identity.SignatureKey, Options);
                    payload = auth.Payload.Decrypt(randomMac, CryptoOptions);
                }
                // Run pre-actions
                PakeServerEventArgs e = new(auth, payload);
                OnAuth?.Invoke(this, e);
                if (e.NewIdentity is not null)
                {
                    ClearIdentity();
                    Identity = e.NewIdentity;
                }
                if (Identity is null) throw CryptographicException.From(new InvalidOperationException("Unknown identity"));
                // Validate pre-conditions
                byte[] identifier = Identifier;
                if (!identifier.SlowCompare(auth.Identifier)) throw CryptographicException.From(new InvalidDataException("Identity mismatch"));
                byte[] key = null!,
                    secret = null!,
                    signatureKey = null!,
                    signature = null!;
                int len = identifier.Length;
                try
                {
                    // Validate the auth values lengths
                    if (auth.Key.Length != len || auth.Signature.Length != len || auth.Random.Length != len)
                        throw CryptographicException.From(new InvalidDataException("Value lengths invalid"));
                    // Extract key and secret
                    randomMac ??= auth.Random.CloneArray().Mac(Identity.SignatureKey, Options);
                    key = auth.Key.CloneArray().Xor(randomMac);
                    secret = Identity.Secret.CloneArray().Xor(key);
                    // Validate the signature and create the session key (MAC)
                    signature = SignAndCreateSessionKey(Identity.SignatureKey, key, auth.Random, auth.Payload, secret);
                    if (!auth.Signature.SlowCompare(signature))
                        throw CryptographicException.From(new InvalidDataException("Signature validation failed"));
                    // Validate the signature key (KDF)
                    if (!skipSignatureKeyValidation && !SkipSignatureKeyValidation)
                    {
                        signatureKey = CreateSignatureKey(key, secret);
                        if (!Identity.SignatureKey.SlowCompare(signatureKey))
                            throw CryptographicException.From(new InvalidDataException("Authentication key validation failed"));
                    }
                    return payload ?? auth.Payload.CloneArray();
                }
                finally
                {
                    key?.Clear();
                    secret?.Clear();
                    signatureKey?.Clear();
                    signature?.Clear();
                }
            }
            catch (Exception ex)
            {
                ClearSessionKey();
                OnAuthError?.Invoke(this, new(auth, payload, ex));
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
        /// Delegate for a PAKE server event handler delegate
        /// </summary>
        /// <param name="pake">PAKE</param>
        /// <param name="e">Arguments</param>
        public delegate void PakeServer_Delegate(Pake pake, PakeServerEventArgs e);

        /// <summary>
        /// Raised on signup
        /// </summary>
        public event PakeServer_Delegate? OnSignup;
        /// <summary>
        /// Raise the <see cref="OnSignup"/> event
        /// </summary>
        /// <param name="e">Arguments</param>
        internal void RaiseOnSignup(in PakeServerEventArgs e) => OnSignup?.Invoke(this, e);

        /// <summary>
        /// Raised on authentication
        /// </summary>
        public event PakeServer_Delegate? OnAuth;
        /// <summary>
        /// Raise the <see cref="OnAuth"/> event
        /// </summary>
        /// <param name="e">Arguments</param>
        internal void RaiseOnAuth(in PakeServerEventArgs e) => OnAuth?.Invoke(this, e);

        /// <summary>
        /// Raised on authentication
        /// </summary>
        public event PakeServer_Delegate? OnAuthError;
        /// <summary>
        /// Raise the <see cref="OnAuthError"/> event
        /// </summary>
        /// <param name="e">Arguments</param>
        internal void RaiseOnAuthError(in PakeServerEventArgs e) => OnAuthError?.Invoke(this, e);

        /// <summary>
        /// PAKE server event arguments
        /// </summary>
        public sealed class PakeServerEventArgs : EventArgs
        {
            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="request">Request</param>
            /// <param name="payload">Decrypted payload, if any</param>
            /// <param name="ex">Exception</param>
            public PakeServerEventArgs(in IPakeRequest request, in byte[]? payload = null, in Exception? ex = null) : base()
            {
                Request = request;
                Payload = payload;
                Exception = ex;
            }

            /// <summary>
            /// Request
            /// </summary>
            public IPakeRequest Request { get; }

            /// <summary>
            /// Decrypted payload, if any
            /// </summary>
            public byte[]? Payload { get; }

            /// <summary>
            /// Exception
            /// </summary>
            public Exception? Exception { get; }

            /// <summary>
            /// New PAKE identity record to use for the current process (being ignored in case this instance is used as arguments for the <see cref="OnAuthError"/> event!)
            /// </summary>
            public IPakeRecord? NewIdentity { get; set; }
        }
    }
}
