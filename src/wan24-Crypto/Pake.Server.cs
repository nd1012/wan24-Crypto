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
        /// <param name="identity">Identity (initializes server operations; will be cleared!)</param>
        /// <param name="options">Options with KDF and MAC settings (will be cleared!)</param>
        public Pake(IPakeRecord identity, CryptoOptions? options = null) : this(options)
        {
            Key = null;
            Identity = identity;
        }

        /// <summary>
        /// Identity (will be cleared!)
        /// </summary>
        public IPakeRecord? Identity { get; private set; }

        /// <summary>
        /// Handle a signup (server)
        /// </summary>
        /// <param name="signup">Signup (will be disposed!)</param>
        /// <returns>Payload (should be cleared!)</returns>
        /// <exception cref="InvalidDataException">Invalid signup record</exception>
        [MemberNotNull(nameof(Identity))]
        public byte[] HandleSignup(PakeSignup signup)
        {
            try
            {
                EnsureUndisposed();
                if (Key is not null) throw CryptographicException.From(new InvalidOperationException("Initialized for client operation"));
                byte[] secret = null!,
                    signatureKey = null!,
                    signature = null!;
                try
                {
                    // Reset this instance
                    ClearSessionKey();
                    ClearIdentity();
                    // Create the identity (KDF)
                    signatureKey = CreateSignatureKey(signup.Key, signup.Identifier);
                    Identity = new PakeRecord(signup.Identifier.CloneArray(), signup.Secret.CloneArray(), signatureKey);
                    PakeServerEventArgs e = new(signup);
                    OnSignup?.Invoke(this, e);
                    if (e.NewIdentity is not null)
                    {
                        ClearIdentity();
                        Identity = e.NewIdentity;
                    }
                    // Validate the signature and create the session key (MAC)
                    signature = CreateSignatureAndSessionKey(signatureKey, signup.Key, signup.Random, signup.Payload, signup.Secret);
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
                    secret?.Clear();
                    signature?.Clear();
                }
            }
            catch(Exception ex)
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
        /// Handle an auuthentication (server)
        /// </summary>
        /// <param name="auth">Authentication (will be disposed!)</param>
        /// <returns>Payload (should be cleared!)</returns>
        /// <exception cref="InvalidDataException">Invalid authentication record</exception>
        [MemberNotNull(nameof(Identity))]
        public byte[] HandleAuth(IPakeRequest auth)
        {
            try
            {
                EnsureUndisposed();
                if (Key is not null) throw CryptographicException.From(new InvalidOperationException("Initialized for client operation"));
                // Run pre-actions
                PakeServerEventArgs e = new(auth);
                OnAuth?.Invoke(this, e);
                if (e.NewIdentity is not null)
                {
                    ClearIdentity();
                    Identity = e.NewIdentity;
                }
                // Validate pre-conditions
                if (Identity is null) throw CryptographicException.From(new InvalidOperationException("Unknown identity"));
                if (!Identity.Identifier.SlowCompare(auth.Identifier))
                    throw CryptographicException.From(new InvalidDataException("Identity mismatch"));
                byte[] signatureKey = null!,
                    signature = null!;
                try
                {
                    // Validate the signature and create the session key (MAC)
                    signature = CreateSignatureAndSessionKey(Identity.SignatureKey, auth.Key, auth.Random, auth.Payload, Identity.Secret);
                    if (!auth.Signature.SlowCompare(signature))
                        throw CryptographicException.From(new InvalidDataException("Signature validation failed"));
                    // Validate the signature key (KDF)
                    signatureKey = CreateSignatureKey(auth.Key);
                    if (!Identity.SignatureKey.SlowCompare(signatureKey))
                        throw CryptographicException.From(new InvalidDataException("Authentication key validation failed"));
                    return auth.Payload.CloneArray();
                }
                finally
                {
                    signatureKey?.Clear();
                    signature?.Clear();
                }
            }
            catch(Exception ex)
            {
                ClearSessionKey();
                OnAuthError?.Invoke(this, new(auth, ex));
                if (ex is CryptographicException) throw;
                throw CryptographicException.From(ex);
            }
            finally
            {
                auth.Dispose();
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
        /// Raised on authentication
        /// </summary>
        public event PakeServer_Delegate? OnAuth;

        /// <summary>
        /// Raised on authentication
        /// </summary>
        public event PakeServer_Delegate? OnAuthError;

        /// <summary>
        /// PAKE server event arguments
        /// </summary>
        public sealed class PakeServerEventArgs : EventArgs
        {
            /// <summary>
            /// Constructor
            /// </summary>
            /// <param name="request">Request</param>
            /// <param name="ex">Exception</param>
            public PakeServerEventArgs(IPakeRequest request, Exception? ex = null) : base()
            {
                Request = request;
                Exception = ex;
            }

            /// <summary>
            /// Request
            /// </summary>
            public IPakeRequest Request { get; }

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
