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
        /// <returns>Identity (will be cleared!)</returns>
        /// <exception cref="InvalidDataException">Invalid signup record</exception>
        [MemberNotNull(nameof(Identity))]
        public IPakeRecord HandleSignup(PakeSignup signup)
        {
            try
            {
                EnsureUndisposed();
                if (Key is not null) throw new InvalidOperationException("Initialized for client operation");
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
                    // Validate the signature and create the session key (MAC)
                    signature = CreateSignatureAndSessionKey(signatureKey, signup.Key, signup.Random, signup.Secret);
                    if (!signup.Signature.SlowCompare(signature))
                        throw new InvalidDataException("Signature validation failed");
                    return Identity;
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
            catch
            {
                ClearSessionKey();
                ClearIdentity();
                throw;
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
        /// <returns>Session key (will be cleared!)</returns>
        /// <exception cref="InvalidDataException">Invalid authentication record</exception>
        [MemberNotNull(nameof(Identity))]
        public byte[] HandleAuth(PakeAuth auth)
        {
            try
            {
                EnsureUndisposed();
                if (Key is not null) throw new InvalidOperationException("Initialized for client operation");
                // Validate pre-conditions
                if (Identity is null) throw new InvalidOperationException("Unknown identity");
                if (!Identity.Identifier.SlowCompare(auth.Identifier))
                    throw new InvalidDataException("Identity mismatch");
                byte[] signatureKey = null!,
                    signature = null!;
                try
                {
                    // Validate the signature and create the session key (MAC)
                    signature = CreateSignatureAndSessionKey(Identity.SignatureKey, auth.Key, auth.Random, Identity.Secret);
                    if (!auth.Signature.SlowCompare(signature))
                        throw new InvalidDataException("Signature validation failed");
                    // Validate the signature key (KDF)
                    signatureKey = CreateSignatureKey(auth.Key);
                    if (!Identity.SignatureKey.SlowCompare(signatureKey))
                        throw new InvalidDataException("Authentication key validation failed");
                    return _SessionKey;
                }
                finally
                {
                    signatureKey?.Clear();
                    signature?.Clear();
                }
            }
            catch
            {
                ClearSessionKey();
                throw;
            }
            finally
            {
                auth.Dispose();
            }
        }
    }
}
