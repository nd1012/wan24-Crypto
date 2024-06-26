﻿using System.Diagnostics.CodeAnalysis;
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
            options?.ValidateAlgorithms();
            cryptoOptions?.ValidateAlgorithms();
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
        /// <param name="payloadProcessor">Payload processor</param>
        /// <returns>Payload</returns>
        /// <exception cref="InvalidDataException">Invalid signup record</exception>
        [MemberNotNull(nameof(Identity))]
        public byte[] HandleSignup(in PakeSignup signup, in PayloadProcessor_Delegate? payloadProcessor = null)
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
                    // Apply RNG seeding
                    if (((CryptoOptions.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.Random) == RngSeedingTypes.Random)
                        RND.AddSeed(signup.Random);
                    // Create the identity (KDF)
                    signatureKey = CreateSignatureKey(signup.Key, signup.Secret);
                    Identity = new PakeRecord(signup, signatureKey);
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
                    return payloadProcessor is null
                        ? signup.Payload.CloneArray()
                        : payloadProcessor(this, signup.Random, signup.Payload);
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
        /// <param name="payloadProcessor">Payload processor</param>
        /// <returns>Payload</returns>
        /// <exception cref="InvalidDataException">Invalid authentication record</exception>
        [MemberNotNull(nameof(Identity))]
        public byte[] HandleAuth(
            in IPakeRequest auth, 
            in bool decryptPayload = false, 
            in bool skipSignatureKeyValidation = false, 
            in PayloadProcessor_Delegate? payloadProcessor = null
            )
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
                    payload = DecryptPayload(auth.Payload, randomMac);
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
                    // Apply RNG seeding
                    if (((CryptoOptions.RngSeeding ?? RND.AutoRngSeeding) & RngSeedingTypes.Random) == RngSeedingTypes.Random)
                        RND.AddSeed(auth.Random);
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
                    return payloadProcessor is null
                        ? payload ?? auth.Payload.CloneArray()
                        : payloadProcessor(this, auth.Random, payload ?? auth.Payload);
                }
                finally
                {
                    key?.Clear();
                    secret?.Clear();
                    signatureKey?.Clear();
                    signature?.Clear();
                    if (payloadProcessor is not null) payload?.Clear();
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
        /// Payload processor (called after payload decryption to process the payload before returning)
        /// </summary>
        /// <param name="pake">PAKE</param>
        /// <param name="random">Random data</param>
        /// <param name="payload">Payload</param>
        /// <returns>Payload to return (if this is the given payload, the return value should be a copy!)</returns>
        public delegate byte[] PayloadProcessor_Delegate(Pake pake, byte[] random, byte[] payload);

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
        /// <remarks>
        /// Constructor
        /// </remarks>
        /// <param name="request">Request</param>
        /// <param name="payload">Decrypted payload, if any</param>
        /// <param name="ex">Exception</param>
        public sealed class PakeServerEventArgs(in IPakeRequest request, in byte[]? payload = null, in Exception? ex = null) : EventArgs()
        {

            /// <summary>
            /// Request
            /// </summary>
            public IPakeRequest Request { get; } = request;

            /// <summary>
            /// Decrypted payload, if any
            /// </summary>
            public byte[]? Payload { get; } = payload;

            /// <summary>
            /// Exception
            /// </summary>
            public Exception? Exception { get; } = ex;

            /// <summary>
            /// New PAKE identity record to use for the current process (being ignored in case this instance is used as arguments for the <see cref="OnAuthError"/> event!)
            /// </summary>
            public IPakeRecord? NewIdentity { get; set; }
        }
    }
}
