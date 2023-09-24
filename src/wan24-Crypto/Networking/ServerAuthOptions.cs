﻿namespace wan24.Crypto.Networking
{
    /// <summary>
    /// Server authentication options
    /// </summary>
    public sealed class ServerAuthOptions
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="privateKeys">Private keys (will be disposed!)</param>
        /// <param name="identityfactory">Identity factory (required for signup/authentication)</param>
        public ServerAuthOptions(PrivateKeySuite privateKeys, ServerAuth.Identity_Delegate? identityfactory = null)
        {
            PrivateKeys = privateKeys;
            IdentityFactory = identityfactory;
        }

        /// <summary>
        /// Private keys (will be disposed!)
        /// </summary>
        public PrivateKeySuite PrivateKeys { get; }

        /// <summary>
        /// Allow public key request?
        /// </summary>
        public bool AllowPublicKeyRequest { get; set; } = true;

        /// <summary>
        /// Allow signup?
        /// </summary>
        public bool AllowSignup { get; set; } = true;

        /// <summary>
        /// Allow the signup of a temporary client?
        /// </summary>
        public bool AllowTemporaryClient { get; set; } = true;

        /// <summary>
        /// Allow authentication?
        /// </summary>
        public bool AllowAuthentication { get; set; } = true;

        /// <summary>
        /// Sign the client public key on request?
        /// </summary>
        public bool SignClientPublicKey { get; set; } = true;

        /// <summary>
        /// Hash options (require hash algorithm; will be cleared!)
        /// </summary>
        public CryptoOptions? HashOptions { get; set; }

        /// <summary>
        /// PAKE options (require KDF and MAC algorithms; will be cleared!)
        /// </summary>
        public CryptoOptions? PakeOptions { get; set; }

        /// <summary>
        /// Skip the PAKE signature key validation (KDF) during authentication?
        /// </summary>
        public bool SkipPakeSignatureKeyValidation { get; set; }

        /// <summary>
        /// Decrypt the payload during authentication?
        /// </summary>
        public bool DecryptPayload { get; set; }

        /// <summary>
        /// Crypto options (require encryption algorithms; shouldn't use KDF; cipher must not require MAC authentication; will be cleared!)
        /// </summary>
        public CryptoOptions? CryptoOptions { get; set; }

        /// <summary>
        /// Send a response on authentication?
        /// </summary>
        public bool SendAuthenticationResponse { get; set; } = true;

        /// <summary>
        /// Signup validator
        /// </summary>
        public ServerAuth.SignupValidator_Delegate? SignupValidator { get; set; }

        /// <summary>
        /// Identity factory
        /// </summary>
        public ServerAuth.Identity_Delegate? IdentityFactory { get; set; }

        /// <summary>
        /// Signup handler
        /// </summary>
        public ServerAuth.Signup_Delegate? SignupHandler { get; set; }

        /// <summary>
        /// Authentication handler
        /// </summary>
        public ServerAuth.Authentication_Delegate? AuthenticationHandler { get; set; }

        /// <summary>
        /// Max. time difference to a peers time
        /// </summary>
        public TimeSpan MaxTimeDifference { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Public client key signature purpose
        /// </summary>
        public string PublicClientKeySignaturePurpose { get; set; } = ServerAuth.PUBLIC_KEY_SIGNATURE_PURPOSE;
    }
}