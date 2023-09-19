using wan24.Core;

namespace wan24.Crypto
{
    // Static
    public sealed partial class Pake
    {
        /// <summary>
        /// Default options
        /// </summary>
        private static CryptoOptions? _DefaultOptions = null;
        /// <summary>
        /// Default options for encryption
        /// </summary>
        private static CryptoOptions? _DefaultCryptoOptions = null;

        /// <summary>
        /// Default options (should/will be cleared!)
        /// </summary>
        public static CryptoOptions DefaultOptions
        {
            get => (_DefaultOptions ??= new CryptoOptions()
                .WithKdf()
                .WithMac()).Clone();
            set
            {
                _DefaultOptions?.Clear();
                _DefaultOptions = value;
                if (value is null) return;
                if (_DefaultOptions.KdfAlgorithm is null) _DefaultOptions.WithKdf();
                if (_DefaultOptions.MacAlgorithm is null) _DefaultOptions.WithMac();
            }
        }

        /// <summary>
        /// Default options for encryption (should/will be cleared!)
        /// </summary>
        public static CryptoOptions DefaultCryptoOptions
        {
            get
            {
                if (_DefaultCryptoOptions is not null) return _DefaultCryptoOptions.Clone();
                _DefaultCryptoOptions = new();
                _DefaultCryptoOptions.WithEncryptionAlgorithm()
                    .WithoutCompression()
                    .WithoutKdf()
                    .WithoutMac()
                    .IncludeNothing()
                    .WithoutRequirements(CryptoFlags.FLAGS);
                if (EncryptionHelper.GetAlgorithm(_DefaultCryptoOptions.Algorithm!).RequireMacAuthentication)
                    _DefaultCryptoOptions.WithMac()
                        .WithFlagsIncluded(CryptoFlags.LatestVersion | CryptoFlags.MacIncluded, setRequirements: true);
                return _DefaultCryptoOptions.Clone();
            }
            set
            {
                _DefaultCryptoOptions?.Clear();
                _DefaultCryptoOptions = value;
            }
        }

        /// <summary>
        /// Skip the signature key validation (KDF) during authentication?
        /// </summary>
        public static bool SkipSignatureKeyValidation { get; set; }

        /// <summary>
        /// Cast as existing session flag
        /// </summary>
        /// <param name="pake"><see cref="Pake"/></param>
        public static implicit operator bool(in Pake pake) => pake.HasSession;

        /// <summary>
        /// Cast as session key (should be cleared!)
        /// </summary>
        /// <param name="pake"><see cref="Pake"/></param>
        public static implicit operator byte[](in Pake pake) => pake.SessionKey.CloneArray();

        /// <summary>
        /// Get the payload
        /// </summary>
        /// <param name="pake"><see cref="Pake"/></param>
        /// <param name="signup"><see cref="PakeSignup"/> (will be disposed!)</param>
        /// <returns>Payload</returns>
        public static byte[] operator +(in Pake pake, in PakeSignup signup)
        {
            pake.HandleSignup(signup);
            return pake;
        }

        /// <summary>
        /// Get the payload
        /// </summary>
        /// <param name="pake"><see cref="Pake"/></param>
        /// <param name="auth"><see cref="PakeAuth"/> (will be disposed!)</param>
        /// <returns>Payload</returns>
        public static byte[] operator +(in Pake pake, in PakeAuth auth) => pake.HandleAuth(auth).CloneArray();

        /// <summary>
        /// Derive a session key
        /// </summary>
        /// <param name="signup">Signup (will be disposed!)</param>
        /// <param name="initializer">PAKE instance initializer</param>
        /// <param name="options">Options</param>
        /// <returns>Session key, payload and identity</returns>
        public static (byte[] SessionKey, byte[] Payload, IPakeRecord Identity) DeriveSessionKey(
            in PakeSignup signup,
            in Action<Pake>? initializer = null,
            in CryptoOptions? options = null
            )
        {
            using PakeSignup request = signup;
            using Pake pake = new(options?.Clone());
            if (initializer is not null) initializer(pake);
            byte[] payload = pake.HandleSignup(request);
            return (pake.SessionKey.CloneArray(), payload, new PakeRecord(pake.Identity));
        }

        /// <summary>
        /// Derive a session key
        /// </summary>
        /// <param name="identity">Identity (will be cleared/disposed!)</param>
        /// <param name="auth">Authentication (will be disposed!)</param>
        /// <param name="initializer">PAKE instance initializer</param>
        /// <param name="options">Options</param>
        /// <param name="cryptoOptions">Options for encryption</param>
        /// <param name="decryptPayload">Decrypt the payload?</param>
        /// <returns>Session key and payload</returns>
        public static (byte[] SessionKey, byte[] Payload) DeriveSessionKey(
            in IPakeRecord identity, 
            in PakeAuth auth,
            in Action<Pake>? initializer = null, 
            in CryptoOptions? options = null, 
            in CryptoOptions? cryptoOptions = null, 
            in bool decryptPayload = false
            )
        {
            using PakeAuth request = auth;
            using Pake pake = new(new PakeRecord(identity), options?.Clone(), cryptoOptions?.Clone());
            if (initializer is not null) initializer(pake);
            byte[] payload = pake.HandleAuth(request, decryptPayload);
            return (pake.SessionKey.CloneArray(), payload);
        }
    }
}
