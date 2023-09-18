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
    }
}
