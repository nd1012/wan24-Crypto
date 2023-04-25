using wan24.Core;

namespace wan24.Crypto
{
    // Requirements
    public partial class CryptoOptions
    {
        /// <summary>
        /// Require the header version (when decrypting)
        /// </summary>
        public bool RequireHeaderVersion { get; set; } = true;

        /// <summary>
        /// Require the serializer version (when decrypting)
        /// </summary>
        public bool RequireSerializerVersion { get; set; } = true;

        /// <summary>
        /// Require a MAC (when decrypting)
        /// </summary>
        public bool RequireMac { get; set; } = true;

        /// <summary>
        /// Require KDF (when decrypting)
        /// </summary>
        public bool RequireKdf { get; set; } = true;

        /// <summary>
        /// Require a counter MAC (when decrypting)
        /// </summary>
        public bool RequireCounterMac { get; set; }

        /// <summary>
        /// Require an asymmetric counter algorithm (when decrypting)
        /// </summary>
        public bool RequireAsymmetricCounterAlgorithm { get; set; }

        /// <summary>
        /// Require counter KDF (when decrypting)
        /// </summary>
        public bool RequireCounterKdf { get; set; }

        /// <summary>
        /// Require key exchange data (when decrypting)
        /// </summary>
        public bool RequireKeyExchangeData { get; set; }

        /// <summary>
        /// Require payload (when decrypting)
        /// </summary>
        public bool RequirePayload { get; set; }

        /// <summary>
        /// Require a time (when decrypting)
        /// </summary>
        public bool RequireTime { get; set; }

        /// <summary>
        /// Require the MAC to cover the whole data (when decrypting)
        /// </summary>
        public bool RequireMacCoverWhole { get; set; }

        /// <summary>
        /// Requirements
        /// </summary>
        public CryptoFlags Requirements
        {
            get
            {
                CryptoFlags res = CryptoFlags.Version1;
                if (RequireSerializerVersion) res |= CryptoFlags.SerializerVersionIncluded;
                if (RequireMac) res |= CryptoFlags.MacIncluded;
                if (RequireKdf) res |= CryptoFlags.KdfAlgorithmIncluded;
                if (RequireCounterMac) res |= CryptoFlags.RequireCounterMac;
                if (RequireAsymmetricCounterAlgorithm) res |= CryptoFlags.RequireAsymmetricCounterAlgorithm;
                if (RequireCounterKdf) res |= CryptoFlags.RequireCounterKdfAlgorithm;
                if (RequireKeyExchangeData) res |= CryptoFlags.KeyExchangeDataIncluded;
                if (RequirePayload) res |= CryptoFlags.PayloadIncluded;
                if (RequireTime) res |= CryptoFlags.TimeIncluded;
                if (RequireMacCoverWhole) res |= CryptoFlags.ForceMacCoverWhole;
                if (RequireHeaderVersion) res |= CryptoFlags.HeaderVersionIncluded;
                return res.OnlyFlags();
            }
            set
            {
                RequireSerializerVersion = value.HasFlag(CryptoFlags.SerializerVersionIncluded);
                RequireMac = value.HasFlag(CryptoFlags.MacIncluded);
                RequireKdf = value.HasFlag(CryptoFlags.KdfAlgorithmIncluded);
                RequireCounterMac = value.HasFlag(CryptoFlags.RequireCounterMac);
                RequireAsymmetricCounterAlgorithm = value.HasFlag(CryptoFlags.RequireAsymmetricCounterAlgorithm);
                RequireCounterKdf = value.HasFlag(CryptoFlags.RequireCounterKdfAlgorithm);
                RequireKeyExchangeData = value.HasFlag(CryptoFlags.KeyExchangeDataIncluded);
                RequirePayload = value.HasFlag(CryptoFlags.PayloadIncluded);
                RequireTime = value.HasFlag(CryptoFlags.TimeIncluded);
                RequireMacCoverWhole = value.HasFlag(CryptoFlags.ForceMacCoverWhole);
                RequireHeaderVersion = value.HasFlag(CryptoFlags.HeaderVersionIncluded);
            }
        }
    }
}
