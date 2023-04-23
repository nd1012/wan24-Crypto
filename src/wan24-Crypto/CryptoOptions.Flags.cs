using wan24.Core;

namespace wan24.Crypto
{
    // Flags
    public partial class CryptoOptions
    {
        /// <summary>
        /// Header version included?
        /// </summary>
        public bool HeaderVersionIncluded { get; set; } = true;

        /// <summary>
        /// Serializer version included?
        /// </summary>
        public bool SerializerVersionIncluded { get; set; } = true;

        /// <summary>
        /// MAC included?
        /// </summary>
        public bool MacIncluded { get; set; } = true;

        /// <summary>
        /// Compressed?
        /// </summary>
        public bool Compressed { get; set; } = true;

        /// <summary>
        /// MAC algorithm included?
        /// </summary>
        public bool MacAlgorithmIncluded { get; set; } = true;

        /// <summary>
        /// KDF algorithm included?
        /// </summary>
        public bool KdfAlgorithmIncluded { get; set; } = true;

        /// <summary>
        /// Asymmetric algorithm (for the key exchange data) included?
        /// </summary>
        public bool AsymmetricAlgorithmIncluded { get; set; }

        /// <summary>
        /// Counter MAC algorithm included?
        /// </summary>
        public bool CounterMacAlgorithmIncluded { get; set; }

        /// <summary>
        /// Counter KDF algorithm included?
        /// </summary>
        public bool CounterKdfAlgorithmIncluded { get; set; }

        /// <summary>
        /// Asymmetric counter algorithm (for the key exchange data) included?
        /// </summary>
        public bool AsymmetricCounterAlgorithmIncluded { get; set; }

        /// <summary>
        /// Key exchange data included?
        /// </summary>
        public bool KeyExchangeDataIncluded { get; set; }

        /// <summary>
        /// Payload included?
        /// </summary>
        public bool PayloadIncluded { get; set; }

        /// <summary>
        /// Time included?
        /// </summary>
        public bool TimeIncluded { get; set; }

        /// <summary>
        /// Forced the MAC to cover the whole data?
        /// </summary>
        public bool ForceMacCoverWhole { get; set; }

        /// <summary>
        /// Flags included?
        /// </summary>
        public bool FlagsIncluded { get; set; } = true;

        /// <summary>
        /// Flags
        /// </summary>
        public CryptoFlags Flags
        {
            get
            {
                CryptoFlags res = (CryptoFlags)HeaderVersion;
                if (SerializerVersionIncluded) res |= CryptoFlags.SerializerVersionIncluded;
                if (MacIncluded) res |= CryptoFlags.MacIncluded;
                if (Compressed) res |= CryptoFlags.Compressed;
                if (MacIncluded) res |= CryptoFlags.MacIncluded;
                if (KdfAlgorithmIncluded) res |= CryptoFlags.KdfAlgorithmIncluded;
                if (AsymmetricAlgorithmIncluded) res |= CryptoFlags.AsymmetricAlgorithmIncluded;
                if (CounterMacAlgorithmIncluded) res |= CryptoFlags.CounterMacAlgorithmIncluded;
                if (CounterKdfAlgorithmIncluded) res |= CryptoFlags.CounterKdfAlgorithmIncluded;
                if (AsymmetricCounterAlgorithmIncluded) res |= CryptoFlags.AsymmetricCounterAlgorithmIncluded;
                if (KeyExchangeDataIncluded) res |= CryptoFlags.KeyExchangeDataIncluded;
                if (PayloadIncluded) res |= CryptoFlags.PayloadIncluded;
                if (TimeIncluded) res |= CryptoFlags.TimeIncluded;
                if (ForceMacCoverWhole) res |= CryptoFlags.ForceMacCoverWhole;
                if (HeaderVersionIncluded) res |= CryptoFlags.HeaderVersionIncluded;
                return res;
            }
            set
            {
                HeaderVersion = (int)value.RemoveFlags();
                if (HeaderVersion < 1 || HeaderVersion > HEADER_VERSION) throw new CryptographicException($"Invalid header version {HeaderVersion} in crypto flags");
                SerializerVersionIncluded = value.HasFlag(CryptoFlags.SerializerVersionIncluded);
                MacIncluded = value.HasFlag(CryptoFlags.MacIncluded);
                Compressed = value.HasFlag(CryptoFlags.Compressed);
                MacIncluded = value.HasFlag(CryptoFlags.MacIncluded);
                KdfAlgorithmIncluded = value.HasFlag(CryptoFlags.KdfAlgorithmIncluded);
                AsymmetricAlgorithmIncluded = value.HasFlag(CryptoFlags.AsymmetricAlgorithmIncluded);
                CounterMacAlgorithmIncluded = value.HasFlag(CryptoFlags.CounterMacAlgorithmIncluded);
                CounterKdfAlgorithmIncluded = value.HasFlag(CryptoFlags.CounterKdfAlgorithmIncluded);
                AsymmetricCounterAlgorithmIncluded = value.HasFlag(CryptoFlags.AsymmetricCounterAlgorithmIncluded);
                KeyExchangeDataIncluded = value.HasFlag(CryptoFlags.KeyExchangeDataIncluded);
                PayloadIncluded = value.HasFlag(CryptoFlags.PayloadIncluded);
                TimeIncluded = value.HasFlag(CryptoFlags.TimeIncluded);
                ForceMacCoverWhole = value.HasFlag(CryptoFlags.ForceMacCoverWhole);
                HeaderVersionIncluded = value.HasFlag(CryptoFlags.HeaderVersionIncluded);
            }
        }

        /// <summary>
        /// Exclude everything
        /// </summary>
        /// <param name="requireNothing">Require nothing, too?</param>
        /// <returns>This</returns>
        public CryptoOptions IncludeNothing(bool requireNothing = true)
        {
            Flags = (CryptoFlags)HeaderVersion;
            if (requireNothing) Requirements = Flags;
            return this;
        }
    }
}
