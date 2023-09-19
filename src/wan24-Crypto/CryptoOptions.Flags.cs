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
                if (HeaderVersion < 1 || HeaderVersion > HEADER_VERSION) throw new ArgumentException($"Invalid header version {HeaderVersion} in crypto flags", nameof(value));
                SerializerVersionIncluded = value.ContainsAnyFlag(CryptoFlags.SerializerVersionIncluded);
                MacIncluded = value.ContainsAnyFlag(CryptoFlags.MacIncluded);
                Compressed = value.ContainsAnyFlag(CryptoFlags.Compressed);
                MacIncluded = value.ContainsAnyFlag(CryptoFlags.MacIncluded);
                KdfAlgorithmIncluded = value.ContainsAnyFlag(CryptoFlags.KdfAlgorithmIncluded);
                KeyExchangeDataIncluded = value.ContainsAnyFlag(CryptoFlags.KeyExchangeDataIncluded);
                PayloadIncluded = value.ContainsAnyFlag(CryptoFlags.PayloadIncluded);
                TimeIncluded = value.ContainsAnyFlag(CryptoFlags.TimeIncluded);
                ForceMacCoverWhole = value.ContainsAnyFlag(CryptoFlags.ForceMacCoverWhole);
                HeaderVersionIncluded = value.ContainsAnyFlag(CryptoFlags.HeaderVersionIncluded);
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
