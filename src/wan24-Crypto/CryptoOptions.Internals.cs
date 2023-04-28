using wan24.ObjectValidation;

namespace wan24.Crypto
{
    // Internals
    public partial class CryptoOptions
    {
        /// <summary>
        /// KDF salt (used internal)
        /// </summary>
        [CountLimit(1, byte.MaxValue)]
        public byte[]? KdfSalt { get; set; }

        /// <summary>
        /// Counter KDF salt (used internal)
        /// </summary>
        [CountLimit(1, byte.MaxValue)]
        public byte[]? CounterKdfSalt { get; set; }

        /// <summary>
        /// MAC position within the cipher stream (used internal)
        /// </summary>
        public long MacPosition { get; set; }

        /// <summary>
        /// MAC (used internal for decryption)
        /// </summary>
        [CountLimit(byte.MaxValue)]
        public byte[]? Mac { get; set; }

        /// <summary>
        /// Has the header been processed (used internal)?
        /// </summary>
        public bool HeaderProcessed { get; set; }

        /// <summary>
        /// Password (used internal)
        /// </summary>
        [CountLimit(byte.MaxValue)]
        public byte[]? Password { get; set; }
    }
}
