using System.ComponentModel.DataAnnotations;

namespace wan24.Crypto
{
    // Counter
    public partial class CryptoOptions
    {
        /// <summary>
        /// Counter MAC algorithm name (used for en-/decryption only)
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? CounterMacAlgorithm { get; set; }

        /// <summary>
        /// Counter KDF algorithm name (used for en-/decryption only)
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? CounterKdfAlgorithm { get; set; }

        /// <summary>
        /// Counter KDF iterations (used for en-/decryption only)
        /// </summary>
        [Range(1, int.MaxValue)]
        public int CounterKdfIterations { get; set; } = 1;

        /// <summary>
        /// Asymmetric counter algorithm name (for the key exchange data; used for en-/decryption and signature only)
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? AsymmetricCounterAlgorithm { get; set; }

        /// <summary>
        /// Counter private key (used for en-/decryption and signature only)
        /// </summary>
        public IAsymmetricPrivateKey? CounterPrivateKey { get; set; }

        /// <summary>
        /// Using a counter MAC?
        /// </summary>
        public bool UsingCounterMac => CounterMacAlgorithm != null || CounterMacAlgorithmIncluded || RequireCounterMac;

        /// <summary>
        /// Using a counter KDF?
        /// </summary>
        public bool UsingCounterKdf => CounterKdfAlgorithm != null || CounterKdfAlgorithmIncluded || RequireCounterKdf;

        /// <summary>
        /// Using an asymmetric counter algorithm?
        /// </summary>
        public bool UsingAsymmetricCounterAlgorithm => AsymmetricCounterAlgorithm != null || AsymmetricCounterAlgorithmIncluded || RequireAsymmetricCounterAlgorithm;

        /// <summary>
        /// Set the counter private key (used for en-/decryption and signature only)
        /// </summary>
        /// <param name="key">Private key</param>
        public void SetCounterPrivateKey(IAsymmetricPrivateKey key)
        {
            CounterPrivateKey = key;
            KeyExchangeDataIncluded = true;
            RequireKeyExchangeData = true;
        }
    }
}
