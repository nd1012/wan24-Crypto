﻿using System.ComponentModel.DataAnnotations;
using System.Diagnostics.CodeAnalysis;
using wan24.Core;

namespace wan24.Crypto
{
    // Counter
    public partial record class CryptoOptions
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
        public int CounterKdfIterations { get; set; } = 1;// Dummy value to satisfy the object validation

        /// <summary>
        /// Counter KDF options
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? CounterKdfOptions { get; set; }

        /// <summary>
        /// Asymmetric counter algorithm name (for the key exchange data; used for en-/decryption and signature only)
        /// </summary>
        [StringLength(byte.MaxValue)]
        public string? AsymmetricCounterAlgorithm { get; set; }

        /// <summary>
        /// Counter private key (for en-/decryption/key exchange/signature)
        /// </summary>
        [SensitiveData]
        public IAsymmetricPrivateKey? CounterPrivateKey { get; set; }

        /// <summary>
        /// Counter private key (used for encryption/key exchange)
        /// </summary>
        public IAsymmetricPublicKey? CounterPublicKey { get; set; }

        /// <summary>
        /// Using a counter MAC?
        /// </summary>
        public bool UsingCounterMac => CounterMacAlgorithm is not null || RequireCounterMac;

        /// <summary>
        /// Using a counter KDF?
        /// </summary>
        public bool UsingCounterKdf => CounterKdfAlgorithm is not null || RequireCounterKdf;

        /// <summary>
        /// Using an asymmetric counter algorithm?
        /// </summary>
        public bool UsingAsymmetricCounterAlgorithm => AsymmetricCounterAlgorithm is not null;

        /// <summary>
        /// Set the counter keys (used for en-/decryption and signature only)
        /// </summary>
        /// <param name="privateKey">Private key</param>
        /// <param name="publicKey">Public key (required for encryption, if not using a PFS key)</param>
        [MemberNotNull(nameof(CounterPrivateKey), nameof(AsymmetricCounterAlgorithm))]
        public void SetCounterKeys(IAsymmetricPrivateKey privateKey, IAsymmetricPublicKey? publicKey = null)
        {
            try
            {
                if (publicKey is not null && publicKey.Algorithm != privateKey.Algorithm) throw new ArgumentException("Algorithm mismatch", nameof(publicKey));
                CounterPrivateKey = privateKey;
                CounterPublicKey = publicKey;
                AsymmetricCounterAlgorithm = privateKey.Algorithm.Name;
                KeyExchangeDataIncluded = true;
                RequireKeyExchangeData = true;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }
    }
}
