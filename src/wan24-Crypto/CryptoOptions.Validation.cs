﻿using wan24.Compression;
using wan24.Core;

namespace wan24.Crypto
{
    // Validation
    public partial class CryptoOptions
    {
        /// <summary>
        /// Maximum age
        /// </summary>
        public TimeSpan? MaximumAge { get; set; } = DefaultMaximumAge;

        /// <summary>
        /// Maximum time offset
        /// </summary>
        public TimeSpan? MaximumTimeOffset { get; set; } = DefaultMaximumTimeOffset;

        /// <summary>
        /// Validate the requirements
        /// </summary>
        public void ValidateRequirements()
        {
            CryptoFlags requirements = Requirements;
            if ((Flags.OnlyFlags() & requirements) != requirements) throw new CryptographicException("Requirements not met");
        }

        /// <summary>
        /// Validate the algorithms
        /// </summary>
        public void ValidateAlgorithms()
        {
            try
            {
                if (Algorithm != null) EncryptionHelper.GetAlgorithm(Algorithm);
                if (MacAlgorithm != null) MacHelper.GetAlgorithm(MacAlgorithm);
                if (KdfAlgorithm != null)
                {
                    KdfAlgorithmBase kdfAlgo = KdfHelper.GetAlgorithm(KdfAlgorithm);
                    if (kdfAlgo.DefaultIterations > KdfIterations) throw new InvalidDataException("Invalid KDF iteration count");
                }
                if (AsymmetricAlgorithm != null)
                {
                    IAsymmetricAlgorithm asymmetricAlgo = AsymmetricHelper.GetAlgorithm(AsymmetricAlgorithm);
                    if (!asymmetricAlgo.AllowedKeySizes.Contains(AsymmetricKeyBits)) throw new InvalidDataException("Invalid asymmetric key size");
                }
                if (CounterMacAlgorithm != null) MacHelper.GetAlgorithm(CounterMacAlgorithm);
                if (CounterKdfAlgorithm != null)
                {
                    KdfAlgorithmBase kdfAlgo = KdfHelper.GetAlgorithm(CounterKdfAlgorithm);
                    if (kdfAlgo.DefaultIterations > KdfIterations) throw new InvalidDataException("Invalid counter KDF iteration count");
                }
                if (AsymmetricCounterAlgorithm != null) AsymmetricHelper.GetAlgorithm(AsymmetricCounterAlgorithm);
                if (HashAlgorithm != null) HashHelper.GetAlgorithm(HashAlgorithm);
                if (Compression?.Algorithm != null) CompressionHelper.GetAlgorithm(Compression.Algorithm);

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
