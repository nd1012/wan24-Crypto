using wan24.Compression;
using wan24.Core;

namespace wan24.Crypto
{
    // Validation
    public partial record class CryptoOptions
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
            CryptoFlags requirements = Requirements,
                flags = Flags.OnlyFlags() & ~CryptoFlags.Compressed;
            if ((flags & requirements) != requirements) throw new CryptographicException($"Requirements not met ({flags}/{requirements})");
        }

        /// <summary>
        /// Validate the algorithms
        /// </summary>
        public void ValidateAlgorithms()
        {
            try
            {
                if (Algorithm is not null)
                {
                    EncryptionAlgorithmBase algo = EncryptionHelper.GetAlgorithm(Algorithm);
                    if (!algo.IsSupported) throw new InvalidDataException("Encryption algorithm isn't supported");
                }
                if (MacAlgorithm is not null)
                {
                    MacAlgorithmBase algo = MacHelper.GetAlgorithm(MacAlgorithm);
                    if (!algo.IsSupported) throw new InvalidDataException("MAC algorithm isn't supported");
                }
                if (KdfAlgorithm is not null)
                {
                    KdfAlgorithmBase kdfAlgo = KdfHelper.GetAlgorithm(KdfAlgorithm);
                    if (kdfAlgo.DefaultIterations > KdfIterations) throw new InvalidDataException("Invalid KDF iteration count");
                    if (!kdfAlgo.IsSupported) throw new InvalidDataException("KDF algorithm isn't supported");
                }
                if (AsymmetricAlgorithm is not null)
                {
                    IAsymmetricAlgorithm asymmetricAlgo = AsymmetricHelper.GetAlgorithm(AsymmetricAlgorithm);
                    if (AsymmetricKeyBits != 1 && !asymmetricAlgo.AllowedKeySizes.Contains(AsymmetricKeyBits)) throw new InvalidDataException("Invalid asymmetric key size");
                    if (!asymmetricAlgo.IsSupported) throw new InvalidDataException("Asymmetric algorithm isn't supported");
                    if (asymmetricAlgo.IsEllipticCurveAlgorithm && !EllipticCurves.IsCurveAllowed(AsymmetricKeyBits)) throw new InvalidDataException("Elliptic curve isn't allowed");
                }
                if (CounterMacAlgorithm is not null)
                {
                    MacAlgorithmBase algo = MacHelper.GetAlgorithm(CounterMacAlgorithm);
                    if (!algo.IsSupported) throw new InvalidDataException("Counter MAC algorithm isn't supported");
                }
                if (CounterKdfAlgorithm is not null)
                {
                    KdfAlgorithmBase kdfAlgo = KdfHelper.GetAlgorithm(CounterKdfAlgorithm);
                    if (kdfAlgo.DefaultIterations > KdfIterations) throw new InvalidDataException("Invalid counter KDF iteration count");
                    if (!kdfAlgo.IsSupported) throw new InvalidDataException("Counter KDF algorithm isn't supported");
                }
                if (AsymmetricCounterAlgorithm is not null)
                {
                    IAsymmetricAlgorithm asymmetricAlgo = AsymmetricHelper.GetAlgorithm(AsymmetricCounterAlgorithm);
                    if (!asymmetricAlgo.IsSupported) throw new InvalidDataException("Asymmetric counter algorithm isn't supported");
                }
                if (HashAlgorithm is not null)
                {
                    HashAlgorithmBase algo = HashHelper.GetAlgorithm(HashAlgorithm);
                    if (!algo.IsSupported) throw new InvalidDataException("Hash algorithm isn't supported");
                }
                if (Compression?.Algorithm is not null) CompressionHelper.GetAlgorithm(Compression.Algorithm);
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
