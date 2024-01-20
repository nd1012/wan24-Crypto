using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Crypto helper
    /// </summary>
    public static class CryptoHelper
    {
        /// <summary>
        /// Has the post quantum-safety been forced?
        /// </summary>
        public static bool PostQuantumSafetyForced { get; private set; }

        /// <summary>
        /// Has the post quantum-safety been forced strictly (no pre quantum-algorithms are allowed)?
        /// </summary>
        public static bool StrictPostQuantumSafety { get; private set; }

        /// <summary>
        /// Force all default algorithms to be "post quantum-safe" (using <see cref="HybridAlgorithmHelper"/>)
        /// </summary>
        /// <param name="strict">Force strictly (no pre quantum-algorithms are allowed)?</param>
        public static void ForcePostQuantumSafety(bool strict = false)
        {
            try
            {
                if (!EncryptionHelper.DefaultAlgorithm.IsPostQuantum) EncryptionHelper.DefaultAlgorithm = EncryptionHelper.GetAlgorithm(EncryptionAes256CbcAlgorithm.ALGORITHM_NAME);
                if (!KdfHelper.DefaultAlgorithm.IsPostQuantum) KdfHelper.DefaultAlgorithm = KdfHelper.GetAlgorithm(KdfPbKdf2Algorithm.ALGORITHM_NAME);
                if (!HashHelper.DefaultAlgorithm.IsPostQuantum) HashHelper.DefaultAlgorithm = HashHelper.GetAlgorithm(HashSha3_512Algorithm.ALGORITHM_NAME);
                if (!MacHelper.DefaultAlgorithm.IsPostQuantum) MacHelper.DefaultAlgorithm = MacHelper.GetAlgorithm(MacHmacSha3_512Algorithm.ALGORITHM_NAME);
                OnForcePostQuantum?.Invoke(new(!PostQuantumSafetyForced, strict));
                if (!AsymmetricHelper.DefaultKeyExchangeAlgorithm.IsPostQuantum && !(HybridAlgorithmHelper.KeyExchangeAlgorithm?.IsPostQuantum ?? false))
                    AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricHelper.Algorithms.Values.FirstOrDefault(a => a.CanExchangeKey && a.IsPostQuantum)
                        ?? throw new InvalidOperationException("No post quantum key exchange algorithm");
                if (!AsymmetricHelper.DefaultSignatureAlgorithm.IsPostQuantum && !(HybridAlgorithmHelper.SignatureAlgorithm?.IsPostQuantum ?? false))
                    AsymmetricHelper.DefaultSignatureAlgorithm = AsymmetricHelper.Algorithms.Values.FirstOrDefault(a => a.CanSign && a.IsPostQuantum)
                        ?? throw new InvalidOperationException("No post quantum signature algorithm");
                EncryptionHelper.UseHybridOptions = true;
                AsymmetricHelper.UseHybridKeyExchangeOptions = true;
                AsymmetricHelper.UseHybridSignatureOptions = true;
                StrictPostQuantumSafety = strict;
                PostQuantumSafetyForced = true;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Remove unsupported cryptographic algorithms
        /// </summary>
        /// <param name="updateDefaultOptions">Update factory defaults to use alternative algorithms</param>
        /// <returns>Removed algorithms</returns>
        public static ICryptoAlgorithm[] RemoveUnsupportedAlgorithms(in bool updateDefaultOptions = true)
        {
            List<ICryptoAlgorithm> res = [];
            bool Remove<T>(ICryptoAlgorithm algo, IDictionary<string, T> dict) where T : ICryptoAlgorithm
            {
                if (!dict.TryGetValue(algo.Name, out T? registered) || algo.GetType() != registered.GetType()) return false;
                dict.Remove(algo.Name, out _);
                res.Add(algo);
                return true;
            }
            if (ENV.IsBrowserApp)
            {
                // Browser doesn't support many algorithms...
                if (
                    Remove(AsymmetricEcDiffieHellmanAlgorithm.Instance, AsymmetricHelper.Algorithms) &&
                    AsymmetricHelper.DefaultKeyExchangeAlgorithm.GetType() == typeof(AsymmetricEcDiffieHellmanAlgorithm)
                    )
                    AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricVoidAlgorithm.Instance;
                if (
                    Remove(AsymmetricEcDsaAlgorithm.Instance, AsymmetricHelper.Algorithms) &&
                    AsymmetricHelper.DefaultSignatureAlgorithm.GetType() == typeof(AsymmetricEcDsaAlgorithm)
                    )
                    AsymmetricHelper.DefaultSignatureAlgorithm = AsymmetricVoidAlgorithm.Instance;
                if (
                    Remove(KdfSp800_108HmacCtrKbKdfAlgorithm.Instance, KdfHelper.Algorithms) &&
                    KdfHelper.DefaultAlgorithm.GetType() == typeof(KdfSp800_108HmacCtrKbKdfAlgorithm)
                    )
                    KdfHelper.DefaultAlgorithm = KdfPbKdf2Algorithm.Instance;
                if (
                    Remove(EncryptionAes256CbcAlgorithm.Instance, EncryptionHelper.Algorithms) &&
                    EncryptionHelper.DefaultAlgorithm.GetType() == typeof(EncryptionAes256CbcAlgorithm)
                    )
                    EncryptionHelper.DefaultAlgorithm = EncryptionVoidAlgorithm.Instance;
                if (updateDefaultOptions)
                {
                    CryptoOptions options = Pake.DefaultOptions;
                    if (res.Any(a => a.Name == options.KdfAlgorithm && KdfHelper.Algorithms.TryGetValue(a.Name, out KdfAlgorithmBase? kdf) && a.GetType() == kdf.GetType()))
                        Pake.DefaultOptions = options.WithKdf(
                            KdfHelper.DefaultAlgorithm.Name,
                            KdfHelper.DefaultAlgorithm.DefaultIterations,
                            KdfHelper.DefaultAlgorithm.DefaultKdfOptions
                            );
                    options = Pake.DefaultCryptoOptions;
                    if (
                        options.AsymmetricAlgorithm is not null &&
                        res.Any(a => a.Name == options.AsymmetricAlgorithm && AsymmetricHelper.Algorithms.TryGetValue(a.Name, out IAsymmetricAlgorithm? aa) && a.GetType() == aa.GetType())
                        )
                        Pake.DefaultCryptoOptions = options.WithKeyExchangeAlgorithm(
                            AsymmetricHelper.DefaultKeyExchangeAlgorithm.Name, 
                            AsymmetricHelper.DefaultKeyExchangeAlgorithm.DefaultKeySize
                            );
                    if (
                        options.AsymmetricCounterAlgorithm is not null &&
                        res.Any(a => a.Name == options.AsymmetricCounterAlgorithm && AsymmetricHelper.Algorithms.TryGetValue(a.Name, out IAsymmetricAlgorithm? aa) && a.GetType() == aa.GetType())
                        )
                    {
                        options.AsymmetricCounterAlgorithm = AsymmetricHelper.DefaultKeyExchangeAlgorithm.Name;
                        Pake.DefaultCryptoOptions = options;
                    }
                    if (res.Any(a => a.Name == options.Algorithm && EncryptionHelper.Algorithms.TryGetValue(a.Name, out EncryptionAlgorithmBase? enc) && a.GetType() == enc.GetType()))
                        Pake.DefaultCryptoOptions = options.WithEncryptionAlgorithm(EncryptionVoidAlgorithm.ALGORITHM_NAME);
                    if (
                        options.KdfAlgorithm is not null &&
                        res.Any(a => a.Name == options.KdfAlgorithm && KdfHelper.Algorithms.TryGetValue(a.Name, out KdfAlgorithmBase? kdf) && a.GetType() == kdf.GetType())
                        )
                        Pake.DefaultCryptoOptions = options.WithKdf(
                            KdfHelper.DefaultAlgorithm.Name, 
                            KdfHelper.DefaultAlgorithm.DefaultIterations, 
                            KdfHelper.DefaultAlgorithm.DefaultKdfOptions
                            );
                    if (
                        options.CounterKdfAlgorithm is not null &&
                        res.Any(a => a.Name == options.CounterKdfAlgorithm && KdfHelper.Algorithms.TryGetValue(a.Name, out KdfAlgorithmBase? kdf) && a.GetType() == kdf.GetType())
                        )
                        Pake.DefaultCryptoOptions = options.WithCounterKdf(
                            KdfHelper.DefaultAlgorithm.Name, 
                            KdfHelper.DefaultAlgorithm.DefaultIterations, 
                            KdfHelper.DefaultAlgorithm.DefaultKdfOptions
                            );
                }
            }
            if (!Shake128.IsSupported)
            {
                // SHA3 relies on the Shake hash algorithm
                if (
                    Remove(HashShake128Algorithm.Instance, HashHelper.Algorithms) &&
                    HashHelper.DefaultAlgorithm.GetType() == typeof(HashShake128Algorithm)
                    )
                    HashHelper.DefaultAlgorithm = HashSha512Algorithm.Instance;
                if (
                    Remove(HashShake256Algorithm.Instance, HashHelper.Algorithms) &&
                    HashHelper.DefaultAlgorithm.GetType() == typeof(HashShake256Algorithm)
                    )
                    HashHelper.DefaultAlgorithm = HashSha512Algorithm.Instance;
                if (
                    Remove(HashSha3_256Algorithm.Instance, HashHelper.Algorithms) &&
                    HashHelper.DefaultAlgorithm.GetType() == typeof(HashSha3_256Algorithm)
                    )
                    HashHelper.DefaultAlgorithm = HashSha512Algorithm.Instance;
                if (
                    Remove(HashSha3_384Algorithm.Instance, HashHelper.Algorithms) &&
                    HashHelper.DefaultAlgorithm.GetType() == typeof(HashSha3_384Algorithm)
                    )
                    HashHelper.DefaultAlgorithm = HashSha512Algorithm.Instance;
                if (
                    Remove(HashSha3_512Algorithm.Instance, HashHelper.Algorithms) &&
                    HashHelper.DefaultAlgorithm.GetType() == typeof(HashSha3_512Algorithm)
                    )
                    HashHelper.DefaultAlgorithm = HashSha512Algorithm.Instance;
                if (
                    Remove(MacHmacSha3_256Algorithm.Instance, MacHelper.Algorithms) &&
                    MacHelper.DefaultAlgorithm.GetType() == typeof(MacHmacSha3_256Algorithm)
                    )
                    MacHelper.DefaultAlgorithm = MacHmacSha512Algorithm.Instance;
                if (
                    Remove(MacHmacSha3_384Algorithm.Instance, MacHelper.Algorithms) &&
                    MacHelper.DefaultAlgorithm.GetType() == typeof(MacHmacSha3_384Algorithm)
                    )
                    MacHelper.DefaultAlgorithm = MacHmacSha512Algorithm.Instance;
                if (
                    Remove(MacHmacSha3_512Algorithm.Instance, MacHelper.Algorithms) &&
                    MacHelper.DefaultAlgorithm.GetType() == typeof(MacHmacSha3_512Algorithm)
                    )
                    MacHelper.DefaultAlgorithm = MacHmacSha512Algorithm.Instance;
                if (updateDefaultOptions)
                {
                    CryptoOptions options = Pake.DefaultOptions;
                    if (res.Any(a => a.Name == options.MacAlgorithm && MacHelper.Algorithms.TryGetValue(a.Name, out MacAlgorithmBase? mac) && a.GetType() == mac.GetType()))
                        Pake.DefaultOptions = options.WithMac(MacHmacSha512Algorithm.ALGORITHM_NAME);
                    options = Pake.DefaultCryptoOptions;
                    if (
                        options.MacAlgorithm is not null &&
                        res.Any(a => a.Name == options.MacAlgorithm && MacHelper.Algorithms.TryGetValue(a.Name, out MacAlgorithmBase? mac) && a.GetType() == mac.GetType())
                        )
                        Pake.DefaultCryptoOptions = options.WithMac(MacHmacSha512Algorithm.ALGORITHM_NAME);
                    if (res.Any(a => a.Name == KdfPbKdf2Options.DefaultHashAlgorithm && HashHelper.Algorithms.TryGetValue(a.Name, out HashAlgorithmBase? hash) && a.GetType() == hash.GetType()))
                        KdfPbKdf2Options.DefaultHashAlgorithm = HashSha384Algorithm.ALGORITHM_NAME;
                }
            }
            return res.Count == 0 ? [] : [.. res];
        }

        /// <summary>
        /// Delegate for a force post quantum handler
        /// </summary>
        /// <param name="e">Arguments</param>
        public delegate void ForcePostQuantum_Delegate(ForcePostQuantumEventArgs e);
        /// <summary>
        /// Raised when forcing post quantum
        /// </summary>
        public static event ForcePostQuantum_Delegate? OnForcePostQuantum;
    }
}
