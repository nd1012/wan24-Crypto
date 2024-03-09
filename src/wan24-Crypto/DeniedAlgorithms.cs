using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Denied algorithms (won't be accepted for creating new keys, key exchange data, signatures or for encryption; may still be used for key exchange, signature validation and decryption)
    /// </summary>
    public static class DeniedAlgorithms
    {
        /// <summary>
        /// Asymmetric algorithms (key is the algorithm value, value is the algorithm name)
        /// </summary>
        private static readonly ConcurrentChangeTokenDictionary<int, string> AsymmetricAlgorithms = [];
        /// <summary>
        /// Asymmetric algorithms (key is the algorithm value, value is the algorithm name)
        /// </summary>
        private static readonly ConcurrentChangeTokenDictionary<int, string> EncryptionAlgorithms = [];

        /// <summary>
        /// Determine if an asymmetric algorithm was denied
        /// </summary>
        /// <param name="value">Algorithm value</param>
        /// <returns>If the algorithm was denied</returns>
        public static bool IsAsymmetricAlgorithmDenied(in int value) => AsymmetricAlgorithms.ContainsKey(value);

        /// <summary>
        /// Determine if an asymmetric algorithm was denied
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <returns>If the algorithm was denied</returns>
        public static bool IsAsymmetricAlgorithmDenied(string name) => AsymmetricAlgorithms.Values.Any(v => v == name);

        /// <summary>
        /// Determine if an encryption algorithm was denied
        /// </summary>
        /// <param name="value">Algorithm value</param>
        /// <returns>If the algorithm was denied</returns>
        public static bool IsEncryptionAlgorithmDenied(in int value) => EncryptionAlgorithms.ContainsKey(value);

        /// <summary>
        /// Determine if an encryption algorithm was denied
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <returns>If the algorithm was denied</returns>
        public static bool IsEncryptionAlgorithmDenied(string name) => EncryptionAlgorithms.Values.Any(v => v == name);

        /// <summary>
        /// Add an asymmetric algrithm
        /// </summary>
        /// <param name="algo">Algorithm</param>
        public static void AddAsymmetricAlgorithm(in IAsymmetricAlgorithm algo)
        {
            if(algo.KeyPool is Dictionary<int, IAsymmetricKeyPool> pools)
            {
                algo.KeyPool = null;
                pools.Values.DisposeAll();
            }
            AddAsymmetricAlgorithm(algo.Value, algo.Name);
        }

        /// <summary>
        /// Add an asymmetric algrithm
        /// </summary>
        /// <param name="value">Value</param>
        /// <param name="name">Name</param>
        public static void AddAsymmetricAlgorithm(in int value, in string name)
        {
            if(AsymmetricHelper.Algorithms.TryGetValue(name, out IAsymmetricAlgorithm? algo) && algo.KeyPool is Dictionary<int, IAsymmetricKeyPool> pools)
            {
                algo.KeyPool = null;
                pools.Values.DisposeAll();
            }
            AsymmetricAlgorithms[value] = name;
        }

        /// <summary>
        /// Add an encryption algrithm
        /// </summary>
        /// <param name="algo">Algorithm</param>
        public static void AddEncryptionAlgorithm(in EncryptionAlgorithmBase algo) => AddEncryptionAlgorithm(algo.Value, algo.Name);

        /// <summary>
        /// Add an encryption algrithm
        /// </summary>
        /// <param name="value">Value</param>
        /// <param name="name">Name</param>
        public static void AddEncryptionAlgorithm(in int value, in string name) => EncryptionAlgorithms[value] = name;
    }
}
