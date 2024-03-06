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
        public static readonly Dictionary<int, string> AsymmetricAlgorithms = [];
        /// <summary>
        /// Asymmetric algorithms (key is the algorithm value, value is the algorithm name)
        /// </summary>
        public static readonly Dictionary<int, string> EncryptionAlgorithms = [];

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
        public static bool IsAsymmetricAlgorithmDenied(in string name) => AsymmetricAlgorithms.ContainsValue(name);

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
        public static bool IsEncryptionAlgorithmDenied(in string name) => EncryptionAlgorithms.ContainsValue(name);
    }
}
