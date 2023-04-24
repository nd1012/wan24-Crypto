namespace wan24.Crypto
{
    /// <summary>
    /// Crypto helper
    /// </summary>
    public static class CryptoHelper
    {
        /// <summary>
        /// Force all default algorithms to be "post quantum-safe" (using <see cref="HybridAlgorithmHelper"/>)
        /// </summary>
        public static void ForcePostQuantumSafety()
        {
            if (!EncryptionHelper.DefaultAlgorithm.IsPostQuantum) EncryptionHelper.DefaultAlgorithm = EncryptionHelper.GetAlgorithm(EncryptionAes256CbcAlgorithm.ALGORITHM_NAME);
            if (!KdfHelper.DefaultAlgorithm.IsPostQuantum) KdfHelper.DefaultAlgorithm = KdfHelper.GetAlgorithm(KdfPbKdf2Algorithm.ALGORITHM_NAME);
            if (!HashHelper.DefaultAlgorithm.IsPostQuantum) HashHelper.DefaultAlgorithm = HashHelper.GetAlgorithm(HashSha512Algorithm.ALGORITHM_NAME);
            if (!MacHelper.DefaultAlgorithm.IsPostQuantum) MacHelper.DefaultAlgorithm = MacHelper.GetAlgorithm(MacHmacSha512Algorithm.ALGORITHM_NAME);
            OnForcePostQuantum?.Invoke(new());
            if (!AsymmetricHelper.DefaultKeyExchangeAlgorithm.IsPostQuantum && !(HybridAlgorithmHelper.KeyExchangeAlgorithm?.IsPostQuantum ?? false))
                AsymmetricHelper.DefaultKeyExchangeAlgorithm = AsymmetricHelper.Algorithms.Values.FirstOrDefault(a => a.CanExchangeKey && a.IsPostQuantum)
                    ?? throw new InvalidOperationException("No post quantum key exchange algorithm");
            if (!AsymmetricHelper.DefaultSignatureAlgorithm.IsPostQuantum && !(HybridAlgorithmHelper.SignatureAlgorithm?.IsPostQuantum ?? false))
                AsymmetricHelper.DefaultSignatureAlgorithm = AsymmetricHelper.Algorithms.Values.FirstOrDefault(a => a.CanSign && a.IsPostQuantum)
                    ?? throw new InvalidOperationException("No post quantum signature algorithm");
            EncryptionHelper.UseHybridOptions = true;
            AsymmetricHelper.UseHybridKeyExchangeOptions = true;
            AsymmetricHelper.UseHybridSignatureOptions = true;
        }

        /// <summary>
        /// Delegate for a force
        /// </summary>
        /// <param name="e"></param>
        public delegate void ForcePostQuantum_Delegate(EventArgs e);
        /// <summary>
        /// Raised when forcing post quantum
        /// </summary>
        public static event ForcePostQuantum_Delegate? OnForcePostQuantum;
    }
}
