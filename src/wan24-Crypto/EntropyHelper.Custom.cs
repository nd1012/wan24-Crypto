using wan24.Core;

namespace wan24.Crypto
{
    // Custom
    public static partial class EntropyHelper
    {
        /// <summary>
        /// Custom entropy algorithm
        /// </summary>
        public static EntropyAlgorithm_Delegate? CustomAlgorithm { get; set; }

        /// <summary>
        /// Min. required custom entropy (zero to disable checks)
        /// </summary>
        [CliConfig]
        public static double MinCustomEntropy { get; set; }

        /// <summary>
        /// Delegate for an entropy algorithm
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="algo">Custom algorithm bits (excluding <see cref="Algorithms.Custom"/>)</param>
        /// <param name="byteCounters">Byte counters</param>
        /// <param name="throwOnInvalidAlgorithm">Throw an exception on an invalid value of <c>algo</c>?</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>str</c> was empty; <see cref="double.NaN"/>, if <c>algo</c> was invalid)</returns>
        public delegate double EntropyAlgorithm_Delegate(ReadOnlySpan<byte> data, int algo, OrderedDictionary<byte, int>? byteCounters = null, bool throwOnInvalidAlgorithm = false);
    }
}
