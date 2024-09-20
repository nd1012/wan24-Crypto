using System.ComponentModel.DataAnnotations;
using wan24.Core;

namespace wan24.Crypto
{
    // Rényi
    public static partial class EntropyHelper
    {
        /// <summary>
        /// Min. required Rényi entropy (zero to disable checks)
        /// </summary>
        [CliConfig]
        public static double MinRenyiEntropy { get; set; }

        /// <summary>
        /// Rényi entropy alpha value
        /// </summary>
        [CliConfig, Range(double.Epsilon, double.MaxValue)]
        public static double RenyiEntropyAlpha { get; set; } = 2;

        /// <summary>
        /// Rényi entropy algorithm
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="customAlpha">Custom alpha value</param>
        /// <param name="byteCounters">Byte counters</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>data</c> was empty)</returns>
        public static double RenyiEntropy(in ReadOnlySpan<byte> data, in double? customAlpha = null, OrderedDictionary<byte, int>? byteCounters = null)
        {
            int len = data.Length,
                len2,
                i;
            if (len < 1) return double.MinValue;
            double alpha = customAlpha ?? RenyiEntropyAlpha;
            ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(alpha, other: 0, nameof(customAlpha));
            byteCounters ??= GetByteCounters(data);
            double probability = 0;
            for (i = 0, len2 = byteCounters.Count; i < len2; i++) probability += Math.Pow((double)byteCounters[i] / len, alpha);
            return (1 / (1 - alpha)) * Math.Log2(probability);
        }
    }
}
