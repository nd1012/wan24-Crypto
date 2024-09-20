using wan24.Core;

namespace wan24.Crypto
{
    // Min
    public static partial class EntropyHelper
    {
        /// <summary>
        /// Max. required Min entropy (zero to disable checks)
        /// </summary>
        [CliConfig]
        public static double MaxMinEntropy { get; set; }

        /// <summary>
        /// Min entropy algorithm
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="byteCounters">Byte counters</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>data</c> was empty)</returns>
        public static double MinEntropy(in ReadOnlySpan<byte> data, OrderedDictionary<byte, int>? byteCounters = null)
        {
            int len = data.Length;
            if (len < 1) return double.MinValue;
            byteCounters ??= GetByteCounters(data);
            int max = 0;
            for (int i = 0, len2 = byteCounters.Count; i < len2; i++)
                if (byteCounters[i] > max)
                    max = byteCounters[i];
            return -Math.Log2((double)max / len);
        }
    }
}
