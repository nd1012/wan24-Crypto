using wan24.Core;

namespace wan24.Crypto
{
    // Min
    public static partial class EntropyHelper
    {
        /// <summary>
        /// Min. required Min entropy (zero to disable checks; depends on the data length! <c>2.5</c> for 8 byte)
        /// </summary>
        [CliConfig]
        public static double MinMinEntropy { get; set; } = 2.5d;

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
            EnsureValidByteCounters(byteCounters);
            int max = 0;
            for (int i = 0, len2 = byteCounters.Count, cnt; i < len2; i++)
            {
                cnt = byteCounters[i];
                if (cnt > max) max = cnt;
            }
            return -Math.Log2((double)max / len);
        }
    }
}
