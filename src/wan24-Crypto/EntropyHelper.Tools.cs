using wan24.Core;

namespace wan24.Crypto
{
    // Tools
    public static partial class EntropyHelper
    {
        /// <summary>
        /// Get byte counters
        /// </summary>
        /// <param name="data">Data</param>
        /// <returns>Byte counters</returns>
        public static OrderedDictionary<byte, int> GetByteCounters(in ReadOnlySpan<byte> data)
        {
            int len = data.Length;
            OrderedDictionary<byte, int> res = new(Math.Min(256, len));
            byte b;
            for (int i = 0; i < len; i++)
            {
                b = data[i];
                if (!res.TryAdd(b, 1)) res[b]++;
            }
            return res;
        }

        /// <summary>
        /// Ensure valid byte counters
        /// </summary>
        /// <param name="byteCounters">Byte counters</param>
        /// <returns>Valid byte counters</returns>
        /// <exception cref="ArgumentException">Invalid byte counters</exception>
        public static OrderedDictionary<byte, int> EnsureValidByteCounters(in OrderedDictionary<byte, int> byteCounters)
        {
            int len = byteCounters.Count;
            if (len < 1) throw new ArgumentException("Empty byte counters", nameof(byteCounters));
            for (int i = 0; i < len; i++)
                if (byteCounters[i] < 1)
                    throw new ArgumentException("Invalid byte counters", nameof(byteCounters));
            return byteCounters;
        }
    }
}
