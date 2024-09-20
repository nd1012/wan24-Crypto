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
    }
}
