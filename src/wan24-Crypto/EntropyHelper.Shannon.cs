using wan24.Core;

namespace wan24.Crypto
{
    // Shannon
    public static partial class EntropyHelper
    {
        /// <summary>
        /// Min. required Shannon bit entropy (zero to disable checks; depends on the data length! <c>20</c> for 8 byte)
        /// </summary>
        [CliConfig]
        public static double MinShannonBitEntropy { get; set; } = 20d;

        /// <summary>
        /// Min. required Shannon byte entropy (zero to disable checks; depends on the data length! <c>0.2</c> for 8 byte)
        /// </summary>
        [CliConfig]
        public static double MinShannonByteEntropy { get; set; } = 0.2d;

        /// <summary>
        /// Shannon bit entropy algorithm
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="byteCounters">Byte counters</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>data</c> was empty)</returns>
        public static double ShannonBitEntropy(in ReadOnlySpan<byte> data, OrderedDictionary<byte, int>? byteCounters = null)
        {
            int len = data.Length;
            if (len < 1) return double.MinValue;
            byteCounters ??= GetByteCounters(data);
            double res = 0,
                lenD = len;
            for (int i = 0, len2 = byteCounters.Count; i < len2; res -= Math.Log2(byteCounters[i] / lenD), i++) ;
            return res;
        }

        /// <summary>
        /// Shannon byte entropy algorithm
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="byteCounters">Byte counters</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>data</c> was empty)</returns>
        public static double ShannonByteEntropy(in ReadOnlySpan<byte> data, OrderedDictionary<byte, int>? byteCounters = null)
        {
            int len = data.Length;
            if (len < 1) return double.MinValue;
            byteCounters ??= GetByteCounters(data);
            double res = 0,
                lenD = len;
            for (int i = 0, len2 = byteCounters.Count; i < len2; res -= Math.Log(byteCounters[i] / lenD, 256), i++) ;
            return res;
        }
    }
}
