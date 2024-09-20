using System.ComponentModel.DataAnnotations;
using wan24.Core;

namespace wan24.Crypto
{
    // Permutation
    public static partial class EntropyHelper
    {
        /// <summary>
        /// Min. required Permutation entropy (zero to disable checks)
        /// </summary>
        [CliConfig]
        public static double MinPermutationEntropy { get; set; }

        /// <summary>
        /// Permutation entropy calculator window size (if the given data count is less than this value, the algorithm will return <see cref="MinPermutationEntropy"/>)
        /// </summary>
        [CliConfig, Range(3, int.MaxValue)]
        public static int PermutationWindowSize { get; set; } = 3;

        /// <summary>
        /// Permutation entropy algorithm
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="windowSize">Window size (if the given <c>data</c> count is less than this value, the algorithm will return <see cref="MinPermutationEntropy"/>)</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>data</c> was empty)</returns>
        public static double PermutationEntropy(in ReadOnlySpan<byte> data, in int? windowSize = null)
        {
            int len = data.Length,
                len2,
                i,
                permutation;
            if (len < 1) return double.MinValue;
            int winLen = windowSize ?? PermutationWindowSize;
            if (data.Length < winLen) return MinPermutationEntropy;
            len2 = len - winLen;
            OrderedDictionary<int, int> temp = new(Math.Min(256, len2));
            using (RentedArrayRefStruct<byte> window = new(len: winLen, clean: false))
                for (i = 0; i <= len2; i++)
                {
                    data.Slice(i, winLen).CopyTo(window.Span);
                    window.Span.Sort();
                    permutation = window.Span.CombineHashCodes();
                    if (!temp.TryAdd(permutation, 1))
                        temp[permutation]++;
                }
            double entropy = 0,
                probability;
            for (i = 0, len = temp.Count, len2++; i < len; i++)
            {
                probability = (double)temp[i] / len2;
                entropy -= probability * Math.Log2(probability);// Shannon entropy
            }
            return entropy;
        }
    }
}
