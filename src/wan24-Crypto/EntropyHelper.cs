using System.Text;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Entropy helper
    /// </summary>
    public static class EntropyHelper
    {
        /// <summary>
        /// Single default algorithm
        /// </summary>
        [CliConfig]
        public static Algorithms DefaultAlgorithm { get; set; } = Algorithms.ShannonBit;

        /// <summary>
        /// Default algorithms
        /// </summary>
        [CliConfig]
        public static Algorithms DefaultAlgorithms { get; set; } = Algorithms.ALL;

        /// <summary>
        /// Custom entropy algorithm
        /// </summary>
        public static EntropyAlgorithm_Delegate? CustomAlgorithm { get; set; }

        /// <summary>
        /// Min. required Shannon bit entropy (zero to disable checks)
        /// </summary>
        [CliConfig]
        public static double MinShannonBitEntropy { get; set; }

        /// <summary>
        /// Min. required Shannon byte entropy (zero to disable checks)
        /// </summary>
        [CliConfig]
        public static double MinShannonByteEntropy { get; set; }

        /// <summary>
        /// Min. required custom entropy (zero to disable checks)
        /// </summary>
        [CliConfig]
        public static double MinCustomEntropy { get; set; }

        /// <summary>
        /// Shannon bit entropy algorithm
        /// </summary>
        /// <param name="data">Data</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>data</c> was empty)</returns>
        public static double ShannonBitEntropy(in ReadOnlySpan<byte> data)
        {
            int len = data.Length;
            if (len < 1) return double.MinValue;
            int[] counters;
            {
                Dictionary<byte, int> temp = new(Math.Min(256, len));
                for (int i = 0; i < len; i++)
                    if (!temp.TryAdd(data[i], 1))
                        temp[data[i]]++;
                counters = [.. temp.Values];
            }
            double res = 0,
                lenD = len;
            for (int i = 0, mapLen = counters.Length; i < mapLen; res -= Math.Log2(counters[i] / lenD), i++) ;
            return res / lenD;
        }

        /// <summary>
        /// Shannon byte entropy algorithm
        /// </summary>
        /// <param name="data">Data</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>data</c> was empty)</returns>
        public static double ShannonByteEntropy(in ReadOnlySpan<byte> data)
        {
            int len = data.Length;
            if (len < 1) return double.MinValue;
            int[] counters;
            {
                Dictionary<byte, int> temp = new(Math.Min(256, len));
                for (int i = 0; i < len; i++)
                    if (!temp.TryAdd(data[i], 1))
                        temp[data[i]]++;
                counters = [.. temp.Values];
            }
            double res = 0,
                lenD = len;
            for (int i = 0, mapLen = counters.Length; i < mapLen; res -= Math.Log(counters[i] / lenD, 256), i++) ;
            return res / lenD;
        }

        /// <summary>
        /// Get the entropy using a specific algorithm
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="algo">Algorithm</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>data</c> was empty)</returns>
        public static double CalculateEntropy(in ReadOnlySpan<byte> data, Algorithms? algo = null)
            => (algo ??= DefaultAlgorithm) switch
            {
                Algorithms.ShannonBit => ShannonBitEntropy(data),
                Algorithms.ShannonByte => ShannonByteEntropy(data),
                Algorithms.None => throw new ArgumentException($"Invalid algorithm \"{algo}\"", nameof(algo)),
                _ => CustomAlgorithm is null 
                    ? throw new ArgumentException($"Invalid algorithm \"{algo}\"", nameof(algo)) 
                    : CustomAlgorithm(data, (int)(algo.Value & ~Algorithms.Custom), throwOnInvalidAlgorithm: true)
            };

        /// <summary>
        /// Check if the entropy is valid
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="algos">Algorithms to use</param>
        /// <param name="throwOnError">If to throw an exception on error</param>
        /// <returns>If the entropy is valid (empty data or no algorithms is valid always!)</returns>
        /// <exception cref="InvalidDataException">Invalid entropy</exception>
        public static bool CheckEntropy(in ReadOnlySpan<byte> data, Algorithms? algos = null, in bool throwOnError = false)
        {
            if (data.Length < 1) return true;
            algos ??= DefaultAlgorithms;
            if (algos.Value == Algorithms.None) return true;
            double entropy;
            // Shannon bit
            if (MinShannonBitEntropy != 0 && (algos.Value & Algorithms.ShannonBit) == Algorithms.ShannonBit && (entropy = ShannonBitEntropy(data)) < MinShannonBitEntropy)
            {
                if (!throwOnError) return false;
                throw new InvalidDataException($"Shannon bit entropy of {entropy} doesn't fit the min. required entropy of {MinShannonBitEntropy}");
            }
            // Shannon byte
            if (MinShannonByteEntropy != 0 && (algos.Value & Algorithms.ShannonByte) == Algorithms.ShannonByte && (entropy = ShannonByteEntropy(data)) < MinShannonByteEntropy)
            {
                if (!throwOnError) return false;
                throw new InvalidDataException($"Shannon byte entropy of {entropy} doesn't fit the min. required entropy of {MinShannonByteEntropy}");
            }
            // Custom
            if (CustomAlgorithm is not null && MinCustomEntropy != 0 && (algos.Value & Algorithms.Custom) == Algorithms.Custom)
            {
                int customAlgo = (int)(algos.Value & Algorithms.ALL);
                entropy = CustomAlgorithm(data, customAlgo);
                if (double.IsNaN(entropy))
                {
                    if (!throwOnError) return false;
                    throw new ArgumentException($"Invalid custom entropy algorithm {customAlgo}", nameof(algos));
                }
                if (entropy < MinCustomEntropy)
                {
                    if (!throwOnError) return false;
                    throw new InvalidDataException($"Custom entropy of {entropy} doesn't fit the min. required entropy of {MinCustomEntropy}");
                }
            }
            return true;
        }

        /// <summary>
        /// Get the entropy
        /// </summary>
        /// <param name="str">String</param>
        /// <param name="algo">Algorithm</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>str</c> was empty)</returns>
        public static double GetEntropy(this string str, in Algorithms? algo = null)
        {
            if (str.Length < 1) return double.MinValue;
            using RentedArrayRefStruct<byte> buffer = new(len: Encoding.UTF8.GetMaxByteCount(str.Length), clean: false)
            {
                Clear = true
            };
            return CalculateEntropy(buffer.Span[..str.GetBytes(buffer.Span)], algo);
        }

        /// <summary>
        /// Get the entropy
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="algo">Algorithm</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>str</c> was empty)</returns>
        public static double GetEntropy(this byte[] data, in Algorithms? algo = null) => CalculateEntropy(data, algo);

        /// <summary>
        /// Get the entropy
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="algo">Algorithm</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>str</c> was empty)</returns>
        public static double GetEntropy(this Span<byte> data, in Algorithms? algo = null) => CalculateEntropy(data, algo);

        /// <summary>
        /// Get the entropy
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="algo">Algorithm</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>str</c> was empty)</returns>
        public static double GetEntropy(this ReadOnlySpan<byte> data, in Algorithms? algo = null) => CalculateEntropy(data, algo);

        /// <summary>
        /// Get the entropy
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="algo">Algorithm</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>str</c> was empty)</returns>
        public static double GetEntropy(this Memory<byte> data, in Algorithms? algo = null) => CalculateEntropy(data.Span, algo);

        /// <summary>
        /// Get the entropy
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="algo">Algorithm</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>str</c> was empty)</returns>
        public static double GetEntropy(this ReadOnlyMemory<byte> data, in Algorithms? algo = null) => CalculateEntropy(data.Span, algo);

        /// <summary>
        /// Delegate for an entropy algorithm
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="algo">Custom algorithm bits (excluding <see cref="Algorithms.Custom"/>)</param>
        /// <param name="throwOnInvalidAlgorithm">Throw an exception on an invalid value of <c>algo</c>?</param>
        /// <returns>Entropy (<see cref="double.MinValue"/>, if <c>str</c> was empty; <see cref="double.NaN"/>, if <c>algo</c> was invalid)</returns>
        public delegate double EntropyAlgorithm_Delegate(ReadOnlySpan<byte> data, int algo, bool throwOnInvalidAlgorithm = false);

        /// <summary>
        /// Algorithms
        /// </summary>
        [Flags]
        public enum Algorithms
        {
            /// <summary>
            /// None
            /// </summary>
            [DisplayText("None")]
            None = 0,
            /// <summary>
            /// Shannon bit
            /// </summary>
            [DisplayText("Shannon bit")]
            ShannonBit = 1,
            /// <summary>
            /// Shannon byte
            /// </summary>
            [DisplayText("Shannon byte")]
            ShannonByte = 2,
            /// <summary>
            /// Custom
            /// </summary>
            [DisplayText("Custom")]
            Custom = 3,
            /// <summary>
            /// All algorithms
            /// </summary>
            [DisplayText("All algorithms")]
            ALL = ShannonBit | ShannonByte | Custom
        }
    }
}
