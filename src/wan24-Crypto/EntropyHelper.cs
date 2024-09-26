using System.Text;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Entropy helper
    /// </summary>
    public static partial class EntropyHelper
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
                Algorithms.Renyi => RenyiEntropy(data),
                Algorithms.Min => MinEntropy(data),
                Algorithms.Permutation => PermutationEntropy(data),
                Algorithms.Kolmogorov => KolmogorovComplexity(data),
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
            OrderedDictionary<byte, int>? byteCounters = null;
            // Shannon bit
            if (
                MinShannonBitEntropy != 0 &&
                (algos.Value & Algorithms.ShannonBit) == Algorithms.ShannonBit &&
                (entropy = ShannonBitEntropy(data, byteCounters = GetByteCounters(data))) < MinShannonBitEntropy
                )
            {
                if (!throwOnError) return false;
                throw new InvalidDataException($"Shannon bit entropy of {entropy} doesn't fit the min. required entropy of {MinShannonBitEntropy}");
            }
            // Shannon byte
            if (
                MinShannonByteEntropy != 0 &&
                (algos.Value & Algorithms.ShannonByte) == Algorithms.ShannonByte &&
                (entropy = ShannonByteEntropy(data, byteCounters ??= GetByteCounters(data))) < MinShannonByteEntropy
                )
            {
                if (!throwOnError) return false;
                throw new InvalidDataException($"Shannon byte entropy of {entropy} doesn't fit the min. required entropy of {MinShannonByteEntropy}");
            }
            // Rényi
            if (
                MinRenyiEntropy != 0 &&
                (algos.Value & Algorithms.Renyi) == Algorithms.Renyi &&
                (entropy = RenyiEntropy(data, byteCounters ??= GetByteCounters(data))) < MinRenyiEntropy
                )
            {
                if (!throwOnError) return false;
                throw new InvalidDataException($"Rényi entropy of {entropy} doesn't fit the min. required entropy of {MinRenyiEntropy}");
            }
            // Min
            if (
                MinMinEntropy != 0 &&
                (algos.Value & Algorithms.Min) == Algorithms.Min &&
                (entropy = MinEntropy(data, byteCounters ??= GetByteCounters(data))) < MinMinEntropy
                )
            {
                if (!throwOnError) return false;
                throw new InvalidDataException($"Min entropy of {entropy} doesn't fit the max. required entropy of {MinMinEntropy}");
            }
            // Permutation
            if (
                MinPermutationEntropy != 0 &&
                (algos.Value & Algorithms.Permutation) == Algorithms.Permutation &&
                (entropy = PermutationEntropy(data)) < MinPermutationEntropy
                )
            {
                if (!throwOnError) return false;
                throw new InvalidDataException($"Permutation entropy of {entropy} doesn't fit the min. required entropy of {MinPermutationEntropy}");
            }
            // Kolmogorov
            if (
                MinKolmogorovComplexity != 0 &&
                (algos.Value & Algorithms.Kolmogorov) == Algorithms.Kolmogorov &&
                (entropy = KolmogorovComplexity(data)) < MinKolmogorovComplexity
                )
            {
                if (!throwOnError) return false;
                throw new InvalidDataException($"Kolmogorov complexity of {entropy} doesn't fit the min. required complexity of {MinKolmogorovComplexity}");
            }
            // Custom
            if (CustomAlgorithm is not null && MinCustomEntropy != 0 && (algos.Value & Algorithms.Custom) == Algorithms.Custom)
            {
                int customAlgo = (int)(algos.Value & ~Algorithms.ALL);
                entropy = CustomAlgorithm(data, customAlgo, byteCounters);
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
            using RentedMemoryRef<byte> buffer = new(len: Encoding.UTF8.GetMaxByteCount(str.Length), clean: false)
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
        /// Algorithms
        /// </summary>
        [Flags]
        public enum Algorithms : int
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
            ShannonBit = 1 << 1,
            /// <summary>
            /// Shannon byte
            /// </summary>
            [DisplayText("Shannon byte")]
            ShannonByte = 1 << 2,
            /// <summary>
            /// Custom
            /// </summary>
            [DisplayText("Custom")]
            Custom = 1 << 3,
            /// <summary>
            /// Rényi
            /// </summary>
            [DisplayText("Rényi")]
            Renyi = 1 << 4,
            /// <summary>
            /// Min
            /// </summary>
            [DisplayText("Min")]
            Min = 1 << 5,
            /// <summary>
            /// Permutation
            /// </summary>
            [DisplayText("Permutation")]
            Permutation = 1 << 6,
            /// <summary>
            /// Kolmogorov
            /// </summary>
            [DisplayText("Kolmogorov")]
            Kolmogorov = 1 << 7,
            /// <summary>
            /// All algorithms
            /// </summary>
            [DisplayText("All algorithms")]
            ALL = ShannonBit | ShannonByte | Custom | Renyi | Min | Permutation | Kolmogorov
        }
    }
}
