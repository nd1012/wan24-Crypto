using System.IO.Compression;
using wan24.Core;

namespace wan24.Crypto
{
    // Kolmogorov
    public static partial class EntropyHelper
    {
        /// <summary>
        /// Min. required Kolmogorov complexity (zero to disable checks; depends on the data length! <c>2</c> for 8 byte)
        /// </summary>
        [CliConfig]
        public static double MinKolmogorovComplexity { get; set; } = 2d;

        /// <summary>
        /// Kolmogorov complexity algorithm (using GZip)
        /// </summary>
        /// <param name="data">Data</param>
        /// <returns>Complexity (<see cref="double.MinValue"/>, if <c>data</c> was empty)</returns>
        public static double KolmogorovComplexity(in ReadOnlySpan<byte> data)
        {
            using MemoryPoolStream ms = new()
            {
                CleanReturned = true
            };
            using (GZipStream zip = new(ms, CompressionLevel.Optimal)) zip.Write(data);
            int len = data.Length;
            return ms.Length - len;
        }
    }
}
