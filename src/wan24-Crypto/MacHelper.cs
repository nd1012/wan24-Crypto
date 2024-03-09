using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// MAC helper
    /// </summary>
    public static class MacHelper
    {
        /// <summary>
        /// Default MAC algorithm
        /// </summary>
        private static MacAlgorithmBase _DefaultAlgorithm;

        /// <summary>
        /// Registered MAC algorithms
        /// </summary>
        public static readonly ConcurrentDictionary<string, MacAlgorithmBase> Algorithms;

        /// <summary>
        /// Constructor
        /// </summary>
        static MacHelper()
        {
            Algorithms = new(
            [
                new(MacHmacSha1Algorithm.ALGORITHM_NAME, MacHmacSha1Algorithm.Instance),
                new(MacHmacSha256Algorithm.ALGORITHM_NAME, MacHmacSha256Algorithm.Instance),
                new(MacHmacSha384Algorithm.ALGORITHM_NAME, MacHmacSha384Algorithm.Instance),
                new(MacHmacSha512Algorithm.ALGORITHM_NAME, MacHmacSha512Algorithm.Instance),
                new(MacHmacSha3_256Algorithm.ALGORITHM_NAME, MacHmacSha3_256Algorithm.Instance),
                new(MacHmacSha3_384Algorithm.ALGORITHM_NAME, MacHmacSha3_384Algorithm.Instance),
                new(MacHmacSha3_512Algorithm.ALGORITHM_NAME, MacHmacSha3_512Algorithm.Instance)
            ]);
            _DefaultAlgorithm = MacHmacSha3_512Algorithm.Instance.IsSupported ? MacHmacSha3_512Algorithm.Instance : MacHmacSha512Algorithm.Instance;
        }

        /// <summary>
        /// An object for thread synchronization
        /// </summary>
        public static object SyncObject { get; } = new();

        /// <summary>
        /// Default MAC algorithm
        /// </summary>
        public static MacAlgorithmBase DefaultAlgorithm
        {
            get => _DefaultAlgorithm;
            set
            {
                value.EnsureAllowed();
                if (!value.IsSupported) throw new InvalidOperationException();
                lock (SyncObject) _DefaultAlgorithm = value;
            }
        }

        /// <summary>
        /// TPM algorithms
        /// </summary>
        public static IEnumerable<MacAlgorithmBase> TpmAlgorithms
            => from algo in Algorithms.Values
               where algo.UsesTpm
               select algo;

        /// <summary>
        /// Pre-quantum algorithms
        /// </summary>
        public static IEnumerable<MacAlgorithmBase> PreQuantum
            => from algo in Algorithms.Values
               where !algo.IsPostQuantum
               select algo;

        /// <summary>
        /// Post-quantum algorithms
        /// </summary>
        public static IEnumerable<MacAlgorithmBase> PostQuantum
            => from algo in Algorithms.Values
               where algo.IsPostQuantum
               select algo;

        /// <summary>
        /// Get a MAC stream
        /// </summary>
        /// <param name="pwd">Password</param>
        /// <param name="target">Target stream</param>
        /// <param name="writable">Writable?</param>
        /// <param name="options">Options</param>
        /// <returns>MAC streams</returns>
        public static MacStreams GetMacStream(byte[] pwd, Stream? target = null, bool writable = true, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.MacAlgorithm!).GetMacStream(pwd, target, writable, options);
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static byte[] Mac(this byte[] data, byte[] pwd, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.MacAlgorithm!).Mac(data, pwd, options);
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static byte[] Mac(this ReadOnlySpan<byte> data, byte[] pwd, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.MacAlgorithm!).Mac(data, pwd, options);
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="outputBuffer">Output buffer</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static Span<byte> Mac(this ReadOnlySpan<byte> data, byte[] pwd, Span<byte> outputBuffer, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.MacAlgorithm!).Mac(data, pwd, outputBuffer, options);
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>MAC</returns>
        public static byte[] Mac(this Stream data, byte[] pwd, CryptoOptions? options = null)
        {
            options = GetDefaultOptions(options);
            return GetAlgorithm(options.MacAlgorithm!).Mac(data, pwd, options);
        }

        /// <summary>
        /// Create a MAC
        /// </summary>
        /// <param name="data">Data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>MAC</returns>
        public static async Task<byte[]> MacAsync(this Stream data, byte[] pwd, CryptoOptions? options = null, CancellationToken cancellationToken = default)
        {
            options = GetDefaultOptions(options);
            return await GetAlgorithm(options.MacAlgorithm!).MacAsync(data, pwd, options, cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Get the default options used by the MAC helper
        /// </summary>
        /// <param name="options">Options</param>
        /// <returns>Options</returns>
        public static CryptoOptions GetDefaultOptions(CryptoOptions? options = null)
        {
            try
            {
                if (options is null)
                {
                    options = DefaultAlgorithm.DefaultOptions;
                }
                else
                {
                    options.MacAlgorithm ??= DefaultAlgorithm.Name;
                }
                return options;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Get an algorithm
        /// </summary>
        /// <param name="name">Algorithm name</param>
        /// <returns>Algorithm</returns>
        public static MacAlgorithmBase GetAlgorithm(string name)
            => Algorithms.TryGetValue(name, out MacAlgorithmBase? algo)
                ? algo
                : throw new ArgumentException("Invalid algorithm", nameof(name));

        /// <summary>
        /// Get an algorithm
        /// </summary>
        /// <param name="value">Algorithm value</param>
        /// <returns>Algorithm</returns>
        public static MacAlgorithmBase GetAlgorithm(int value)
            => Algorithms.Values.FirstOrDefault(a => a.Value == value) ?? throw new ArgumentException("Invalid algorithm", nameof(value));

        /// <summary>
        /// Get the matching MAC algorithm for a digest length
        /// </summary>
        /// <param name="len">Digest length in byte</param>
        /// <param name="allowedAlgos">Allowed MAC algorithm names</param>
        /// <returns>MAC algorithm name</returns>
        public static string GetAlgorithmName(int len, params string[] allowedAlgos)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(len, 1);
            if (allowedAlgos.Length == 0) allowedAlgos = [.. Algorithms.Keys];
            return (from algo in Algorithms.Values
                    where algo.MacLength == len &&
                        allowedAlgos.Contains(algo.Name)
                    select algo.Name)
                    .FirstOrDefault() ??
                    throw CryptographicException.From($"Digest length {len} byte doesn't match any of the allowed MAC algorithms", new InvalidDataException());
        }

        /// <summary>
        /// Get the matching MAC algorithm for a digest length
        /// </summary>
        /// <param name="len">Digest length in byte</param>
        /// <param name="algo">MAC algorithm name</param>
        /// <param name="allowedAlgos">Allowed MAC algorithm names</param>
        /// <returns>If succeed</returns>
        public static bool TryGetAlgorithmName(int len, [NotNullWhen(returnValue: true)] out string? algo, params string[] allowedAlgos)
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(len, 1);
            if (allowedAlgos.Length == 0) allowedAlgos = [.. Algorithms.Keys];
            algo = (from a in Algorithms.Values
                    where a.MacLength == len &&
                        allowedAlgos.Contains(a.Name)
                    select a.Name)
                    .FirstOrDefault();
            return algo is not null;
        }
    }
}
