using Microsoft.Extensions.DependencyInjection;
using wan24.Core;
using wan24.Crypto.Authentication;

namespace wan24.Crypto
{
    /// <summary>
    /// Crypto extensions
    /// </summary>
    public static class CryptoExtensions
    {
        /// <summary>
        /// Add random padding bytes
        /// </summary>
        /// <typeparam name="T">Stream type</typeparam>
        /// <param name="stream">Stream</param>
        /// <param name="blockSize">Block size in bytes</param>
        /// <param name="written">Number of written bytes</param>
        /// <returns>Stream</returns>
        public static T AddPadding<T>(this T stream, int blockSize, long? written = null) where T : Stream
        {
            try
            {
                ArgumentOutOfRangeException.ThrowIfLessThan(blockSize, 1);
                if (written is not null && written < 0) throw new ArgumentOutOfRangeException(nameof(written));
                int len = blockSize - (int)((written ?? stream.Length) % blockSize);
                if (len > Settings.StackAllocBorder)
                {
                    using RentedArrayRefStruct<byte> buffer = new(len, clean: false)
                    {
                        Clear = true
                    };
                    RND.FillBytes(buffer.Span);
                    stream.Write(buffer.Span);
                }
                else
                {
                    Span<byte> buffer = stackalloc byte[len];
                    RND.FillBytes(buffer);
                    stream.Write(buffer);
                }
                return stream;
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch(Exception ex)
            {
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Add random padding bytes
        /// </summary>
        /// <typeparam name="T">Stream type</typeparam>
        /// <param name="stream">Stream</param>
        /// <param name="blockSize">Block size in bytes</param>
        /// <param name="written">Number of written bytes</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public static async Task AddPaddingAsync<T>(this T stream, int blockSize, long? written = null, CancellationToken cancellationToken = default) where T : Stream
        {
            try
            {
                ArgumentOutOfRangeException.ThrowIfLessThan(blockSize, 1);
                if (written is not null && written < 0) throw new ArgumentOutOfRangeException(nameof(written));
                int len = blockSize - (int)((written ?? stream.Length) % blockSize);
                using RentedArrayStruct<byte> buffer = new(len, clean: false)
                {
                    Clear = true
                };
                RND.FillBytes(buffer.Span);
                await stream.WriteAsync(buffer.Memory, cancellationToken).DynamicContext();
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw await CryptographicException.FromAsync(ex);
            }
        }

        /// <summary>
        /// Validate a MAC
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="mac">MAC</param>
        /// <param name="pwd">Password</param>
        /// <param name="resetPosition">Reset the original stream position?</param>
        /// <param name="options">Options</param>
        /// <returns>If the MAC is valid</returns>
        public static bool ValidateMac(this Stream stream, byte[] mac, byte[] pwd, bool resetPosition = true, CryptoOptions? options = null)
        {
            try
            {
                if (!stream.CanRead) throw new NotSupportedException();
                if (resetPosition && !stream.CanSeek) throw new InvalidOperationException();
                long pos = resetPosition ? stream.Position : 0;
                try
                {
                    return mac.AsSpan().SlowCompare(stream.Mac(pwd, options));
                }
                finally
                {
                    if (resetPosition) stream.Position = pos;
                }
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
        /// Validate a MAC
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="mac">MAC</param>
        /// <param name="pwd">Password</param>
        /// <param name="resetPosition">Reset the original stream position?</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>If the MAC is valid</returns>
        public static async Task<bool> ValidateMacAsync(
            this Stream stream,
            byte[] mac,
            byte[] pwd,
            bool resetPosition = true,
            CryptoOptions? options = null,
            CancellationToken cancellationToken = default
            )
        {
            try
            {
                if (!stream.CanRead) throw new NotSupportedException();
                if (resetPosition && !stream.CanSeek) throw new InvalidOperationException();
                long pos = resetPosition ? stream.Position : 0;
                try
                {
                    byte[] mac2 = await stream.MacAsync(pwd, options, cancellationToken).DynamicContext();
                    return mac.AsSpan().SlowCompare(mac2);
                }
                finally
                {
                    if (resetPosition) stream.Position = pos;
                }
            }
            catch (CryptographicException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw await CryptographicException.FromAsync(ex);
            }
        }

        /// <summary>
        /// Extend a key by additional keys
        /// </summary>
        /// <param name="key">Key (will be cleared!)</param>
        /// <param name="additionalKeys">Additional keys (will be cleared!)</param>
        /// <returns>Extended key</returns>
        public static byte[] ExtendKey(this byte[] key, params byte[]?[] additionalKeys)
        {
            int addLen = 0,
                offset = 0,
                len = additionalKeys.Length;
            for (int i = 0; i != len; addLen += additionalKeys[i]?.Length ?? 0, i++) ;
            byte[] res = new byte[addLen + key.Length];
            byte[]? addKey;
            Span<byte> resSpan = res.AsSpan();
            for (int i = len - 1; i >= 0; i--)
            {
                addKey = additionalKeys[i];
                if (addKey is null) continue;
                addKey.CopyTo(resSpan[offset..]);
                offset += addKey.Length;
                addKey.Clear();
            }
            key.CopyTo(resSpan[offset..]);
            key.Clear();
            return res;
        }

        /// <summary>
        /// Create key pools for all allowed key sizes (existing key pools won't be overwritten!)
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <param name="capacity">Capacity per key pool</param>
        /// <param name="start">Start the key pool?</param>
        public static void CreateKeyPools(this IAsymmetricAlgorithm algo, int capacity, bool start = true)
        {
            algo.EnsureAllowed();
            IAsymmetricKeyPool pool;
            CryptoOptions options;
            Type poolType = typeof(AsymmetricKeyPool<>);
            algo.KeyPool ??= new(algo.AllowedKeySizes.Count);
            foreach (int size in algo.AllowedKeySizes)
            {
                if (algo.KeyPool.ContainsKey(size) || (algo.IsEllipticCurveAlgorithm && !EllipticCurves.IsCurveAllowed(size))) continue;
                options = algo.DefaultOptions;
                options.AsymmetricKeyBits = size;
                pool = poolType.MakeGenericType(algo.PrivateKeyType).ConstructAuto(usePrivate: false, param: [capacity, options]) as IAsymmetricKeyPool
                    ?? throw new InvalidProgramException($"Failed to instance asymmetric key pool for {algo.PrivateKeyType} (key size {size})");
                algo.KeyPool[size] = pool;
                if (start) pool.StartAsync().Wait();
            }
        }

        /// <summary>
        /// Create key pools for all allowed key sizes (existing key pools won't be overwritten!)
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <param name="capacity">Capacity per key pool</param>
        /// <param name="start">Start the key pool?</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public static async Task CreateKeyPoolsAsync(this IAsymmetricAlgorithm algo, int capacity, bool start = true, CancellationToken cancellationToken = default)
        {
            algo.EnsureAllowed();
            IAsymmetricKeyPool pool;
            CryptoOptions options;
            Type poolType = typeof(AsymmetricKeyPool<>);
            algo.KeyPool ??= new(algo.AllowedKeySizes.Count);
            foreach (int size in algo.AllowedKeySizes)
            {
                if (algo.KeyPool.ContainsKey(size) || (algo.IsEllipticCurveAlgorithm && !EllipticCurves.IsCurveAllowed(size))) continue;
                options = algo.DefaultOptions;
                options.AsymmetricKeyBits = size;
                pool = poolType.MakeGenericType(algo.PrivateKeyType).ConstructAuto(usePrivate: false, param: [capacity, options]) as IAsymmetricKeyPool
                    ?? throw new InvalidProgramException($"Failed to instance asymmetric key pool for {algo.PrivateKeyType} (key size {size})");
                algo.KeyPool[size] = pool;
                if (start) await pool.StartAsync(cancellationToken).DynamicContext();
            }
        }

        /// <summary>
        /// Get a pooled key
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <param name="options">Options</param>
        /// <returns>Pooled key (don't forget to dispose!)</returns>
        public static IAsymmetricPrivateKey GetPooledKey(this IAsymmetricAlgorithm algo, in CryptoOptions? options = null)
        {
            int bits = options?.AsymmetricKeyBits ?? algo.DefaultKeySize;
            if (!(algo.KeyPool?.TryGetValue(bits, out IAsymmetricKeyPool? pool) ?? false))
                throw CryptographicException.From(new InvalidOperationException($"Key pool for {algo.DisplayName} not found (key size {bits} bits)"));
            return pool.GetKey();
        }

        /// <summary>
        /// Get a pooled key
        /// </summary>
        /// <param name="algo">Algorithm</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Pooled key (don't forget to dispose!)</returns>
        public static async Task<IAsymmetricPrivateKey> GetPooledKeyAsync(this IAsymmetricAlgorithm algo, CryptoOptions? options = null, CancellationToken cancellationToken = default)
        {
            int bits = options?.AsymmetricKeyBits ?? algo.DefaultKeySize;
            if (!(algo.KeyPool?.TryGetValue(bits, out IAsymmetricKeyPool? pool) ?? false))
                throw CryptographicException.From(new InvalidOperationException($"Key pool for {algo.DisplayName} not found (key size {bits} bits)"));
            return await pool.GetKeyAsync(cancellationToken).DynamicContext();
        }

        /// <summary>
        /// Add all <c>wan24-Crypto</c> registered algorithms as DI service objects
        /// </summary>
        /// <param name="services">Services</param>
        /// <returns>Services</returns>
        public static IServiceCollection AddWan24Crypto(this IServiceCollection services)
        {
            foreach (ICryptoAlgorithm algo in CryptoEnvironment.AllAlgorithms.Where(a => a.IsSupported && a.EnsureAllowed(throwIfDenied: false)))
                services.AddSingleton(algo.GetType(), algo);
            services.AddSingleton(serviceProvider => CryptoEnvironment.PKI ?? throw new InvalidOperationException("No PKI defined"))
                .AddSingleton(serviceProvider => CryptoEnvironment.PrivateKeysStore ?? throw new InvalidOperationException("No private keys store defined"))
                .AddSingleton(serviceProvider => CryptoEnvironment.RandomGenerator ?? throw new InvalidOperationException("No random data generator defined"))
                .AddSingleton(serviceProvider => CryptoEnvironment.PakeAuthClient ?? throw new InvalidOperationException("No fast PAKE authentication client defined"))
                .AddSingleton(serviceProvider => CryptoEnvironment.PakeAuthServer ?? throw new InvalidOperationException("No fast PAKE authentication server defined"))
                .AddSingleton(serviceProvider => CryptoEnvironment.AsymmetricKeyPool ?? throw new InvalidOperationException("No asymmetric key pool defined"))
                .AddSingleton(serviceProvider => CryptoEnvironment.PakeAuthRecordPool ?? throw new InvalidOperationException("No PAKE authentication record pool defined"))
                .AddSingleton(serviceProvider => RND.SeedConsumer ?? throw new InvalidOperationException("No seed consumer defined"))
                .AddSingleton(serviceProvider => RND.Generator ?? throw new InvalidOperationException("No RNG defined"))
                .AddSingleton(serviceProvider => serviceProvider.GetRequiredService<IAsymmetricKeyPool>().GetKey())
                .AddSingleton(serviceProvider => serviceProvider.GetRequiredService<IPakeAuthRecordPool>().GetOne())
                .AddTransient<CryptoOptions>()
                .AddTransient(serviceProvider => EncryptionHelper.DefaultAlgorithm)
                .AddTransient(serviceProvider => HashHelper.DefaultAlgorithm)
                .AddTransient(serviceProvider => MacHelper.DefaultAlgorithm)
                .AddTransient(serviceProvider => KdfHelper.DefaultAlgorithm);
            return services;
        }
    }
}
