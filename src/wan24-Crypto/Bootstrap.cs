using Microsoft.Extensions.DependencyInjection;
using wan24.Core;
using wan24.Crypto.Authentication;
using wan24.StreamSerializerExtensions;

//TODO .NET 8: SHA3

[assembly: Bootstrapper(typeof(wan24.Crypto.Bootstrap), nameof(wan24.Crypto.Bootstrap.Boot))]

namespace wan24.Crypto
{
    /// <summary>
    /// Bootstrapper
    /// </summary>
    public static class Bootstrap
    {
        /// <summary>
        /// Boot
        /// </summary>
        public static void Boot()
        {
            // wan24-Core
            BytesExtensions.ClearHandler = ClearBytes;
            // TimeoutToken serializer
            StreamSerializer.SyncSerializer[typeof(TimeoutToken)] = (s, v) => StreamSerializerExtensions.Write(s, (TimeoutToken)SerializerHelper.EnsureNotNull(v));
            StreamSerializer.AsyncSerializer[typeof(TimeoutToken)] =
                async (s, v, ct) => await StreamSerializerExtensions.WriteAsync(s, (TimeoutToken)SerializerHelper.EnsureNotNull(v), cancellationToken: ct).DynamicContext();
            StreamSerializer.SyncDeserializer[typeof(TimeoutToken)] = (s, t, v, o) => s.ReadTimeoutToken();
            StreamSerializer.AsyncDeserializer[typeof(TimeoutToken)] = async (s, t, v, o, ct) => await s.ReadTimeoutTokenAsync(cancellationToken: ct).DynamicContext();
        }

        /// <summary>
        /// Add all <c>wan24-Crypto</c> registered algorithms as DI service objects
        /// </summary>
        /// <param name="services">Services</param>
        /// <returns>Services</returns>
        public static IServiceCollection AddWan24Crypto(this IServiceCollection services)
        {
            foreach (IAsymmetricAlgorithm algo in AsymmetricHelper.Algorithms.Values)
                services.AddSingleton(algo.GetType(), algo);
            foreach (EncryptionAlgorithmBase algo in EncryptionHelper.Algorithms.Values)
                services.AddSingleton(algo.GetType(), algo);
            foreach (HashAlgorithmBase algo in HashHelper.Algorithms.Values)
                services.AddSingleton(algo.GetType(), algo);
            foreach (MacAlgorithmBase algo in MacHelper.Algorithms.Values)
                services.AddSingleton(algo.GetType(), algo);
            foreach (KdfAlgorithmBase algo in KdfHelper.Algorithms.Values)
                services.AddSingleton(algo.GetType(), algo);
            services.AddSingleton(EncryptionHelper.DefaultAlgorithm);
            services.AddSingleton(HashHelper.DefaultAlgorithm);
            services.AddSingleton(MacHelper.DefaultAlgorithm);
            services.AddSingleton(KdfHelper.DefaultAlgorithm);
            services.AddSingleton(serviceProvider => CryptoEnvironment.PKI ?? throw new InvalidOperationException("No PKI defined"));
            services.AddSingleton(serviceProvider => CryptoEnvironment.PrivateKeysStore ?? throw new InvalidOperationException("No private keys store defined"));
            services.AddSingleton(serviceProvider => CryptoEnvironment.RandomGenerator ?? throw new InvalidOperationException("No random data generator defined"));
            services.AddSingleton(serviceProvider => CryptoEnvironment.PakeAuthClient ?? throw new InvalidOperationException("No fast PAKE authentication client defined"));
            services.AddSingleton(serviceProvider => CryptoEnvironment.PakeAuthServer ?? throw new InvalidOperationException("No fast PAKE authentication server defined"));
            services.AddSingleton(serviceProvider => CryptoEnvironment.AsymmetricKeyPool ?? throw new InvalidOperationException("No asymmetric key pool defined"));
            services.AddSingleton(serviceProvider => CryptoEnvironment.PakeAuthRecordPool ?? throw new InvalidOperationException("No PAKE authentication record pool defined"));
            services.AddSingleton(serviceProvider => RND.SeedConsumer ?? throw new InvalidOperationException("No seed consumer defined"));
            services.AddSingleton(serviceProvider => RND.Generator ?? throw new InvalidOperationException("No RNG defined"));
            services.AddTransient<CryptoOptions>();
            services.AddTransient(serviceProvider => serviceProvider.GetRequiredService<IAsymmetricKeyPool>().GetKey());
            services.AddTransient(serviceProvider => serviceProvider.GetRequiredService<IPakeAuthRecordPool>().GetOne());
            return services;
        }

        /// <summary>
        /// Clear a byte array (will with random data and then zero)
        /// </summary>
        /// <param name="bytes">Byte array</param>
        private static void ClearBytes(Span<byte> bytes)
        {
            RND.FillBytes(bytes);
            bytes.Clear();
        }
    }
}
