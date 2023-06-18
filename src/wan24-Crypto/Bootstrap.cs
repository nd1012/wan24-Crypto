using wan24.Core;
using wan24.StreamSerializerExtensions;

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
            // TimeoutToken serializer
            StreamSerializer.SyncSerializer[typeof(TimeoutToken)] = (s, v) => StreamSerializerExtensions.Write(s, (TimeoutToken)SerializerHelper.EnsureNotNull(v));
            StreamSerializer.AsyncSerializer[typeof(TimeoutToken)] =
                async (s, v, ct) => await StreamSerializerExtensions.WriteAsync(s, (TimeoutToken)SerializerHelper.EnsureNotNull(v), cancellationToken: ct).DynamicContext();
            StreamSerializer.SyncDeserializer[typeof(TimeoutToken)] = (s, t, v, o) => s.ReadTimeoutToken();
            StreamSerializer.AsyncDeserializer[typeof(TimeoutToken)] = async (s, t, v, o, ct) => await s.ReadTimeoutTokenAsync(cancellationToken: ct).DynamicContext();
        }
    }
}
