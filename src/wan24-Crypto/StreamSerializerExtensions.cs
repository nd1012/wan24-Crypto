using System.Buffers;
using System.Runtime;
using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    /// <summary>
    /// Stream serializer extensions
    /// </summary>
    public static class StreamSerializerExtensions
    {
        /// <summary>
        /// Write
        /// </summary>
        /// <typeparam name="T">Stream type</typeparam>
        /// <param name="stream">Stream</param>
        /// <param name="tt">Timeout token</param>
        /// <param name="buffer">Buffer</param>
        /// <param name="pool">Buffer pool</param>
        /// <returns>Stream</returns>
        [TargetedPatchingOptOut("Tiny method")]
        public static T Write<T>(this T stream, in TimeoutToken tt, byte[]? buffer = null, ArrayPool<byte>? pool = null) where T : Stream
        {
            tt.Serialize(stream, buffer, pool ?? StreamSerializer.BufferPool);
            return stream;
        }

        /// <summary>
        /// Write
        /// </summary>
        /// <typeparam name="T">Stream type</typeparam>
        /// <param name="stream">Stream</param>
        /// <param name="tt">Timeout token</param>
        /// <param name="buffer">Buffer</param>
        /// <param name="pool">Buffer pool</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Stream</returns>
        [TargetedPatchingOptOut("Tiny method")]
        public static async Task<T> WriteAsync<T>(this T stream, TimeoutToken tt, byte[]? buffer = null, ArrayPool<byte>? pool = null, CancellationToken cancellationToken = default)
            where T : Stream
        {
            await tt.SerializeAsync(stream, buffer, pool ?? StreamSerializer.BufferPool, cancellationToken).DynamicContext();
            return stream;
        }

        /// <summary>
        /// Read a timeout token
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="pool">Buffer pool</param>
        /// <returns>Timeout token</returns>
        [TargetedPatchingOptOut("Tiny method")]
        public static TimeoutToken ReadTimeoutToken(this Stream stream, ArrayPool<byte>? pool = null)
        {
            using RentedArrayRefStruct<byte> buffer = new(TimeoutToken.STRUCT_LENGTH, pool, clean: false);
            stream.ReadExactly(buffer.Span);
            return (TimeoutToken)buffer.Span!;
        }

        /// <summary>
        /// Read a timeout token
        /// </summary>
        /// <param name="stream">Stream</param>
        /// <param name="pool">Array pool</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Timeout token</returns>
        [TargetedPatchingOptOut("Tiny method")]
        public static async Task<TimeoutToken> ReadTimeoutTokenAsync(this Stream stream, ArrayPool<byte>? pool = null, CancellationToken cancellationToken = default)
        {
            using RentedArrayStruct<byte> buffer = new(TimeoutToken.STRUCT_LENGTH, pool, clean: false);
            await stream.ReadExactlyAsync(buffer.Memory, cancellationToken).DynamicContext();
            return (TimeoutToken)buffer.Span;
        }
    }
}
