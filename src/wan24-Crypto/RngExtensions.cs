using System.Runtime.InteropServices;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// <see cref="Rng"/> extensions
    /// </summary>
    public static class RngExtensions
    {
        /// <summary>
        /// Get a random 32 bit integer
        /// </summary>
        /// <param name="rng">Random number generator</param>
        /// <param name="fromInclusive">From inclusive</param>
        /// <param name="toExclusive">To exclusive</param>
        /// <returns>Random integer</returns>
        public static int GetInt32(this RandomNumberGenerator rng, int fromInclusive, int toExclusive)
        {
            /*
             * NOTE: This piece of code is almost a 1:1 copy of the RandomNumberGenerator code, which is licensed under the MIT license by the .NET Foundation. See 
             * Rng.LICENSE.md for details.
             */
            ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(fromInclusive, toExclusive);
            uint range = (uint)toExclusive - (uint)fromInclusive - 1;
            if (range == 0) return fromInclusive;
            uint mask = range;
            mask |= mask >> 1;
            mask |= mask >> 2;
            mask |= mask >> 4;
            mask |= mask >> 8;
            mask |= mask >> 16;
            Span<uint> resultSpan = stackalloc uint[1];
            try
            {
                uint result;
                do
                {
                    rng.GetBytes(MemoryMarshal.AsBytes(resultSpan));
                    result = mask & resultSpan[0];
                }
                while (result > range);
                return (int)result + fromInclusive;
            }
            finally
            {
                resultSpan.Clear();
            }
        }

        /// <summary>
        /// Get a random 32 bit integer
        /// </summary>
        /// <param name="rng">Random number generator</param>
        /// <param name="toExclusive">To exclusive</param>
        /// <returns>Random integer</returns>
        public static int GetInt32(this RandomNumberGenerator rng, int toExclusive) => GetInt32(rng, fromInclusive: 0, toExclusive);

        /// <summary>
        /// Get a random 32 bit integer
        /// </summary>
        /// <param name="rng">Random data generator</param>
        /// <param name="fromInclusive">From inclusive</param>
        /// <param name="toExclusive">To exclusive</param>
        /// <returns>Random integer</returns>
        public static int GetInt32(this IRng rng, int fromInclusive, int toExclusive)
        {
            /*
             * NOTE: This piece of code is almost a 1:1 copy of the RandomNumberGenerator code, which is licensed under the MIT license by the .NET Foundation. See 
             * Rng.LICENSE.md for details.
             */
            ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(fromInclusive, toExclusive);
            uint range = (uint)toExclusive - (uint)fromInclusive - 1;
            if (range == 0) return fromInclusive;
            uint mask = range;
            mask |= mask >> 1;
            mask |= mask >> 2;
            mask |= mask >> 4;
            mask |= mask >> 8;
            mask |= mask >> 16;
            Span<uint> resultSpan = stackalloc uint[1];
            try
            {
                uint result;
                do
                {
                    rng.FillBytes(MemoryMarshal.AsBytes(resultSpan));
                    result = mask & resultSpan[0];
                }
                while (result > range);
                return (int)result + fromInclusive;
            }
            finally
            {
                resultSpan.Clear();
            }
        }

        /// <summary>
        /// Get a random 32 bit integer
        /// </summary>
        /// <param name="rng">Random number generator</param>
        /// <param name="toExclusive">To exclusive</param>
        /// <returns>Random integer</returns>
        public static int GetInt32(this IRng rng, int toExclusive) => GetInt32(rng, fromInclusive: 0, toExclusive);

        /// <summary>
        /// Get a random 32 bit integer
        /// </summary>
        /// <param name="rng">Random number generator</param>
        /// <param name="fromInclusive">From inclusive</param>
        /// <param name="toExclusive">To exclusive</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Random integer</returns>
        public static async Task<int> GetInt32Async(this IRng rng, int fromInclusive, int toExclusive, CancellationToken cancellationToken = default)
        {
            /*
             * NOTE: This piece of code is almost a 1:1 copy of the RandomNumberGenerator code, which is licensed under the MIT license by the .NET Foundation. See 
             * Rng.LICENSE.md for details.
             */
            ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(fromInclusive, toExclusive);
            uint range = (uint)toExclusive - (uint)fromInclusive - 1;
            if (range == 0) return fromInclusive;
            uint mask = range;
            mask |= mask >> 1;
            mask |= mask >> 2;
            mask |= mask >> 4;
            mask |= mask >> 8;
            mask |= mask >> 16;
            uint result;
            using (RentedArrayStructSimple<byte> buffer = new(len: sizeof(uint), clean: false)
            {
                Clear = true
            })
                do
                {
                    await rng.FillBytesAsync(buffer.Memory, cancellationToken).DynamicContext();
                    result = mask & buffer.Span.ToUInt();
                }
                while (result > range);
            return (int)result + fromInclusive;
        }

        /// <summary>
        /// Get a random 32 bit integer
        /// </summary>
        /// <param name="rng">Random number generator</param>
        /// <param name="toExclusive">To exclusive</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Random integer</returns>
        public static Task<int> GetInt32Async(this IRng rng, int toExclusive, CancellationToken cancellationToken = default)
            => GetInt32Async(rng, fromInclusive: 0, toExclusive, cancellationToken);

        /// <summary>
        /// Get non-zero random bytes
        /// </summary>
        /// <param name="rng">Random number generator</param>
        /// <param name="data">Data</param>
        public static void GetNonZeroBytes(this IRng rng, Span<byte> data)
        {
            rng.FillBytes(data);
            if (data.IndexOf((byte)0) == -1) return;
            int i;
            List<int> zeroIndex = [],
                newZeroIndex = null!;
            unchecked
            {
                for (i = 0; i != data.Length; i++) if (data[i] == 0) zeroIndex.Add(i);
                using RentedMemoryRef<byte> buffer = new(zeroIndex.Count, clean: false)
                {
                    Clear = true
                };
                Span<byte> bufferSpan = buffer.Span;
                for (
                    rng.FillBytes(buffer.Span);
                    ;
                    zeroIndex.Clear(), zeroIndex.AddRange(newZeroIndex), newZeroIndex.Clear(), rng.FillBytes(bufferSpan[..zeroIndex.Count])
                    )
                {
                    for (i = 0; i != zeroIndex.Count; i++)
                        if (bufferSpan[i] == 0)
                        {
                            newZeroIndex ??= [];
                            newZeroIndex.Add(zeroIndex[i]);
                        }
                        else
                        {
                            data[i] = bufferSpan[i];
                        }
                    if (newZeroIndex is null || newZeroIndex.Count == 0) return;
                }
            }
        }

        /// <summary>
        /// Get non-zero random bytes
        /// </summary>
        /// <param name="rng">Random number generator</param>
        /// <param name="data">Data</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public static async Task GetNonZeroBytesAsync(this IRng rng, Memory<byte> data, CancellationToken cancellationToken = default)
        {
            await rng.FillBytesAsync(data, cancellationToken).DynamicContext();
            if (data.IndexOf((byte)0) == -1) return;
            int i;
            List<int> zeroIndex = [],
                newZeroIndex = null!;
            unchecked
            {
                for (i = 0; i != data.Length; i++) if (data.Span[i] == 0) zeroIndex.Add(i);
                using RentedArrayStructSimple<byte> buffer = new(zeroIndex.Count, clean: false)
                {
                    Clear = true
                };
                byte[] bufferArr = buffer.Array;
                await rng.FillBytesAsync(buffer.Memory, cancellationToken).DynamicContext();
                for (
                    ;
                    ;
                    zeroIndex.Clear(), zeroIndex.AddRange(newZeroIndex), newZeroIndex.Clear()
                    )
                {
                    for (i = 0; i != zeroIndex.Count; i++)
                        if (bufferArr[i] == 0)
                        {
                            newZeroIndex ??= [];
                            newZeroIndex.Add(zeroIndex[i]);
                        }
                        else
                        {
                            data.Span[i] = bufferArr[i];//FIXME Avoid span access here
                        }
                    if (newZeroIndex is null || newZeroIndex.Count == 0) return;
                    await rng.FillBytesAsync(buffer.Memory[..newZeroIndex.Count], cancellationToken).DynamicContext();
                }
            }
        }
    }
}
