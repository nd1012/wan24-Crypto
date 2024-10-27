using System.Runtime.InteropServices;
using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Random number generator
    /// </summary>
    public class Rng : RandomNumberGenerator, IRng
    {
        /// <summary>
        /// Singleton instance
        /// </summary>
        private static Rng? _Instance = null;

        /// <summary>
        /// Constructor
        /// </summary>
        public Rng() : base() { }

        /// <summary>
        /// Singleton instance
        /// </summary>
        public static Rng Instance
        {
            get => _Instance ??= new();
            set => _Instance = value;
        }

        /// <inheritdoc/>
        public override void GetBytes(byte[] data) => RND.FillBytes(data);

        /// <inheritdoc/>
        public override void GetBytes(Span<byte> data) => RND.FillBytes(data);

        /// <inheritdoc/>
        public override void GetBytes(byte[] data, int offset, int count) => RND.FillBytes(data.AsSpan(offset, count));

        /// <inheritdoc/>
        public override void GetNonZeroBytes(byte[] data) => GetNonZeroBytes(data.AsSpan());

        /// <inheritdoc/>
        public override void GetNonZeroBytes(Span<byte> data)
        {
            RND.FillBytes(data);
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
                    RND.FillBytes(buffer.Span);
                    ;
                    zeroIndex.Clear(), zeroIndex.AddRange(newZeroIndex), newZeroIndex.Clear(), RND.FillBytes(bufferSpan[..zeroIndex.Count])
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
        /// <param name="data">Data</param>
        public virtual async Task GetNonZeroBytesAsync(Memory<byte> data)
        {
            await RND.FillBytesAsync(data).DynamicContext();
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
                await RND.FillBytesAsync(buffer.Memory).DynamicContext();
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
                    await RND.FillBytesAsync(buffer.Memory[..newZeroIndex.Count]).DynamicContext();
                }
            }
        }

        /// <inheritdoc/>
        public virtual byte[] GetBytes(in int count)
        {
            if (count < 1) return [];
            byte[] res = new byte[count];
            GetBytes(res);
            return res;
        }

        /// <inheritdoc/>
        public virtual Task<byte[]> GetBytesAsync(int count, CancellationToken cancellationToken = default)
        {
            if (count < 1) return Task.FromResult(Array.Empty<byte>());
            byte[] res = new byte[count];
            GetBytes(res);
            return Task.FromResult(res);
        }

        /// <inheritdoc/>
        public virtual Span<byte> FillBytes(in Span<byte> buffer)
        {
            GetBytes(buffer);
            return buffer;
        }

        /// <inheritdoc/>
        public virtual Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            GetBytes(buffer.Span);
            return Task.FromResult(buffer);
        }

        /// <inheritdoc/>
        new public static void Fill(Span<byte> data) => RND.FillBytes(data);

        /// <inheritdoc/>
        new public static int GetInt32(int fromInclusive, int toExclusive)
        {
            /*
             * NOTE: This piece of code is almost a 1:1 copy of the RandomNumberGenerator code, which is licensed under the MIT license by the .NET Foundation. See 
             * licenses for details.
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
                    RND.FillBytes(MemoryMarshal.AsBytes(resultSpan));
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

        /// <inheritdoc/>
        new public static int GetInt32(int toExclusive) => GetInt32(fromInclusive: 0, toExclusive);

        /// <summary>
        /// Get a random 32 bit integer
        /// </summary>
        /// <param name="fromInclusive">From inclusive</param>
        /// <param name="toExclusive">To exclusive</param>
        /// <returns>Random integer</returns>
        public static async Task<int> GetInt32Async(int fromInclusive, int toExclusive)
        {
            /*
             * NOTE: This piece of code is almost a 1:1 copy of the RandomNumberGenerator code, which is licensed under the MIT license by the .NET Foundation. See 
             * licenses for details.
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
                    await RND.FillBytesAsync(buffer.Memory).DynamicContext();
                    result = mask & buffer.Span.ToUInt();
                }
                while (result > range);
            return (int)result + fromInclusive;
        }

        /// <summary>
        /// Get a random 32 bit integer
        /// </summary>
        /// <param name="toExclusive">To exclusive</param>
        /// <returns>Random integer</returns>
        public static Task<int> GetInt32Async(int toExclusive) => GetInt32Async(fromInclusive: 0, toExclusive);

        /// <inheritdoc/>
        new public static byte[] GetBytes(int count)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(count);
            if (count == 0) return [];
            byte[] res = new byte[count];
            RND.FillBytes(res);
            return res;
        }
    }
}
