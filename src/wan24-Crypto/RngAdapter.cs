﻿using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// <see cref="IRng"/> to <see cref="RandomNumberGenerator"/> adapter
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="rng">Random number generator</param>
    public sealed class RngAdapter(IRng rng) : Rng()
    {
        /// <summary>
        /// Random number generator
        /// </summary>
        public IRng RNG { get; } = rng;

        /// <inheritdoc/>
        public override void GetBytes(byte[] data) => RNG.FillBytes(data);

        /// <inheritdoc/>
        public override void GetBytes(Span<byte> data) => RNG.FillBytes(data);

        /// <inheritdoc/>
        public override void GetBytes(byte[] data, int offset, int count) => RNG.FillBytes(data.AsSpan(offset, count));

        /// <inheritdoc/>
        public override void GetNonZeroBytes(byte[] data) => GetNonZeroBytes(data.AsSpan());

        /// <inheritdoc/>
        public override void GetNonZeroBytes(Span<byte> data)
        {
            RNG.FillBytes(data);
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
                    RNG.FillBytes(buffer.Span);
                    ;
                    zeroIndex.Clear(), zeroIndex.AddRange(newZeroIndex), newZeroIndex.Clear(), RNG.FillBytes(bufferSpan[..zeroIndex.Count])
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

        /// <inheritdoc/>
        public override async Task GetNonZeroBytesAsync(Memory<byte> data)
        {
            await RNG.FillBytesAsync(data).DynamicContext();
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
                await RNG.FillBytesAsync(buffer.Memory).DynamicContext();
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
                    await RNG.FillBytesAsync(buffer.Memory[..newZeroIndex.Count]).DynamicContext();
                }
            }
        }
    }
}
