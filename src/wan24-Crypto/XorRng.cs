﻿using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// RNG which combines two or more RNGs with XOR
    /// </summary>
    public sealed class XorRng : RngBase
    {
        /// <summary>
        /// Number of RNGs to combine
        /// </summary>
        private readonly int Count;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rngs">RNGs to use</param>
        public XorRng(params IRng[] rngs) : base()
        {
            if (rngs.Length < 2) throw new ArgumentOutOfRangeException(nameof(rngs), "Need at last 2 RNGs");
            RNG = rngs;
            Count = rngs.Length;
        }

        /// <summary>
        /// RNGs to use
        /// </summary>
        public IRng[] RNG { get; }

        /// <inheritdoc/>
        public override Span<byte> FillBytes(in Span<byte> buffer)
        {
            if (buffer.Length == 0) return buffer;
            using RentedMemoryRef<byte> res = new(buffer.Length, clean: false)
            {
                Clear = true
            };
            for (int i = 0; i != Count; RNG[i].FillBytes(res.Span), buffer.Xor(res.Span), i++) ;
            return buffer;
        }

        /// <inheritdoc/>
        public override async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length == 0) return buffer;
            using RentedMemory<byte> res = new(buffer.Length, clean: false)
            {
                Clear = true
            };
            for (int i = 0; i != Count; await RNG[i].FillBytesAsync(res.Memory, cancellationToken).DynamicContext(), buffer.Span.Xor(res.Memory.Span), i++) ;
            return buffer;
        }
    }
}
