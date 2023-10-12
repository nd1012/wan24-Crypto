using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// RNG which combines two or more RNGs with XOR
    /// </summary>
    public sealed class XorRng : RngBase
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="rngs">RNGs to use</param>
        public XorRng(params IRng[] rngs) : base()
        {
            if (rngs.Length < 2) throw new ArgumentOutOfRangeException(nameof(rngs), "Need at last 2 RNGs");
            RNG = rngs;
        }

        /// <summary>
        /// RNGs to use
        /// </summary>
        public IRng[] RNG { get; }

        /// <inheritdoc/>
        public override Span<byte> FillBytes(in Span<byte> buffer)
        {
            if (buffer.Length == 0) return buffer;
            using RentedArrayRefStruct<byte> res = new(buffer.Length, clean: false)
            {
                Clear = true
            };
            for (int i = 0, len = RNG.Length; i != len; RNG[i].FillBytes(res.Span), buffer.Xor(res.Span), i++) ;
            return buffer;
        }

        /// <inheritdoc/>
        public override async Task<Memory<byte>> FillBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (buffer.Length == 0) return buffer;
            using RentedArrayStructSimple<byte> res = new(buffer.Length, clean: false)
            {
                Clear = true
            };
            for (int i = 0, len = RNG.Length; i != len; await RNG[i].FillBytesAsync(res.Memory, cancellationToken).DynamicContext(), buffer.Span.Xor(res.Span), i++) ;
            return buffer;
        }
    }
}
