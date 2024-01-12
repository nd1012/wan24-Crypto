using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// .NET <see cref="HashAlgorithm"/> adapter for <see cref="Shake128"/>
    /// </summary>
    public sealed class NetShake128HashAlgorithmAdapter : HashAlgorithm
    {
        /// <summary>
        /// Digest
        /// </summary>
        private readonly Shake128 Digest = new();
        /// <summary>
        /// Output length in bytes (a multiple of 8)
        /// </summary>
        private readonly int OutputLength;
        /// <summary>
        /// If disposed
        /// </summary>
        private bool Disposed = false;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="outputLength">Output length in bytes (a multiple of 8)</param>
        public NetShake128HashAlgorithmAdapter(int outputLength = HashShake128Algorithm.HASH_LENGTH) : base()
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(outputLength, 8, nameof(outputLength));
            if ((outputLength & 7) != 0) throw new ArgumentException("Output length must be a multiple of 8", nameof(outputLength));
            OutputLength = outputLength;
        }

        /// <inheritdoc/>
        public override bool CanReuseTransform => false;

        /// <inheritdoc/>
        public override void Initialize() => ObjectDisposedException.ThrowIf(Disposed, this);

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            ObjectDisposedException.ThrowIf(Disposed, this);
            Digest.AppendData(array.AsSpan(ibStart, cbSize));
        }

        /// <inheritdoc/>
        protected override void HashCore(ReadOnlySpan<byte> source)
        {
            ObjectDisposedException.ThrowIf(Disposed, this);
            Digest.AppendData(source);
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            ObjectDisposedException.ThrowIf(Disposed, this);
            byte[] res = new byte[OutputLength];
            Digest.GetCurrentHash(res);
            Dispose();
            return res;
        }

        /// <inheritdoc/>
        protected override bool TryHashFinal(Span<byte> destination, out int bytesWritten)
        {
            try
            {
                ObjectDisposedException.ThrowIf(Disposed, this);
                ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, OutputLength, nameof(destination));
                Digest.GetCurrentHash(destination.Length == OutputLength ? destination : destination[..OutputLength]);
                bytesWritten = OutputLength;
                Dispose();
                return true;
            }
            catch
            {
                bytesWritten = 0;
                return false;
            }
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            if (Disposed) return;
            base.Dispose(disposing);
            Disposed = true;
            Digest.Dispose();
        }
    }
}
