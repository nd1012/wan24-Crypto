using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace wan24.Crypto
{
    /// <summary>
    /// .NET <see cref="HashAlgorithm"/> adapter for <see cref="Shake256"/>
    /// </summary>
    public sealed class NetShake256HashAlgorithmAdapter : HashAlgorithm
    {
        /// <summary>
        /// Digest
        /// </summary>
        private readonly Shake256 Digest = new();
        /// <summary>
        /// Output length in bytes (a multiple of 8)
        /// </summary>
        private readonly int OutputLength;
        /// <summary>
        /// If disposed
        /// </summary>
        private bool Disposed = false;
        /// <summary>
        /// If the final block was flushed
        /// </summary>
        private bool FinalBlockFlushed = false;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="outputLength">Output length in bytes (a multiple of 8)</param>
        public NetShake256HashAlgorithmAdapter(int outputLength = HashShake256Algorithm.HASH_LENGTH) : base()
        {
            ArgumentOutOfRangeException.ThrowIfLessThan(outputLength, 8, nameof(outputLength));
            if ((outputLength & 7) != 0) throw new ArgumentException("Output length must be a multiple of 8", nameof(outputLength));
            OutputLength = outputLength;
        }

        /// <inheritdoc/>
        public override void Initialize() { }

        /// <inheritdoc/>
        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            ObjectDisposedException.ThrowIf(Disposed, this);
            if (FinalBlockFlushed) throw new InvalidOperationException();
            Digest.AppendData(array.AsSpan(ibStart, cbSize));
        }

        /// <inheritdoc/>
        protected override void HashCore(ReadOnlySpan<byte> source)
        {
            ObjectDisposedException.ThrowIf(Disposed, this);
            if (FinalBlockFlushed) throw new InvalidOperationException();
            Digest.AppendData(source);
        }

        /// <inheritdoc/>
        protected override byte[] HashFinal()
        {
            ObjectDisposedException.ThrowIf(Disposed, this);
            if (FinalBlockFlushed) throw new InvalidOperationException();
            FinalBlockFlushed = true;
            byte[] res = new byte[OutputLength];
            Digest.GetCurrentHash(res);
            return res;
        }

        /// <inheritdoc/>
        protected override bool TryHashFinal(Span<byte> destination, [NotNullWhen(returnValue: true)] out int bytesWritten)
        {
            try
            {
                if (FinalBlockFlushed || Disposed || destination.Length < OutputLength)
                {
                    bytesWritten = 0;
                    return false;
                }
                FinalBlockFlushed = true;
                Digest.GetCurrentHash(destination.Length == OutputLength ? destination : destination[..OutputLength]);
                bytesWritten = OutputLength;
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
            base.Dispose(disposing);
            if (Disposed) return;
            Disposed = true;
            Digest.Dispose();
        }
    }
}
