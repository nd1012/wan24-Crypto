using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Seeds an RNG with streamed cipher data
    /// </summary>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="cipherStream">Cipher data stream</param>
    /// <param name="rng">RNG to seed (if not given, <see cref="RND"/> will be seeded)</param>
    /// <param name="leaveOpen">Leave the cipher stream open when disposing?</param>
    public class RngSeedingStream(in Stream cipherStream, in ISeedableRng? rng = null, in bool leaveOpen = false) : RngSeedingStream<Stream>(cipherStream, rng, leaveOpen)
    {
    }

    /// <summary>
    /// Seeds an RNG with streamed cipher data
    /// </summary>
    /// <typeparam name="T">Base stream type</typeparam>
    /// <remarks>
    /// Constructor
    /// </remarks>
    /// <param name="cipherStream">Cipher data stream</param>
    /// <param name="rng">RNG to seed (if not given, <see cref="RND"/> will be seeded)</param>
    /// <param name="leaveOpen">Leave the cipher stream open when disposing?</param>
    public class RngSeedingStream<T>(in T cipherStream, in ISeedableRng? rng = null, in bool leaveOpen = false) : WrapperStream<T>(cipherStream, leaveOpen) where T : Stream
    {
        /// <summary>
        /// RNG to seed (if <see langword="null"/>, <see cref="RND"/> will be seeded)
        /// </summary>
        public ISeedableRng? RNG { get; } = rng;

        /// <inheritdoc/>
        public override int Read(byte[] buffer, int offset, int count)
        {
            int res = base.Read(buffer, offset, count);
            if (res != 0) AddSeed(buffer.AsSpan(offset, res));
            return res;
        }

        /// <inheritdoc/>
        public override int Read(Span<byte> buffer)
        {
            int res = base.Read(buffer);
            if (res != 0) AddSeed(buffer[..res]);
            return res;
        }

        /// <inheritdoc/>
        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            int res = await base.ReadAsync(buffer, offset, count, cancellationToken).DynamicContext();
            if (res != 0) await AddSeedAsync(buffer.AsMemory(offset, res), cancellationToken).DynamicContext();
            return res;
        }

        /// <inheritdoc/>
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int res = await base.ReadAsync(buffer, cancellationToken).DynamicContext();
            if (res != 0) await AddSeedAsync(buffer[..res], cancellationToken).DynamicContext();
            return res;
        }

        /// <inheritdoc/>
        public override int ReadByte()
        {
            int res = base.ReadByte();
            if (res == -1) return res;
            using RentedArrayRefStruct<byte> buffer = new(len: 1, clean: false)
            {
                Clear = true
            };
            buffer[0] = (byte)res;
            AddSeed(buffer.Span);
            return res;
        }

        /// <inheritdoc/>
        public override void Write(byte[] buffer, int offset, int count)
        {
            base.Write(buffer, offset, count);
            AddSeed(buffer.AsSpan(offset, count));
        }

        /// <inheritdoc/>
        public override void Write(ReadOnlySpan<byte> buffer)
        {
            base.Write(buffer);
            AddSeed(buffer);
        }

        /// <inheritdoc/>
        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            await base.WriteAsync(buffer, offset, count, cancellationToken).DynamicContext();
            await AddSeedAsync(buffer.AsMemory(offset, count), cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await base.WriteAsync(buffer, cancellationToken).DynamicContext();
            await AddSeedAsync(buffer, cancellationToken).DynamicContext();
        }

        /// <inheritdoc/>
        public override void WriteByte(byte value)
        {
            base.WriteByte(value);
            using RentedArrayRefStruct<byte> buffer = new(len: 1, clean: false)
            {
                Clear = true
            };
            buffer[0] = value;
            AddSeed(buffer.Span);
        }

        /// <summary>
        /// Add seed to the RNG
        /// </summary>
        /// <param name="seed">Seed</param>
        protected virtual void AddSeed(ReadOnlySpan<byte> seed)
        {
            if (RNG is null) RND.AddSeed(seed);
            else RNG.AddSeed(seed);
        }

        /// <summary>
        /// Add seed to the RNG
        /// </summary>
        /// <param name="seed">Seed</param>
        /// <param name="cancellationToken">Cancellation token</param>
        protected virtual async Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default)
        {
            if (RNG is null) await RND.AddSeedAsync(seed, cancellationToken).DynamicContext();
            else await RNG.AddSeedAsync(seed, cancellationToken).DynamicContext();
        }
    }
}
