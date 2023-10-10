﻿namespace wan24.Crypto
{
    /// <summary>
    /// Interface for a seedable RNG
    /// </summary>
    public interface ISeedableRng
    {
        /// <summary>
        /// Add seed to the RNG
        /// </summary>
        /// <param name="seed">Seed</param>
        void AddSeed(ReadOnlySpan<byte> seed);
        /// <summary>
        /// Add seed to the RNG
        /// </summary>
        /// <param name="seed">Seed</param>
        /// <param name="cancellationToken">Cancellation token</param>
        Task AddSeedAsync(ReadOnlyMemory<byte> seed, CancellationToken cancellationToken = default);
    }
}
