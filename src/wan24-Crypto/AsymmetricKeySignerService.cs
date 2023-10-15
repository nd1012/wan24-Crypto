using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Parallel <see cref="AsymmetricPublicKeySigningRequest"/> signer service
    /// </summary>
    public sealed class AsymmetricKeySignerService : ParallelItemQueueWorkerBase<Action>
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="capacity">Key signing request queue capacity</param>
        /// <param name="threads">Number of threads to use for parallel processing</param>
        /// <param name="signer">Signer to use</param>
        public AsymmetricKeySignerService(in int capacity, in int threads, in AsymmetricKeySigner? signer = null) : base(capacity, threads)
            => Signer = signer ?? AsymmetricKeySigner.Instance ?? throw new InvalidOperationException("No key signer created/given");

        /// <summary>
        /// Singleton instance
        /// </summary>
        public static AsymmetricKeySignerService? Instance { get; set; }

        /// <summary>
        /// Used signer
        /// </summary>
        public AsymmetricKeySigner Signer { get; }

        /// <summary>
        /// Sign a key signing request
        /// </summary>
        /// <param name="request">Key signing request</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Signed key (will be disposed, if the used signer stored the signed key in a signed PKI store)</returns>
        public async Task<AsymmetricSignedPublicKey> SignAsync(AsymmetricPublicKeySigningRequest request, CancellationToken cancellationToken = default)
        {
            TaskCompletionSource<AsymmetricSignedPublicKey> tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
            await EnqueueAsync(() =>
            {
                try
                {
                    tcs.TrySetResult(Signer.SignKey(request));
                }
                catch (Exception ex)
                {
                    tcs.TrySetException(ex);
                }
            }, cancellationToken).DynamicContext();
            return await tcs.Task.DynamicContext();
        }

        /// <inheritdoc/>
        protected override async Task ProcessItem(Action item, CancellationToken cancellationToken)
        {
            await Task.Yield();
            item();
        }
    }
}
