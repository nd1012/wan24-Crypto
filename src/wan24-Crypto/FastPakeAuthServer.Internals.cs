using wan24.Core;

namespace wan24.Crypto
{
    // Internals
    public sealed partial class FastPakeAuthServer
    {
        /// <summary>
        /// Change token
        /// </summary>
        private readonly DisposableChangeToken ChangeToken = new();
        /// <summary>
        /// Authentication counter
        /// </summary>
        private volatile int _AuthCount = 0;
        /// <summary>
        /// Authentication error counter
        /// </summary>
        private volatile int _AuthErrorCount = 0;

        /// <summary>
        /// Set changed
        /// </summary>
        /// <param name="propertyName">Property name</param>
        private void SetChanged(in string propertyName)
        {
            ChangeToken.InvokeCallbacks();
            ChangeToken.RaisePropertyChanged(propertyName);
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            FastPakeAuthServerTable.Servers.TryRemove(GUID, out _);
            using SemaphoreSync sync = Sync;
            using SemaphoreSyncContext ssc = sync;
            Pake?.Dispose();
            Secret?.Dispose();
            Key?.Dispose();
            ChangeToken.Dispose();
        }

        /// <inheritdoc/>
        protected override async Task DisposeCore()
        {
            FastPakeAuthServerTable.Servers.TryRemove(GUID, out _);
            using (Sync)
            {
                using SemaphoreSyncContext ssc = await Sync.SyncContextAsync().DynamicContext();
                if (Secret is not null) await Secret.DisposeAsync().DynamicContext();
                if (Key is not null) await Key.DisposeAsync().DynamicContext();
                if (Pake is not null) await Pake.DisposeAsync().DynamicContext();
                ChangeToken.Dispose();
            }
        }
    }
}
