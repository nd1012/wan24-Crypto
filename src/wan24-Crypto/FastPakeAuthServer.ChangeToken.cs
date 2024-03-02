using Microsoft.Extensions.Primitives;
using System.ComponentModel;

namespace wan24.Crypto
{
    // Change token implementation
    public sealed partial class FastPakeAuthServer
    {
        /// <inheritdoc/>
        public bool HasChanged => ((IChangeToken)ChangeToken).HasChanged;

        /// <inheritdoc/>
        public bool ActiveChangeCallbacks => ((IChangeToken)ChangeToken).ActiveChangeCallbacks;

        /// <inheritdoc/>
        public IDisposable RegisterChangeCallback(Action<object?> callback, object? state) => ChangeToken.RegisterChangeCallback(callback, state);

        /// <inheritdoc/>
        public event PropertyChangedEventHandler? PropertyChanged
        {
            add => ChangeToken.PropertyChanged += value;
            remove => ChangeToken.PropertyChanged -= value;
        }
    }
}
