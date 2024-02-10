using wan24.Core;

namespace wan24.Crypto
{
    // IKeyExchange implementation
    public sealed partial class Pake
    {
        /// <inheritdoc/>
        (byte[] Key, byte[] KeyExchangeData) IKeyExchange.GetKeyExchangeData()
        {
            using PakeAuth auth = CreateAuth();
            return (SessionKey.CloneArray(), auth);
        }

        /// <inheritdoc/>
        byte[] IKeyExchange.DeriveKey(byte[] keyExchangeData)
        {
            HandleAuth((PakeAuth)keyExchangeData);
            return SessionKey.CloneArray();
        }
    }
}
