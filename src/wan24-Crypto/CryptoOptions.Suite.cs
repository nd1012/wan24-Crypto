namespace wan24.Crypto
{
    // Suite
    public partial class CryptoOptions
    {
        /// <summary>
        /// Apply a private key suite (will set keys for PFS key encryption)
        /// </summary>
        /// <param name="suite">Private key suite</param>
        /// <param name="withCounterAlgorithms">With counter algorithms?</param>
        public void ApplyPrivateKeySuite(PrivateKeySuite suite, bool withCounterAlgorithms = true)
        {
            if (suite.KeyExchangeKey != null) SetKeys(suite.KeyExchangeKey, suite.Public.KeyExchangeKey);
            if (withCounterAlgorithms && suite.CounterKeyExchangeKey != null) SetCounterKeys(suite.CounterKeyExchangeKey, suite.Public.CounterKeyExchangeKey);
            if (suite.KeyExchangeKey == null && suite.SymmetricKey != null) Password = (byte[])suite.SymmetricKey.Clone();
        }

        /// <summary>
        /// Apply a public key suite (will set peer keys for PFS key encryption)
        /// </summary>
        /// <param name="suite">Public key suite</param>
        /// <param name="withCounterAlgorithms">With counter algorithms?</param>
        public void ApplyPublicKeySuite(PublicKeySuite suite, bool withCounterAlgorithms = true)
        {
            if (suite.KeyExchangeKey != null) PublicKey = suite.KeyExchangeKey;
            if (withCounterAlgorithms && suite.CounterKeyExchangeKey != null) CounterPublicKey = suite.CounterKeyExchangeKey;
        }

        /// <summary>
        /// Create a private key suite
        /// </summary>
        /// <returns>Private key suite (don't forget to dispose)</returns>
        public PrivateKeySuite CreatePrivateKeySuite()
        {
            PrivateKeySuite res = new();
            try
            {
                if (PrivateKey?.Algorithm.CanExchangeKey ?? false) res.KeyExchangeKey = (IKeyExchangePrivateKey)PrivateKey.GetCopy();
                if (PrivateKey?.Algorithm.CanSign ?? false) res.SignatureKey = (ISignaturePrivateKey)PrivateKey.GetCopy();
                if (CounterPrivateKey?.Algorithm.CanExchangeKey ?? false) res.CounterKeyExchangeKey = (IKeyExchangePrivateKey)CounterPrivateKey.GetCopy();
                if (CounterPrivateKey?.Algorithm.CanSign ?? false) res.CounterSignatureKey = (ISignaturePrivateKey)CounterPrivateKey.GetCopy();
                if (Password != null) res.SymmetricKey = (byte[])Password.Clone();
                return res;
            }
            catch
            {
                res.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Createa public key suite
        /// </summary>
        /// <returns>Public key suite (don't forget to dispose)</returns>
        public PublicKeySuite CreatePublicKeySuite()
        {
            PublicKeySuite res = new();
            try
            {
                if (PublicKey?.Algorithm.CanExchangeKey ?? false) res.KeyExchangeKey = PublicKey.GetCopy();
                res.KeyExchangeKey ??= PrivateKey?.Algorithm.CanExchangeKey ?? false ? PrivateKey.PublicKey.GetCopy() : null;
                if (PublicKey?.Algorithm.CanSign ?? false) res.SignatureKey = (ISignaturePublicKey)PublicKey.GetCopy();
                res.SignatureKey ??= PrivateKey?.Algorithm.CanSign ?? false ? (ISignaturePublicKey)PrivateKey.PublicKey.GetCopy() : null;
                if (CounterPublicKey?.Algorithm.CanExchangeKey ?? false) res.CounterKeyExchangeKey = CounterPublicKey.GetCopy();
                res.CounterKeyExchangeKey ??= CounterPrivateKey?.Algorithm.CanExchangeKey ?? false ? CounterPrivateKey.PublicKey.GetCopy() : null;
                if (CounterPublicKey?.Algorithm.CanSign ?? false) res.CounterSignatureKey = (ISignaturePublicKey)CounterPublicKey.GetCopy();
                res.CounterSignatureKey ??= CounterPrivateKey?.Algorithm.CanSign ?? false ? (ISignaturePublicKey)CounterPrivateKey.PublicKey.GetCopy() : null;
                return res;
            }
            catch
            {
                res.Dispose();
                throw;
            }
        }
    }
}
