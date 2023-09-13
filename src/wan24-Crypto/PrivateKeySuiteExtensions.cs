using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    /// <summary>
    /// Private key suite extensions
    /// </summary>
    public static class PrivateKeySuiteExtensions
    {
        /// <summary>
        /// Set the (new) key exchange private key
        /// </summary>
        /// <param name="suite">Private key suite</param>
        /// <param name="key">Key exchange private key</param>
        /// <returns>Private key suite</returns>
        public static PrivateKeySuite WithKeyExchangeKey(this PrivateKeySuite suite, IKeyExchangePrivateKey? key = null)
        {
            suite.KeyExchangeKey?.Dispose();
            suite.KeyExchangeKey = key ?? AsymmetricHelper.CreateKeyExchangeKeyPair();
            return suite;
        }

        /// <summary>
        /// Set the (new) counter key exchange private key
        /// </summary>
        /// <param name="suite">Private key suite</param>
        /// <param name="key">Key exchange private key</param>
        /// <returns>Private key suite</returns>
        public static PrivateKeySuite WithCounterKeyExchangeKey(this PrivateKeySuite suite, IKeyExchangePrivateKey? key = null)
        {
            suite.CounterKeyExchangeKey?.Dispose();
            suite.CounterKeyExchangeKey = key ?? (IKeyExchangePrivateKey?)HybridAlgorithmHelper.KeyExchangeAlgorithm?.CreateKeyPair() ?? AsymmetricHelper.CreateKeyExchangeKeyPair();
            return suite;
        }

        /// <summary>
        /// Set the (new) signature private key
        /// </summary>
        /// <param name="suite">Private key suite</param>
        /// <param name="key">Signature private key</param>
        /// <returns>Private key suite</returns>
        public static PrivateKeySuite WithSignatureKey(this PrivateKeySuite suite, ISignaturePrivateKey? key = null)
        {
            suite.SignatureKey?.Dispose();
            suite.SignatureKey = key ?? AsymmetricHelper.CreateSignatureKeyPair();
            return suite;
        }

        /// <summary>
        /// Set the (new) counter signature private key
        /// </summary>
        /// <param name="suite">Private key suite</param>
        /// <param name="key">Signature private key</param>
        /// <returns>Private key suite</returns>
        public static PrivateKeySuite WithCounterSignatureKey(this PrivateKeySuite suite, ISignaturePrivateKey? key = null)
        {
            suite.CounterSignatureKey?.Dispose();
            suite.CounterSignatureKey = key ?? (ISignaturePrivateKey?)HybridAlgorithmHelper.SignatureAlgorithm?.CreateKeyPair() ?? AsymmetricHelper.CreateSignatureKeyPair();
            return suite;
        }

        /// <summary>
        /// Set the (new) signed public key
        /// </summary>
        /// <param name="suite">Private key suite</param>
        /// <param name="key">Signed public key</param>
        /// <returns>Private key suite</returns>
        public static PrivateKeySuite WithSignedPublicKey(this PrivateKeySuite suite, AsymmetricSignedPublicKey key)
        {
            suite.SignedPublicKey?.Dispose();
            suite.SignedPublicKey = key;
            return suite;
        }

        /// <summary>
        /// Set the (new) symmetric key
        /// </summary>
        /// <param name="suite">Private key suite</param>
        /// <param name="key">Symmetric key (if <see langword="null"/>, a 64 byte random key will be generated)</param>
        /// <returns>Private key suite</returns>
        public static PrivateKeySuite WithSymmetricKey(this PrivateKeySuite suite, byte[]? key = null)
        {
            if (key != null && (key.Length < 1 || key.Length > byte.MaxValue)) throw new ArgumentOutOfRangeException(nameof(key));
            suite.SymmetricKey?.Clear();
            suite.SymmetricKey = key ?? RND.GetBytes(64);
            return suite;
        }

        /// <summary>
        /// Set the (new) symmetric key
        /// </summary>
        /// <param name="suite">Private key suite</param>
        /// <param name="len">Length in bytes</param>
        /// <returns>Private key suite</returns>
        public static PrivateKeySuite WithSymmetricKey(this PrivateKeySuite suite, int len)
        {
            if (len < 1 || len > byte.MaxValue) throw new ArgumentOutOfRangeException(nameof(len));
            suite.SymmetricKey?.Clear();
            suite.SymmetricKey = RND.GetBytes(len);
            return suite;
        }
    }
}
