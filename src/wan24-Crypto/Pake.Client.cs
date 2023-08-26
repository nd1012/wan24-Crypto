using System.Security.Cryptography;
using wan24.Core;

namespace wan24.Crypto
{
    // Client
    public sealed partial class Pake
    {
        /// <summary>
        /// Private key
        /// </summary>
        private readonly SymmetricKeySuite? Key;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="key">Private key (requires an identifier; initializes client operations; will be disposed!)</param>
        /// <param name="options">Options with KDF and MAC settings (will be cleared!)</param>
        public Pake(SymmetricKeySuite key, CryptoOptions? options = null) : this(options)
        {
            if (key.Identifier is null) throw new ArgumentException("Missing identifier", nameof(key));
            Key = key;
            Identity = null;
        }

        /// <summary>
        /// Create a signup (client)
        /// </summary>
        /// <returns>Signup (send this to the server and don't forget to dispose!)</returns>
        public PakeSignup CreateSignup()
        {
            EnsureUndisposed();
            if (Key?.Identifier is null) throw new InvalidOperationException("Initialized for server operation");
            byte[] secret = null!,// Needs to be sent to the server for the signup ONLY
                key = null!,
                random = RandomNumberGenerator.GetBytes(Key.ExpandedKey.Length),
                signatureKey = null!,
                signature = null!;
            try
            {
                key = CreateAuthKey();// MAC
                secret = CreateSecret(key);// MAC
                signatureKey = CreateSignatureKey(key);// KDF
                signature = CreateSignatureAndSessionKey(signatureKey, key, random, secret);// MAC
                return new PakeSignup(Key.Identifier.CloneArray(), secret, key, signature, random);
            }
            catch
            {
                secret?.Clear();
                key?.Clear();
                random.Clear();
                signature?.Clear();
                throw;
            }
            finally
            {
                signatureKey?.Clear();
            }
        }

        /// <summary>
        /// Create an authentication (client)
        /// </summary>
        /// <returns>Authentication (send this to the server and don't forget to dispose!)</returns>
        public PakeAuth CreateAuth()
        {
            EnsureUndisposed();
            if (Key?.Identifier is null) throw new InvalidOperationException("Initialized for server operation");
            byte[] secret = null!,
                key = null!,
                random = RandomNumberGenerator.GetBytes(Key.ExpandedKey.Length),
                signatureKey = null!,
                signature = null!;
            try
            {
                key = CreateAuthKey();// MAC
                secret = CreateSecret(key);// MAC
                signatureKey = CreateSignatureKey(key);// KDF
                signature = CreateSignatureAndSessionKey(signatureKey, key, random, secret);// MAC
                return new PakeAuth(Key.Identifier.CloneArray(), key, signature, random);
            }
            catch
            {
                key?.Clear();
                random.Clear();
                signature?.Clear();
                throw;
            }
            finally
            {
                secret?.Clear();
                signatureKey?.Clear();
            }
        }
    }
}
