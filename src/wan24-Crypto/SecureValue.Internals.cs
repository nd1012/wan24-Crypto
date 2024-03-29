﻿using wan24.Core;

namespace wan24.Crypto
{
    // Internals
    public partial class SecureValue
    {
        /// <summary>
        /// Default value encryption random key length in bytes
        /// </summary>
        protected const int DEFAULT_KEY_LEN = 64;

        /// <summary>
        /// Encrypt timer
        /// </summary>
        private readonly System.Timers.Timer EncryptTimer = null!;
        /// <summary>
        /// Recrypt timer
        /// </summary>
        private readonly System.Timers.Timer RecryptTimer = null!;
        /// <summary>
        /// Thread synchronization
        /// </summary>
        private readonly SemaphoreSync Sync = new();
        /// <summary>
        /// Random value encryption key length in bytes
        /// </summary>
        private int _KeyLen;
        /// <summary>
        /// Raw value
        /// </summary>
        private SecureByteArray? RawValue;
        /// <summary>
        /// Encrypted value
        /// </summary>
        private SecureByteArray? EncryptedValue = null;
        /// <summary>
        /// Encryption key
        /// </summary>
        private SecureByteArray? EncryptionKey = null;

        /// <summary>
        /// Encrypt
        /// </summary>
        protected virtual void Encrypt()
        {
            using SemaphoreSyncContext ssc = Sync;
            if (RawValue is null) return;
            EncryptedSince = DateTime.Now;
            EncryptTimer.Stop();
            EncryptionKey = new(RND.GetBytes(_KeyLen));
            using (SecureByteArray rawValue = RawValue)
                EncryptedValue = new(rawValue!.Array.Encrypt(EncryptionKey, Options));
            RawValue = null;
            RecryptTimer.Start();
        }

        /// <summary>
        /// Decrypt
        /// </summary>
        /// <returns>Value (should be cleared!)</returns>
        protected virtual byte[] Decrypt()
        {
            if (RawValue is not null) return RawValue.Array.CloneArray();
            if (EncryptTimeout == TimeSpan.Zero)
                return EncryptedValue!.Array.Decrypt(EncryptionKey!, Options);
            EncryptedSince = DateTime.MinValue;
            RecryptTimer.Stop();
            try
            {
                using SecureByteArray encryptedValue = EncryptedValue!;
                using SecureByteArray encryptionKey = EncryptionKey!;
                RawValue = new(EncryptedValue!.Array.Decrypt(EncryptionKey!, Options));
                EncryptedValue = null;
                EncryptionKey = null;
                return RawValue.Array.CloneArray();
            }
            finally
            {
                EncryptTimer.Start();
            }
        }

        /// <summary>
        /// Re-crypt
        /// </summary>
        protected virtual void Recrypt()
        {
            using SemaphoreSyncContext ssc = Sync;
            if (RawValue is not null) return;
            RecryptTimer.Stop();
            using SecureByteArrayRefStruct rawValue = new(EncryptedValue!.Array.Decrypt(EncryptionKey!, Options));
            {
                EncryptionKey!.Dispose();
                EncryptedValue.Dispose();
                EncryptionKey = new(RND.GetBytes(_KeyLen));
                EncryptedValue = new(rawValue.Array.Encrypt(EncryptionKey, Options));
            }
            RecryptTimer.Start();
        }

        /// <inheritdoc/>
        protected override void Dispose(bool disposing)
        {
            SecureValueTable.Values.TryRemove(GUID, out _);
            using System.Timers.Timer? encryptTimer = EncryptTimer;
            using System.Timers.Timer? recryptTimer = RecryptTimer;
            using SemaphoreSync sync = Sync;
            using SemaphoreSyncContext ssc = sync;
            using SecureByteArray? encryptedValue = EncryptedValue;
            using SecureByteArray? encryptionKey = EncryptionKey;
            using SecureByteArray? rawValue = RawValue;
            RecryptTimer?.Stop();
            EncryptTimer?.Stop();
            Options?.Clear();
        }
    }
}
