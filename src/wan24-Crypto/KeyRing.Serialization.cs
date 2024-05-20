using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    // Serialization
    public sealed partial class KeyRing
    {
        /// <summary>
        /// Object version
        /// </summary>
        public const int VERSION = 1;

        /// <summary>
        /// Serialize and encrypt this private key suite for physical cold storage
        /// </summary>
        /// <param name="key">Key</param>
        /// <param name="options">Options</param>
        /// <returns>Cipher</returns>
        public byte[] Encrypt(byte[] key, CryptoOptions? options = null) => ((byte[])this).Encrypt(key, options);

        /// <inheritdoc/>
        protected override void Serialize(Stream stream)
        {
            using SemaphoreSyncContext ssc = Sync;
            using MemoryPoolStream ms = new()
            {
                CleanReturned = true
            };
            stream.WriteDict(KeyNames)
                .WriteNumber(SymmetricKeys.Count);
            foreach (var kvp in SymmetricKeys)
                stream.WriteNumber(kvp.Key.GetHashCode())
                    .WriteBytes(kvp.Value);
            stream.WriteNumber(AsymmetricPrivateKeys.Count);
            foreach (var kvp in AsymmetricPrivateKeys)
            {
                stream.WriteNumber(kvp.Key.GetHashCode());
                using SecureByteArray key = new(kvp.Value.Export());
                stream.WriteBytes(key.Span);
            }
            stream.WriteNumber(AsymmetricPublicKeys.Count);
            foreach (var kvp in AsymmetricPublicKeys)
            {
                stream.WriteNumber(kvp.Key.GetHashCode());
                using SecureByteArray key = new(kvp.Value.Export());
                stream.WriteBytes(key.Span);
            }
            stream.WriteNumber(PrivateKeys.Count);
            foreach (var kvp in PrivateKeys)
            {
                stream.WriteNumber(kvp.Key.GetHashCode());
                ms.WriteSerialized(kvp.Value);
                stream.WriteNumber(ms.Length);
                ms.Position = 0;
                ms.CopyTo(stream);
                ms.SetLength(0);
            }
            stream.WriteNumber(PublicKeys.Count);
            foreach (var kvp in PublicKeys)
            {
                stream.WriteNumber(kvp.Key.GetHashCode());
                ms.WriteSerialized(kvp.Value);
                stream.WriteNumber(ms.Length);
                ms.Position = 0;
                ms.CopyTo(stream);
                ms.SetLength(0);
            }
            stream.WriteNumber(PrivateKeySuites.Count);
            foreach (var kvp in PrivateKeySuites)
            {
                stream.WriteNumber(kvp.Key.GetHashCode());
                ms.WriteSerialized(kvp.Value);
                stream.WriteNumber(ms.Length);
                ms.Position = 0;
                ms.CopyTo(stream);
                ms.SetLength(0);
            }
            stream.WriteNumber(PublicKeySuites.Count);
            foreach (var kvp in PublicKeySuites)
            {
                stream.WriteNumber(kvp.Key.GetHashCode());
                ms.WriteSerialized(kvp.Value);
                stream.WriteNumber(ms.Length);
                ms.Position = 0;
                ms.CopyTo(stream);
                ms.SetLength(0);
            }
            stream.WriteNumber(PakeRecords.Count);
            foreach (var kvp in PakeRecords)
                stream.WriteNumber(kvp.Key.GetHashCode())
                    .WriteSerialized(kvp.Value);
            stream.WriteNumber(PakeRecordStores.Count);
            foreach (var kvp in PakeRecordStores)
                stream.WriteNumber(kvp.Key.GetHashCode())
                    .WriteSerialized(kvp.Value);
            stream.WriteNumber(Pkis.Count);
            foreach (var kvp in Pkis)
            {
                stream.WriteNumber(kvp.Key.GetHashCode())
                    .WriteString(kvp.Value.GetType().ToString());
                ms.WriteSerialized(kvp.Value);
                stream.WriteNumber(ms.Length);
                ms.Position = 0;
                ms.CopyTo(stream);
                ms.SetLength(0);
            }
            stream.WriteNumber(Options.Count);
            foreach (var kvp in Options)
                stream.WriteNumber(kvp.Key.GetHashCode())
                    .WriteSerialized(kvp.Value);
        }

        /// <inheritdoc/>
        protected override async Task SerializeAsync(Stream stream, CancellationToken cancellationToken)
        {
            using SemaphoreSyncContext ssc = await Sync.SyncContextAsync(cancellationToken).DynamicContext();
            using MemoryPoolStream ms = new()
            {
                CleanReturned = true
            };
            await stream.WriteDictAsync(KeyNames, cancellationToken).DynamicContext();
            await stream.WriteNumberAsync(SymmetricKeys.Count, cancellationToken).DynamicContext();
            foreach (var kvp in SymmetricKeys)
            {
                await stream.WriteNumberAsync(kvp.Key.GetHashCode(), cancellationToken).DynamicContext();
                await stream.WriteBytesAsync(kvp.Value, cancellationToken).DynamicContext();
            }
            await stream.WriteNumberAsync(AsymmetricPrivateKeys.Count, cancellationToken).DynamicContext();
            foreach (var kvp in AsymmetricPrivateKeys)
            {
                await stream.WriteNumberAsync(kvp.Key.GetHashCode(), cancellationToken).DynamicContext();
                using SecureByteArray key = new(kvp.Value.Export());
                await stream.WriteBytesAsync(key.Memory, cancellationToken).DynamicContext();
            }
            await stream.WriteNumberAsync(AsymmetricPublicKeys.Count, cancellationToken).DynamicContext();
            foreach (var kvp in AsymmetricPublicKeys)
            {
                await stream.WriteNumberAsync(kvp.Key.GetHashCode(), cancellationToken).DynamicContext();
                using SecureByteArray key = new(kvp.Value.Export());
                await stream.WriteBytesAsync(key.Memory, cancellationToken).DynamicContext(); ;
            }
            await stream.WriteNumberAsync(PrivateKeys.Count, cancellationToken).DynamicContext();
            foreach (var kvp in PrivateKeys)
            {
                await stream.WriteNumberAsync(kvp.Key.GetHashCode(), cancellationToken).DynamicContext();
                ms.WriteSerialized(kvp.Value);
                await stream.WriteNumberAsync(ms.Length, cancellationToken: cancellationToken).DynamicContext();
                ms.Position = 0;
                await ms.CopyToAsync(stream, cancellationToken: cancellationToken).DynamicContext();
                ms.SetLength(0);
            }
            await stream.WriteNumberAsync(PublicKeys.Count, cancellationToken).DynamicContext();
            foreach (var kvp in PublicKeys)
            {
                await stream.WriteNumberAsync(kvp.Key.GetHashCode(), cancellationToken).DynamicContext();
                ms.WriteSerialized(kvp.Value);
                await stream.WriteNumberAsync(ms.Length, cancellationToken: cancellationToken).DynamicContext();
                ms.Position = 0;
                await ms.CopyToAsync(stream, cancellationToken: cancellationToken).DynamicContext();
                ms.SetLength(0);
            }
            await stream.WriteNumberAsync(PrivateKeySuites.Count, cancellationToken).DynamicContext();
            foreach (var kvp in PrivateKeySuites)
            {
                await stream.WriteNumberAsync(kvp.Key.GetHashCode(), cancellationToken).DynamicContext();
                ms.WriteSerialized(kvp.Value);
                await stream.WriteNumberAsync(ms.Length, cancellationToken: cancellationToken).DynamicContext();
                ms.Position = 0;
                await ms.CopyToAsync(stream, cancellationToken: cancellationToken).DynamicContext();
                ms.SetLength(0);
            }
            await stream.WriteNumberAsync(PublicKeySuites.Count, cancellationToken).DynamicContext();
            foreach (var kvp in PublicKeySuites)
            {
                await stream.WriteNumberAsync(kvp.Key.GetHashCode(), cancellationToken).DynamicContext();
                ms.WriteSerialized(kvp.Value);
                await stream.WriteNumberAsync(ms.Length, cancellationToken: cancellationToken).DynamicContext();
                ms.Position = 0;
                await ms.CopyToAsync(stream, cancellationToken: cancellationToken).DynamicContext();
                ms.SetLength(0);
            }
            await stream.WriteNumberAsync(PakeRecords.Count, cancellationToken).DynamicContext();
            foreach (var kvp in PakeRecords)
            {
                await stream.WriteNumberAsync(kvp.Key.GetHashCode(), cancellationToken).DynamicContext();
                await stream.WriteSerializedAsync(kvp.Value, cancellationToken).DynamicContext();
            }
            await stream.WriteNumberAsync(PakeRecordStores.Count, cancellationToken).DynamicContext();
            foreach (var kvp in PakeRecordStores)
            {
                await stream.WriteNumberAsync(kvp.Key.GetHashCode(), cancellationToken).DynamicContext();
                await stream.WriteSerializedAsync(kvp.Value, cancellationToken).DynamicContext();
            }
            await stream.WriteNumberAsync(Pkis.Count, cancellationToken).DynamicContext();
            foreach (var kvp in Pkis)
            {
                await stream.WriteNumberAsync(kvp.Key.GetHashCode(), cancellationToken).DynamicContext();
                await stream.WriteStringAsync(kvp.Key.GetType().ToString(), cancellationToken).DynamicContext();
                ms.WriteSerialized(kvp.Value);
                await stream.WriteNumberAsync(ms.Length, cancellationToken: cancellationToken).DynamicContext();
                ms.Position = 0;
                await ms.CopyToAsync(stream, cancellationToken: cancellationToken).DynamicContext();
                ms.SetLength(0);
            }
            await stream.WriteNumberAsync(Options.Count, cancellationToken).DynamicContext();
            foreach (var kvp in Options)
            {
                await stream.WriteNumberAsync(kvp.Key.GetHashCode(), cancellationToken).DynamicContext();
                await stream.WriteSerializedAsync(kvp.Value, cancellationToken).DynamicContext();
            }
        }
    }
}
