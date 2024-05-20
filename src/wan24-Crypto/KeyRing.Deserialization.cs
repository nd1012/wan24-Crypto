using wan24.Core;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    // Deserialization
    public sealed partial class KeyRing
    {
        /// <inheritdoc/>
        protected override void Deserialize(Stream stream, int version)
        {
            Dictionary<string, KeyTypes> keyNames = stream.ReadDict<string, KeyTypes>(version, maxLen: MaxCount);//TODO Use key/value options
            SerializedCount = keyNames.Count;
            KeyNames.AddRange(keyNames);
            Dictionary<int, string> nameHashCodes = new(keyNames.Count);
            foreach (string key in keyNames.Keys) nameHashCodes[key.GetHashCode()] = key;
            int len = stream.ReadNumber<int>(version),
                nameHashCode,
                dataLen;
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many symmetric keys ({len})");
            {
                byte[] key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = stream.ReadNumber<int>(version);
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown symmetric key name (key #{i}, hash code {nameHashCode})");
                    key = stream.ReadBytes(version, maxLen: MaxSymmetricKeyLength).Value;
                    if (!TryAdd(name, key))
                    {
                        key.Clear();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at symmetric key #{i}");
                    }
                }
            }
            len = stream.ReadNumber<int>(version);
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many asymmetric private keys ({len})");
            {
                byte[] keyData;
                IAsymmetricKey key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = stream.ReadNumber<int>(version);
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown asymmetric private key name (key #{i}, hash code {nameHashCode})");
                    keyData = stream.ReadBytes(version, maxLen: MaxSymmetricKeyLength).Value;
                    try
                    {
                        key = AsymmetricKeyBase.Import(keyData);
                    }
                    catch (Exception ex)
                    {
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing asymmetric private key #{i}: {ex}");
                        continue;
                    }
                    finally
                    {
                        keyData.Clear();
                    }
                    if (key is not IAsymmetricPrivateKey)
                        try
                        {
                            throw new InvalidDataException($"Invalid asymmetric private key #{i} {key.GetType()}");
                        }
                        finally
                        {
                            key.Dispose();
                        }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at asymmetric private key #{i}");
                    }
                }
            }
            len = stream.ReadNumber<int>(version);
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many asymmetric public keys ({len})");
            {
                byte[] keyData;
                IAsymmetricKey key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = stream.ReadNumber<int>(version);
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown asymmetric public key name (key #{i}, hash code {nameHashCode})");
                    keyData = stream.ReadBytes(version, maxLen: MaxSymmetricKeyLength).Value;
                    try
                    {
                        key = AsymmetricKeyBase.Import(keyData);
                    }
                    catch (Exception ex)
                    {
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing asymmetric public key #{i}: {ex}");
                        continue;
                    }
                    finally
                    {
                        keyData.Clear();
                    }
                    if (key is IAsymmetricPrivateKey)
                        try
                        {
                            throw new InvalidDataException($"Invalid asymmetric public key #{i} {key.GetType()}");
                        }
                        finally
                        {
                            key.Dispose();
                        }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at asymmetric public key #{i}");
                    }
                }
            }
            len = stream.ReadNumber<int>(version);
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many private key suites ({len})");
            {
                PrivateKeySuite key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = stream.ReadNumber<int>(version);
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown private key suite name (key #{i}, hash code {nameHashCode})");
                    dataLen = stream.ReadNumber<int>(version);
                    using LimitedLengthStream limited = new(stream, dataLen, leaveOpen: true)
                    {
                        ThrowOnReadOverflow = true
                    };
                    try
                    {
                        key = limited.ReadSerialized<PrivateKeySuite>(version);
                    }
                    catch (Exception ex)
                    {
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing private key suite #{i}: {ex}");
                        stream.CopyPartialTo(Stream.Null, dataLen - limited.Position);
                        continue;
                    }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at private key suite #{i}");
                    }
                }
            }
            len = stream.ReadNumber<int>(version);
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many public key suites ({len})");
            {
                PublicKeySuite key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = stream.ReadNumber<int>(version);
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown public key suite name (key #{i}, hash code {nameHashCode})");
                    dataLen = stream.ReadNumber<int>(version);
                    using LimitedLengthStream limited = new(stream, dataLen, leaveOpen: true)
                    {
                        ThrowOnReadOverflow = true
                    };
                    try
                    {
                        key = limited.ReadSerialized<PublicKeySuite>(version);
                    }
                    catch (Exception ex)
                    {
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing public key suite #{i}: {ex}");
                        stream.CopyPartialTo(Stream.Null, dataLen - limited.Position);
                        continue;
                    }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at public key suite #{i}");
                    }
                }
            }
            len = stream.ReadNumber<int>(version);
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many private key suite stores ({len})");
            {
                PrivateKeySuiteStore key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = stream.ReadNumber<int>(version);
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown private key suite store name (key #{i}, hash code {nameHashCode})");
                    dataLen = stream.ReadNumber<int>(version);
                    using LimitedLengthStream limited = new(stream, dataLen, leaveOpen: true)
                    {
                        ThrowOnReadOverflow = true
                    };
                    try
                    {
                        key = limited.ReadSerialized<PrivateKeySuiteStore>(version);
                    }
                    catch (Exception ex)
                    {
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing private key suite store #{i}: {ex}");
                        stream.CopyPartialTo(Stream.Null, dataLen - limited.Position);
                        continue;
                    }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at private key suite store #{i}");
                    }
                }
            }
            len = stream.ReadNumber<int>(version);
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many public key suite stores ({len})");
            {
                PublicKeySuiteStore key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = stream.ReadNumber<int>(version);
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown public key suite store name (key #{i}, hash code {nameHashCode})");
                    dataLen = stream.ReadNumber<int>(version);
                    using LimitedLengthStream limited = new(stream, dataLen, leaveOpen: true)
                    {
                        ThrowOnReadOverflow = true
                    };
                    try
                    {
                        key = limited.ReadSerialized<PublicKeySuiteStore>(version);
                    }
                    catch (Exception ex)
                    {
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing public key suite store #{i}: {ex}");
                        stream.CopyPartialTo(Stream.Null, dataLen - limited.Position);
                        continue;
                    }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at public key suite store #{i}");
                    }
                }
            }
            len = stream.ReadNumber<int>(version);
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many PAKE records ({len})");
            {
                PakeRecord key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = stream.ReadNumber<int>(version);
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown PAKE record name (key #{i}, hash code {nameHashCode})");
                    key = stream.ReadSerialized<PakeRecord>(version);
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at PAKE record #{i}");
                    }
                }
            }
            len = stream.ReadNumber<int>(version);
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many PAKE record stores ({len})");
            {
                PakeRecordStore key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = stream.ReadNumber<int>(version);
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown PAKE record store name (key #{i}, hash code {nameHashCode})");
                    key = stream.ReadSerialized<PakeRecordStore>(version);
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at PAKE record store #{i}");
                    }
                }
            }
            len = stream.ReadNumber<int>(version);
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many PKIs ({len})");
            {
                SignedPkiStore key;
                string typeName;
                Type type;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = stream.ReadNumber<int>(version);
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown PKI name (key #{i}, hash code {nameHashCode})");
                    typeName = stream.ReadString(version, minLen: 1, maxLen: byte.MaxValue);
                    type = TypeHelper.Instance.GetType(typeName, throwOnError: true)
                        ?? throw new InvalidDataException($"Can't resolve PKI type name {typeName.ToQuotedLiteral()}");
                    if (!typeof(SignedPkiStore).IsAssignableFrom(type) || !type.CanConstruct())
                        throw new InvalidDataException($"Invalid PKI type {type}");
                    dataLen = stream.ReadNumber<int>(version);
                    using LimitedLengthStream limited = new(stream, dataLen, leaveOpen: true)
                    {
                        ThrowOnReadOverflow = true
                    };
                    key = Activator.CreateInstance(type) as SignedPkiStore
                        ?? throw new InvalidDataException($"Failed to instance PKI {type}");
                    try
                    {
                        ((IStreamSerializer)key).Deserialize(limited, version);
                    }
                    catch (Exception ex)
                    {
                        key.Dispose();
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing PKI #{i}: {ex}");
                        stream.CopyPartialTo(Stream.Null, dataLen - limited.Position);
                        continue;
                    }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at PKI #{i}");
                    }
                }
            }
            len = stream.ReadNumber<int>(version);
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many options ({len})");
            {
                CryptoOptions options;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = stream.ReadNumber<int>(version);
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown options name (key #{i}, hash code {nameHashCode})");
                    options = stream.ReadSerialized<CryptoOptions>(version);
                    if (!TryAdd(name, options))
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at options #{i}");
                }
            }
        }

        /// <inheritdoc/>
        protected override async Task DeserializeAsync(Stream stream, int version, CancellationToken cancellationToken)
        {
            Dictionary<string, KeyTypes> keyNames = await stream.ReadDictAsync<string, KeyTypes>(version, maxLen: MaxCount, cancellationToken: cancellationToken).DynamicContext();//TODO Use key/value options
            SerializedCount = keyNames.Count;
            KeyNames.AddRange(keyNames);
            Dictionary<int, string> nameHashCodes = new(keyNames.Count);
            foreach (string key in keyNames.Keys) nameHashCodes[key.GetHashCode()] = key;
            int len = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext(),
                nameHashCode,
                dataLen;
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many symmetric keys ({len})");
            {
                byte[] key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown symmetric key name (key #{i}, hash code {nameHashCode})");
                    key = (await stream.ReadBytesAsync(version, maxLen: MaxSymmetricKeyLength, cancellationToken: cancellationToken).DynamicContext()).Value;
                    if (!TryAdd(name, key))
                    {
                        key.Clear();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at symmetric key #{i}");
                    }
                }
            }
            len = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many asymmetric private keys ({len})");
            {
                byte[] keyData;
                IAsymmetricKey key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown asymmetric private key name (key #{i}, hash code {nameHashCode})");
                    keyData = (await stream.ReadBytesAsync(version, maxLen: MaxSymmetricKeyLength, cancellationToken: cancellationToken).DynamicContext()).Value;
                    try
                    {
                        key = AsymmetricKeyBase.Import(keyData);
                    }
                    catch (Exception ex)
                    {
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing asymmetric private key #{i}: {ex}");
                        continue;
                    }
                    finally
                    {
                        keyData.Clear();
                    }
                    if (key is not IAsymmetricPrivateKey)
                        try
                        {
                            throw new InvalidDataException($"Invalid asymmetric private key #{i} {key.GetType()}");
                        }
                        finally
                        {
                            key.Dispose();
                        }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at asymmetric private key #{i}");
                    }
                }
            }
            len = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many asymmetric public keys ({len})");
            {
                byte[] keyData;
                IAsymmetricKey key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown asymmetric public key name (key #{i}, hash code {nameHashCode})");
                    keyData = (await stream.ReadBytesAsync(version, maxLen: MaxSymmetricKeyLength, cancellationToken: cancellationToken).DynamicContext()).Value;
                    try
                    {
                        key = AsymmetricKeyBase.Import(keyData);
                    }
                    catch (Exception ex)
                    {
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing asymmetric public key #{i}: {ex}");
                        continue;
                    }
                    finally
                    {
                        keyData.Clear();
                    }
                    if (key is IAsymmetricPrivateKey)
                        try
                        {
                            throw new InvalidDataException($"Invalid asymmetric public key #{i} {key.GetType()}");
                        }
                        finally
                        {
                            key.Dispose();
                        }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at asymmetric public key #{i}");
                    }
                }
            }
            len = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many private key suites ({len})");
            {
                PrivateKeySuite key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown private key suite name (key #{i}, hash code {nameHashCode})");
                    dataLen = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    using LimitedLengthStream limited = new(stream, dataLen, leaveOpen: true)
                    {
                        ThrowOnReadOverflow = true
                    };
                    try
                    {
                        key = await limited.ReadSerializedAsync<PrivateKeySuite>(version, cancellationToken: cancellationToken).DynamicContext();
                    }
                    catch (Exception ex)
                    {
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing private key suite #{i}: {ex}");
                        await stream.CopyPartialToAsync(Stream.Null, dataLen - limited.Position, cancellationToken: cancellationToken).DynamicContext();
                        continue;
                    }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at private key suite #{i}");
                    }
                }
            }
            len = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many public key suites ({len})");
            {
                PublicKeySuite key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown public key suite name (key #{i}, hash code {nameHashCode})");
                    dataLen = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    using LimitedLengthStream limited = new(stream, dataLen, leaveOpen: true)
                    {
                        ThrowOnReadOverflow = true
                    };
                    try
                    {
                        key = await limited.ReadSerializedAsync<PublicKeySuite>(version, cancellationToken: cancellationToken).DynamicContext();
                    }
                    catch (Exception ex)
                    {
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing public key suite #{i}: {ex}");
                        await stream.CopyPartialToAsync(Stream.Null, dataLen - limited.Position, cancellationToken: cancellationToken).DynamicContext();
                        continue;
                    }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at public key suite #{i}");
                    }
                }
            }
            len = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many private key suite stores ({len})");
            {
                PrivateKeySuiteStore key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown private key suite store name (key #{i}, hash code {nameHashCode})");
                    dataLen = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    using LimitedLengthStream limited = new(stream, dataLen, leaveOpen: true)
                    {
                        ThrowOnReadOverflow = true
                    };
                    try
                    {
                        key = await limited.ReadSerializedAsync<PrivateKeySuiteStore>(version, cancellationToken: cancellationToken).DynamicContext();
                    }
                    catch (Exception ex)
                    {
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing private key suite store #{i}: {ex}");
                        await stream.CopyPartialToAsync(Stream.Null, dataLen - limited.Position, cancellationToken: cancellationToken).DynamicContext();
                        continue;
                    }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at private key suite store #{i}");
                    }
                }
            }
            len = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many public key suite stores ({len})");
            {
                PublicKeySuiteStore key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown public key suite store name (key #{i}, hash code {nameHashCode})");
                    dataLen = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    using LimitedLengthStream limited = new(stream, dataLen, leaveOpen: true)
                    {
                        ThrowOnReadOverflow = true
                    };
                    try
                    {
                        key = await limited.ReadSerializedAsync<PublicKeySuiteStore>(version, cancellationToken: cancellationToken).DynamicContext();
                    }
                    catch (Exception ex)
                    {
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing public key suite store #{i}: {ex}");
                        await stream.CopyPartialToAsync(Stream.Null, dataLen - limited.Position, cancellationToken: cancellationToken).DynamicContext();
                        continue;
                    }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at public key suite store #{i}");
                    }
                }
            }
            len = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many PAKE records ({len})");
            {
                PakeRecord key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown PAKE record name (key #{i}, hash code {nameHashCode})");
                    key = await stream.ReadSerializedAsync<PakeRecord>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at PAKE record #{i}");
                    }
                }
            }
            len = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many PAKE record stores ({len})");
            {
                PakeRecordStore key;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown PAKE record store name (key #{i}, hash code {nameHashCode})");
                    key = await stream.ReadSerializedAsync<PakeRecordStore>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at PAKE record store #{i}");
                    }
                }
            }
            len = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many PKIs ({len})");
            {
                SignedPkiStore key;
                string typeName;
                Type type;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown PKI name (key #{i}, hash code {nameHashCode})");
                    typeName = await stream.ReadStringAsync(version, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
                    type = TypeHelper.Instance.GetType(typeName, throwOnError: true)
                        ?? throw new InvalidDataException($"Can't resolve PKI type name {typeName.ToQuotedLiteral()}");
                    if (!typeof(SignedPkiStore).IsAssignableFrom(type) || !type.CanConstruct())
                        throw new InvalidDataException($"Invalid PKI type {type}");
                    dataLen = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    using LimitedLengthStream limited = new(stream, dataLen, leaveOpen: true)
                    {
                        ThrowOnReadOverflow = true
                    };
                    key = Activator.CreateInstance(type) as SignedPkiStore
                        ?? throw new InvalidDataException($"Failed to instance PKI {type}");
                    try
                    {
                        await ((IStreamSerializer)key).DeserializeAsync(limited, version, cancellationToken).DynamicContext();
                    }
                    catch (Exception ex)
                    {
                        key.Dispose();
                        if (!IgnoreSerializationErrors) throw;
                        Logging.WriteWarning($"Skipped deserializing PKI #{i}: {ex}");
                        await stream.CopyPartialToAsync(Stream.Null, dataLen - limited.Position, cancellationToken: cancellationToken).DynamicContext();
                        continue;
                    }
                    if (!TryAdd(name, key))
                    {
                        key.Dispose();
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at PKI #{i}");
                    }
                }
            }
            len = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
            if (len < 0 || Count + len > MaxCount) throw new InvalidDataException($"Too many options ({len})");
            {
                CryptoOptions options;
                for (int i = 0; i < len; i++)
                {
                    nameHashCode = await stream.ReadNumberAsync<int>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!nameHashCodes.TryGetValue(nameHashCode, out string? name))
                        throw new InvalidDataException($"Unknown options name (key #{i}, hash code {nameHashCode})");
                    options = await stream.ReadSerializedAsync<CryptoOptions>(version, cancellationToken: cancellationToken).DynamicContext();
                    if (!TryAdd(name, options))
                        throw new InvalidDataException($"Double key name {name.ToQuotedLiteral()} at options #{i}");
                }
            }
        }
    }
}
