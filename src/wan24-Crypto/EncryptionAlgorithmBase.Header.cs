using System.Buffers;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    // Header methods
    public partial class EncryptionAlgorithmBase
    {
        /// <summary>
        /// Write the options
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Written options and used MAC stream</returns>
        public virtual (CryptoOptions Options, MacStreams? MacStream) WriteOptions(Stream rawData, Stream cipherData, byte[]? pwd = null, CryptoOptions? options = null)
        {
            CryptoOptions? givenOptions = options;
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                // Ensure having options and work with cloned options
                options = options?.Clone() ?? DefaultOptions;
                options = EncryptionHelper.GetDefaultOptions(options);
                if (options.HeaderProcessed) throw new InvalidOperationException();
                options.Password = (byte[]?)pwd?.Clone();
                options.ValidateObject();
                /*List<ValidationResult> results = new();
                if (!options.TryValidateObject(results))
                    foreach (var result in results)
                        Console.WriteLine($"{result.MemberNames.FirstOrDefault()}: {result.ErrorMessage}");*/
                // Write unauthenticated options
                if (options.FlagsIncluded)
                    using (RentedArray<byte> buffer = new(len: 3))
                    {
                        EncodeFlags(options.Flags, buffer.Array);
                        cipherData.Write(buffer.Span);
                    }
                if (options.HeaderVersionIncluded) cipherData.Write((byte)options.HeaderVersion);
                if (options.SerializerVersionIncluded) cipherData.WriteSerializerVersion();
                // Finalize the password to use
                if (options.KeyExchangeDataIncluded) options.SetKeyExchangeData();
                if (options.Password == null) throw new ArgumentException("Password required", nameof(pwd));
                if (options.KdfAlgorithmIncluded)
                {
                    pwd = options.Password;
                    try
                    {
                        (options.Password, options.KdfSalt) = pwd.Stretch(KeySize, options: options);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                    if (options.UsingCounterKdf) HybridAlgorithmHelper.StretchPassword(options);
                }
                // Switch to a MAC stream
                MacStreams? macStream = null;
                if (options.MacIncluded)
                {
                    if (options.MacAlgorithmIncluded)
                    {
                        cipherData.WriteNumber(MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name).Value);
                        if (options.UsingCounterMac)
                            cipherData.WriteNumber(MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).Value);
                    }
                    options.MacPosition = cipherData.Position;
                    using (RentedArray<byte> buffer = options.UsingCounterMac
                        ? new(MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).MacLength)
                        : new(MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name).MacLength))
                        cipherData.Write(buffer.Span);
                    bool coverWhole = RequireMacAuthentication || options.ForceMacCoverWhole;
                    CryptoOptions macOptions = coverWhole ? options : options.Clone();
                    try
                    {
                        if (!coverWhole) macOptions.LeaveOpen = true;
                        macStream = MacHelper.GetMacStream(options.Password, cipherData, options: macOptions);
                    }
                    finally
                    {
                        if (!coverWhole) macOptions.Clear();
                    }
                    cipherData = macStream.Stream;
                }
                else if (RequireMacAuthentication)
                {
                    throw new InvalidOperationException("This algorithm requires a MAC to be included in the cipher header");
                }
                // Write authenticated options
                if (options.KeyExchangeDataIncluded)
                {
                    if (options.KeyExchangeData == null) throw new InvalidOperationException("Missing key exchange data");
                    cipherData.WriteSerialized(options.KeyExchangeData);
                }
                if (options.KdfAlgorithmIncluded)
                {
                    cipherData.WriteNumber(KdfHelper.GetAlgorithm(options.KdfAlgorithm ??= KdfHelper.DefaultAlgorithm.Name).Value);
                    cipherData.WriteNumber(options.KdfIterations);
                    cipherData.WriteBytes(options.KdfSalt);
                    cipherData.WriteStringNullable(options.KdfOptions);
                    if (options.UsingCounterKdf)
                    {
                        cipherData.WriteNumber(KdfHelper.GetAlgorithm(options.CounterKdfAlgorithm ??= HybridAlgorithmHelper.KdfAlgorithm?.Name ?? KdfHelper.DefaultAlgorithm.Name).Value);
                        cipherData.WriteNumber(options.CounterKdfIterations);
                        cipherData.WriteBytes(options.CounterKdfSalt);
                        cipherData.WriteStringNullable(options.CounterKdfOptions);
                    }
                }
                if (options.PayloadData != null) cipherData.WriteBytes(options.PayloadData);
                if (options.TimeIncluded) cipherData.WriteNumber((options.Time ??= DateTime.UtcNow).Ticks);
                options.HeaderProcessed = true;
                return (options, macStream);
            }
            catch (CryptographicException)
            {
                if (options != givenOptions) options?.Clear();
                throw;
            }
            catch (Exception ex)
            {
                if (options != givenOptions) options?.Clear();
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Write the options
        /// </summary>
        /// <param name="rawData">Raw data</param>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Written options and used MAC stream</returns>
        public virtual async Task<(CryptoOptions Options, MacStreams? MacStream)> WriteOptionsAsync(
            Stream rawData,
            Stream cipherData,
            byte[]? pwd = null,
            CryptoOptions? options = null,
            CancellationToken cancellationToken = default
            )
        {
            CryptoOptions? givenOptions = options;
            try
            {
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                // Ensure having options and work with cloned options
                options = options?.Clone() ?? DefaultOptions;
                options = EncryptionHelper.GetDefaultOptions(options);
                if (options.HeaderProcessed) throw new InvalidOperationException();
                options.Password = (byte[]?)pwd?.Clone();
                options.ValidateObject();
                // Write unauthenticated options
                MacStreams? macStream = null;
                if (options.FlagsIncluded)
                    using (RentedArray<byte> buffer = new(len: 3))
                    {
                        EncodeFlags(options.Flags, buffer.Array);
                        await cipherData.WriteAsync(buffer.Memory, cancellationToken).DynamicContext();
                    }
                if (options.HeaderVersionIncluded) await cipherData.WriteAsync((byte)options.HeaderVersion, cancellationToken).DynamicContext();
                if (options.SerializerVersionIncluded) await cipherData.WriteSerializerVersionAsync(cancellationToken).DynamicContext();
                // Finalize the password to use
                if (options.KeyExchangeDataIncluded) options.SetKeyExchangeData();
                if (options.Password == null) throw new ArgumentException("Password required", nameof(pwd));
                if (options.KdfAlgorithmIncluded)
                {
                    pwd = options.Password;
                    try
                    {
                        (options.Password, options.KdfSalt) = pwd.Stretch(KeySize, options: options);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                    if (options.UsingCounterKdf) HybridAlgorithmHelper.StretchPassword(options);
                }
                // Switch to a MAC stream
                if (options.MacIncluded)
                {
                    if (options.MacAlgorithmIncluded)
                    {
                        await cipherData.WriteNumberAsync(MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name).Value, cancellationToken).DynamicContext();
                        if (options.UsingCounterMac)
                            await cipherData.WriteNumberAsync(
                                MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).Value,
                                cancellationToken
                                ).DynamicContext();
                    }
                    options.MacPosition = cipherData.Position;
                    bool coverWhole = RequireMacAuthentication || options.ForceMacCoverWhole;
                    using (RentedArray<byte> buffer = options.UsingCounterMac
                        ? new(MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).MacLength)
                        : new(MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name).MacLength))
                        await cipherData.WriteAsync(buffer.Memory, cancellationToken).DynamicContext();
                    CryptoOptions macOptions = coverWhole ? options : options.Clone();
                    try
                    {
                        if (!coverWhole) macOptions.LeaveOpen = true;
                        macStream = MacHelper.GetMacStream(options.Password ?? throw new ArgumentException("Password required", nameof(pwd)), cipherData, options: macOptions);
                    }
                    finally
                    {
                        if (!coverWhole) macOptions.Clear();
                    }
                    cipherData = macStream.Stream;
                }
                else if (RequireMacAuthentication)
                {
                    throw new InvalidOperationException("This algorithm requires a MAC to be included in the cipher header");
                }
                // Write authenticated options
                if (options.KeyExchangeDataIncluded)
                {
                    if (options.KeyExchangeData == null) throw new InvalidOperationException("Missing key exchange data");
                    await cipherData.WriteSerializedAsync(options.KeyExchangeData, cancellationToken).DynamicContext();
                }
                if (options.KdfAlgorithmIncluded)
                {
                    await cipherData.WriteNumberAsync(KdfHelper.GetAlgorithm(options.KdfAlgorithm ??= KdfHelper.DefaultAlgorithm.Name).Value, cancellationToken).DynamicContext();
                    await cipherData.WriteNumberAsync(options.KdfIterations, cancellationToken).DynamicContext();
                    await cipherData.WriteBytesAsync(options.KdfSalt, cancellationToken).DynamicContext();
                    await cipherData.WriteStringNullableAsync(options.KdfOptions, cancellationToken).DynamicContext();
                    if (options.UsingCounterKdf)
                    {
                        await cipherData.WriteNumberAsync(
                            KdfHelper.GetAlgorithm(options.CounterKdfAlgorithm ??= HybridAlgorithmHelper.KdfAlgorithm?.Name ?? KdfHelper.DefaultAlgorithm.Name).Value, cancellationToken
                            ).DynamicContext();
                        await cipherData.WriteNumberAsync(options.CounterKdfIterations, cancellationToken).DynamicContext();
                        await cipherData.WriteBytesAsync(options.CounterKdfSalt, cancellationToken).DynamicContext();
                        await cipherData.WriteStringNullableAsync(options.CounterKdfOptions, cancellationToken).DynamicContext();
                    }
                }
                if (options.PayloadData != null) await cipherData.WriteBytesAsync(options.PayloadData, cancellationToken).DynamicContext();
                if (options.TimeIncluded) await cipherData.WriteNumberAsync((options.Time ??= DateTime.UtcNow).Ticks, cancellationToken).DynamicContext();
                options.HeaderProcessed = true;
                return (options, macStream);
            }
            catch (CryptographicException)
            {
                if (options != givenOptions) options?.Clear();
                throw;
            }
            catch (Exception ex)
            {
                if (options != givenOptions) options?.Clear();
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Read the options
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <returns>Red options</returns>
        public virtual CryptoOptions ReadOptions(Stream cipherData, Stream rawData, byte[]? pwd = null, CryptoOptions? options = null)
        {
            CryptoOptions? givenOptions = options;
            try
            {
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
                // Ensure having options and work with cloned options
                options = options?.Clone() ?? DefaultOptions;
                options = EncryptionHelper.GetDefaultOptions(options);
                if (options.HeaderProcessed) return options;
                options.ValidateObject();
                // Prepare the password
                if (pwd != null)
                {
                    options.Password ??= (byte[]?)pwd?.Clone();
                }
                else
                {
                    options.KeyExchangeDataIncluded = true;
                    options.RequireKeyExchangeData = true;
                }
                // Read unauthenticated options
                if (options.FlagsIncluded)
                    using (RentedArray<byte> buffer = new(len: 3))
                    {
                        if (cipherData.Read(buffer.Span) != buffer.Length) throw new IOException("Failed to read the crypto flags");
                        options.Flags = DecodeFlags(buffer.Array);
                    }
                options.ValidateRequirements();
                if (options.HeaderVersionIncluded)
                {
                    options.HeaderVersion = cipherData.ReadOneByte();
                    if (options.HeaderVersion < 1 || options.HeaderVersion > CryptoOptions.HEADER_VERSION) throw new InvalidDataException($"Invalid header version {options.HeaderVersion}");
                }
                int? serializerVersion = options.SerializerVersionIncluded ? options.SerializerVersion = cipherData.ReadSerializerVersion() : null;
                // Read the MAC
                MacAlgorithmBase? mac = null;
                if (options.MacIncluded)
                {
                    if (options.MacAlgorithmIncluded)
                    {
                        options.MacAlgorithm = options.MacAlgorithmIncluded
                            ? MacHelper.GetAlgorithm(cipherData.ReadNumber<int>(serializerVersion)).Name
                            : options.MacAlgorithm ?? MacHelper.GetDefaultOptions(options).MacAlgorithm;
                        if (options.UsingCounterMac)
                            options.CounterMacAlgorithm = MacHelper.GetAlgorithm(cipherData.ReadNumber<int>(serializerVersion)).Name;
                    }
                    options.MacPosition = cipherData.Position;
                    mac = MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name);
                    int len = options.UsingCounterMac
                        ? MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).MacLength
                        : mac.MacLength;
                    options.Mac = new byte[len];
                    if (cipherData.Read(options.Mac) != len) throw new IOException("Failed to read the MAC");
                }
                // Read authenticated options
                if (options.KeyExchangeDataIncluded)
                {
                    options.KeyExchangeData = cipherData.ReadSerialized<KeyExchangeDataContainer>(serializerVersion);
                    options.Password = options.DeriveExchangedKey();
                }
                if (options.Password == null) throw new ArgumentException("Password required", nameof(pwd));
                if (options.KdfAlgorithmIncluded)
                {
                    options.KdfAlgorithm = KdfHelper.GetAlgorithm(cipherData.ReadNumber<int>(serializerVersion)).Name;
                    options.KdfIterations = cipherData.ReadNumber<int>(serializerVersion);
                    options.KdfSalt = cipherData.ReadBytes(serializerVersion, minLen: 1, maxLen: byte.MaxValue).Value;
                    options.KdfOptions = cipherData.ReadStringNullable(serializerVersion, minLen: 0, maxLen: byte.MaxValue);
                    pwd = options.Password ?? throw new ArgumentException("No password yet", nameof(pwd));
                    try
                    {
                        (options.Password, _) = pwd!.Stretch(KeySize, options.KdfSalt, options);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                    if (options.UsingCounterKdf)
                        try
                        {
                            pwd = options.Password;
                            options.CounterKdfAlgorithm = KdfHelper.GetAlgorithm(cipherData.ReadNumber<int>(serializerVersion)).Name;
                            options.CounterKdfIterations = cipherData.ReadNumber<int>(serializerVersion);
                            options.CounterKdfSalt = cipherData.ReadBytes(serializerVersion, minLen: 1, maxLen: byte.MaxValue).Value;
                            options.CounterKdfOptions = cipherData.ReadStringNullable(serializerVersion, minLen: 0, maxLen: byte.MaxValue);
                            HybridAlgorithmHelper.StretchPassword(options);
                        }
                        finally
                        {
                            pwd.Clear();
                        }
                }
                if (options.PayloadIncluded) options.PayloadData = cipherData.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
                if (options.TimeIncluded)
                {
                    options.Time = new DateTime(cipherData.ReadNumber<long>(serializerVersion));
                    if (options.MaximumTimeOffset != null) options.Time = options.Time.Value.ApplyOffset(options.MaximumTimeOffset.Value, DateTime.UtcNow);
                    if (options.MaximumAge != null && DateTime.UtcNow - options.Time.Value > options.MaximumAge) throw new InvalidOperationException("Maximum age exceeded");
                }
                options.ValidateRequirements();
                // Authenticate the options and the cipher data using the MAC
                if (options.MacIncluded && (RequireMacAuthentication || options.ForceMacCoverWhole))
                {
                    long pos = cipherData.Position;
                    cipherData.Position = options.MacPosition + options.Mac!.Length;
                    CryptoOptions macOptions = mac!.DefaultOptions;
                    macOptions.LeaveOpen = true;
                    using MacStreams macStream = mac.GetMacStream(options.Password, options: macOptions);
                    cipherData.CopyTo(macStream.Stream);
                    macStream.Stream.Dispose();
                    byte[] redMac = options.Mac;
                    options.Mac = macStream.Transform.Hash ?? throw new InvalidProgramException();
                    if (options.UsingCounterMac) HybridAlgorithmHelper.ComputeMac(options);
                    if (!options.Mac!.AsSpan().SlowCompare(redMac)) throw new InvalidDataException("MAC mismatch");
                    cipherData.Position = pos;
                }
                options.HeaderProcessed = true;
                return options;
            }
            catch (CryptographicException)
            {
                if (options != givenOptions) options?.Clear();
                throw;
            }
            catch (Exception ex)
            {
                if (options != givenOptions) options?.Clear();
                throw CryptographicException.From(ex);
            }
        }

        /// <summary>
        /// Read the options
        /// </summary>
        /// <param name="cipherData">Cipher data</param>
        /// <param name="rawData">Raw data</param>
        /// <param name="pwd">Password</param>
        /// <param name="options">Options</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Red options and serializer version number</returns>
        public virtual async Task<CryptoOptions> ReadOptionsAsync(
            Stream cipherData,
            Stream rawData,
            byte[]? pwd = null,
            CryptoOptions? options = null,
            CancellationToken cancellationToken = default
            )
        {
            CryptoOptions? givenOptions = options;
            try
            {
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
                // Ensure having options and work with cloned options
                options = options?.Clone() ?? DefaultOptions;
                options = EncryptionHelper.GetDefaultOptions(options);
                if (options.HeaderProcessed) return options;
                options.ValidateObject();
                // Prepare the password
                if (pwd != null)
                {
                    options.Password ??= (byte[]?)pwd?.Clone();
                }
                else
                {
                    options.KeyExchangeDataIncluded = true;
                    options.RequireKeyExchangeData = true;
                }
                // Read unauthenticated options
                if (options.FlagsIncluded)
                    using (RentedArray<byte> buffer = new(len: 3))
                    {
                        if (await cipherData.ReadAsync(buffer.Memory, cancellationToken).DynamicContext() != buffer.Length) throw new IOException("Failed to read the crypto flags");
                        options.Flags = DecodeFlags(buffer.Array);
                    }
                options.ValidateRequirements();
                if (options.HeaderVersionIncluded)
                {
                    options.HeaderVersion = await cipherData.ReadOneByteAsync(cancellationToken: cancellationToken).DynamicContext();
                    if (options.HeaderVersion < 1 || options.HeaderVersion > CryptoOptions.HEADER_VERSION) throw new InvalidDataException($"Invalid header version {options.HeaderVersion}");
                }
                int? serializerVersion = options.SerializerVersionIncluded ? options.SerializerVersion = await cipherData.ReadSerializerVersionAsync(cancellationToken).DynamicContext() : null;
                // Read the MAC
                MacAlgorithmBase? mac = null;
                if (options.MacIncluded)
                {
                    if (options.MacAlgorithmIncluded)
                    {
                        options.MacAlgorithm = options.MacAlgorithmIncluded
                            ? MacHelper.GetAlgorithm(await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext()).Name
                            : options.MacAlgorithm ?? MacHelper.DefaultAlgorithm.Name;
                        if (options.UsingCounterMac)
                            options.CounterMacAlgorithm = MacHelper.GetAlgorithm(
                                await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext()
                                ).Name;
                    }
                    options.MacPosition = cipherData.Position;
                    mac = MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name);
                    int len = options.UsingCounterMac
                        ? MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).MacLength
                        : mac.MacLength;
                    options.Mac = new byte[len];
                    if (await cipherData.ReadAsync(options.Mac, cancellationToken).DynamicContext() != len) throw new IOException("Failed to read the MAC");
                }
                // Read authenticated options
                if (options.KeyExchangeDataIncluded)
                {
                    options.KeyExchangeData = await cipherData.ReadSerializedAsync<KeyExchangeDataContainer>(serializerVersion, cancellationToken: cancellationToken).DynamicContext();
                    options.Password = options.DeriveExchangedKey();
                }
                if (options.Password == null) throw new ArgumentException("Password required", nameof(pwd));
                if (options.KdfAlgorithmIncluded)
                {
                    options.KdfAlgorithm = KdfHelper.GetAlgorithm(await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext()).Name;
                    options.KdfIterations = await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext();
                    options.KdfSalt = (await cipherData.ReadBytesAsync(serializerVersion, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
                    options.KdfOptions = await cipherData.ReadStringNullableAsync(serializerVersion, minLen: 0, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
                    pwd = options.Password ?? throw new ArgumentException("No password yet", nameof(pwd));
                    try
                    {
                        (options.Password, _) = pwd!.Stretch(KeySize, options.KdfSalt, options);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                    if (options.UsingCounterKdf)
                    {
                        options.CounterKdfAlgorithm = KdfHelper.GetAlgorithm(
                            await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext()
                            ).Name;
                        options.CounterKdfIterations = await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext();
                        options.CounterKdfSalt = (await cipherData.ReadBytesAsync(serializerVersion, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext())
                            .Value;
                        options.CounterKdfOptions = await cipherData.ReadStringNullableAsync(serializerVersion, minLen: 0, maxLen: byte.MaxValue, cancellationToken: cancellationToken)
                            .DynamicContext();
                        HybridAlgorithmHelper.StretchPassword(options);
                    }
                }
                if (options.PayloadIncluded)
                    options.PayloadData = (await cipherData.ReadBytesAsync(serializerVersion, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
                if (options.TimeIncluded)
                {
                    options.Time = new DateTime(await cipherData.ReadNumberAsync<long>(serializerVersion, cancellationToken: cancellationToken).DynamicContext());
                    if (options.MaximumTimeOffset != null) options.Time = options.Time.Value.ApplyOffset(options.MaximumTimeOffset.Value, DateTime.UtcNow);
                    if (options.MaximumAge != null && DateTime.UtcNow - options.Time.Value > options.MaximumAge) throw new InvalidOperationException("Maximum age exceeded");
                }
                options.ValidateRequirements();
                // Authenticate the options and the cipher data using the MAC
                if (options.MacIncluded && (RequireMacAuthentication || options.ForceMacCoverWhole))
                {
                    long pos = cipherData.Position;
                    cipherData.Position = options.MacPosition + options.Mac!.Length;
                    CryptoOptions macOptions = mac!.DefaultOptions;
                    macOptions.LeaveOpen = true;
                    using MacStreams macStream = mac.GetMacStream(options.Password, options: macOptions);
                    await cipherData.CopyToAsync(macStream.Stream, cancellationToken).DynamicContext();
                    macStream.Stream.Dispose();
                    byte[] redMac = options.Mac;
                    options.Mac = macStream.Transform.Hash ?? throw new InvalidProgramException();
                    if (options.UsingCounterMac) HybridAlgorithmHelper.ComputeMac(options);
                    if (!options.Mac!.AsSpan().SlowCompare(redMac)) throw new InvalidDataException("MAC mismatch");
                    cipherData.Position = pos;
                }
                options.HeaderProcessed = true;
                return options;
            }
            catch (CryptographicException)
            {
                if (options != givenOptions) options?.Clear();
                throw;
            }
            catch (Exception ex)
            {
                if (options != givenOptions) options?.Clear();
                throw CryptographicException.From(ex);
            }
        }
    }
}
