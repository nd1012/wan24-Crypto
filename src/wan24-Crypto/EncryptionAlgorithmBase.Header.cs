using System.Buffers;
using System.ComponentModel.DataAnnotations;
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
            EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
            CryptoOptions? givenOptions = options;
            try
            {
                // Ensure having options and work with cloned options
                options = options?.Clone() ?? DefaultOptions;
                givenOptions?.Clear();
                if (options.HeaderProcessed) throw new InvalidOperationException();
                options.Password ??= (byte[]?)pwd?.Clone();
                options.ValidateObject();
                /*List<ValidationResult> results = new();
                if (!options.TryValidateObject(results))
                    foreach (var result in results)
                        Console.WriteLine($"{result.MemberNames.FirstOrDefault()}: {result.ErrorMessage}");*/
                // Write unauthenticated options
                MacStreams? macStream = null;
                if (options.FlagsIncluded)
                {
                    int flags = (int)options.Flags;
                    using (RentedArray<byte> buffer = new(len: 3))
                    {
                        buffer[0] = (byte)flags;
                        buffer[1] = (byte)(flags >> 8);
                        buffer[2] = (byte)(flags >> 16);
                        cipherData.Write(buffer.Span);
                    }
                }
                if (options.HeaderVersionIncluded) cipherData.Write((byte)options.HeaderVersion);
                if (options.SerializerVersionIncluded) cipherData.Write((byte)StreamSerializer.VERSION);
                // Finalize the password to use
                if (options.KeyExchangeDataIncluded) options.Password = options.SetKeyExchangeData();
                if (options.KdfAlgorithmIncluded)
                {
                    pwd = options.Password ?? throw new CryptographicException("No password yet");
                    try
                    {
                        (options.Password, options.KdfSalt) = pwd.Stretch(KeySize, options: options);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                    if (options.UsingCounterKdf)
                        try
                        {
                            pwd = options.Password;
                            options.Password = HybridAlgorithmHelper.StretchPassword(options.Password, options);
                        }
                        finally
                        {
                            pwd.Clear();
                        }
                }
                // Switch to a MAC stream
                if (options.MacIncluded)
                {
                    if (options.MacAlgorithmIncluded) cipherData.WriteNumber(MacHelper.GetAlgorithmValue(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name));
                    if (options.UsingCounterMac && options.CounterMacAlgorithmIncluded)
                        cipherData.WriteNumber(MacHelper.GetAlgorithmValue(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name));
                    options.MacPosition = cipherData.Position;
                    using (RentedArray<byte> buffer = options.UsingCounterMac
                        ? new(MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).MacLength)
                        : new(MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name).MacLength))
                        cipherData.Write(buffer.Span);
                    CryptoOptions macOptions = RequireMacAuthentication || options.ForceMacCoverWhole ? options : options.Clone();
                    try
                    {
                        if (!RequireMacAuthentication && !options.ForceMacCoverWhole) macOptions.LeaveOpen = true;
                        macStream = MacHelper.GetMacStream(options.Password ?? throw new CryptographicException("No password yet"), cipherData, options: macOptions);
                    }
                    finally
                    {
                        if (!RequireMacAuthentication && !options.ForceMacCoverWhole) macOptions.Clear();
                    }
                    cipherData = macStream.Stream;
                }
                // Write authenticated options
                if (options.KeyExchangeDataIncluded)
                {
                    if (options.AsymmetricAlgorithmIncluded)
                        cipherData.WriteNumber(AsymmetricHelper.GetAlgorithmValue(options.AsymmetricAlgorithm ??= AsymmetricHelper.DefaultKeyExchangeAlgorithm.Name));
                    if (options.UsingAsymmetricCounterAlgorithm && options.AsymmetricCounterAlgorithmIncluded)
                        cipherData.WriteNumber(
                            AsymmetricHelper.GetAlgorithmValue(
                                options.AsymmetricCounterAlgorithm ??= HybridAlgorithmHelper.KeyExchangeAlgorithm?.Name ?? AsymmetricHelper.DefaultKeyExchangeAlgorithm.Name
                                )
                            );
                    cipherData.WriteBytes(options.KeyExchangeData);
                }
                if (options.KdfAlgorithmIncluded)
                {
                    cipherData.WriteNumber(KdfHelper.GetAlgorithmValue(options.KdfAlgorithm ??= KdfHelper.DefaultAlgorithm.Name));
                    cipherData.WriteNumber(options.KdfIterations);
                    cipherData.WriteBytes(options.KdfSalt);
                    if (options.UsingCounterKdf && options.CounterKdfAlgorithmIncluded)
                    {
                        cipherData.WriteNumber(KdfHelper.GetAlgorithmValue(options.CounterKdfAlgorithm ??= HybridAlgorithmHelper.KdfAlgorithm?.Name ?? KdfHelper.DefaultAlgorithm.Name));
                        cipherData.WriteNumber(options.CounterKdfIterations);
                        cipherData.WriteBytes(options.CounterKdfSalt);
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
                throw new CryptographicException(ex.Message, ex);
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
            EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
            CryptoOptions? givenOptions = options;
            try
            {
                // Ensure having options and work with cloned options
                options = options?.Clone() ?? DefaultOptions;
                givenOptions?.Clear();
                if (options.HeaderProcessed) throw new InvalidOperationException();
                options.Password ??= (byte[]?)pwd?.Clone();
                options.ValidateObject();
                // Write unauthenticated options
                MacStreams? macStream = null;
                if (options.FlagsIncluded)
                {
                    int flags = (int)options.Flags;
                    using (RentedArray<byte> buffer = new(len: 3))
                    {
                        buffer[0] = (byte)flags;
                        buffer[1] = (byte)(flags >> 8);
                        buffer[2] = (byte)(flags >> 16);
                        await cipherData.WriteAsync(buffer.Memory, cancellationToken).DynamicContext();
                    }
                }
                if (options.HeaderVersionIncluded) await cipherData.WriteAsync((byte)options.HeaderVersion, cancellationToken).DynamicContext();
                if (options.SerializerVersionIncluded) await cipherData.WriteAsync((byte)StreamSerializer.VERSION, cancellationToken).DynamicContext();
                // Finalize the password to use
                if (options.KeyExchangeDataIncluded) options.Password = options.SetKeyExchangeData();
                if (options.KdfAlgorithmIncluded)
                {
                    pwd = options.Password ?? throw new CryptographicException("No password yet");
                    try
                    {
                        (options.Password, options.KdfSalt) = pwd.Stretch(KeySize, options: options);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                    if (options.UsingCounterKdf)
                        try
                        {
                            pwd = options.Password;
                            options.Password = HybridAlgorithmHelper.StretchPassword(options.Password, options);
                        }
                        finally
                        {
                            pwd.Clear();
                        }
                }
                // Switch to a MAC stream
                if (options.MacIncluded)
                {
                    if (options.MacAlgorithmIncluded)
                        await cipherData.WriteNumberAsync(MacHelper.GetAlgorithmValue(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name), cancellationToken).DynamicContext();
                    if (options.UsingCounterMac && options.CounterMacAlgorithmIncluded)
                        await cipherData.WriteNumberAsync(
                            MacHelper.GetAlgorithmValue(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name),
                            cancellationToken
                            ).DynamicContext();
                    options.MacPosition = cipherData.Position;
                    using (RentedArray<byte> buffer = options.UsingCounterMac
                        ? new(MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).MacLength)
                        : new(MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name).MacLength))
                        await cipherData.WriteAsync(buffer.Memory, cancellationToken).DynamicContext();
                    CryptoOptions macOptions = RequireMacAuthentication || options.ForceMacCoverWhole ? options : options.Clone();
                    try
                    {
                        if (!RequireMacAuthentication && !options.ForceMacCoverWhole) macOptions.LeaveOpen = true;
                        macStream = MacHelper.GetMacStream(options.Password ?? throw new CryptographicException("No password yet"), cipherData, options: macOptions);
                    }
                    finally
                    {
                        if (!RequireMacAuthentication && !options.ForceMacCoverWhole) macOptions.Clear();
                    }
                    cipherData = macStream.Stream;
                }
                // Write authenticated options
                if (options.KeyExchangeDataIncluded)
                {
                    if (options.AsymmetricAlgorithmIncluded)
                        await cipherData.WriteNumberAsync(AsymmetricHelper.GetAlgorithmValue(options.AsymmetricAlgorithm ??= AsymmetricHelper.DefaultKeyExchangeAlgorithm.Name), cancellationToken)
                            .DynamicContext();
                    if (options.UsingAsymmetricCounterAlgorithm && options.AsymmetricCounterAlgorithmIncluded)
                        await cipherData.WriteNumberAsync(
                            AsymmetricHelper.GetAlgorithmValue(
                                options.AsymmetricCounterAlgorithm ??= HybridAlgorithmHelper.KeyExchangeAlgorithm?.Name ?? AsymmetricHelper.DefaultKeyExchangeAlgorithm.Name
                                ),
                            cancellationToken
                            )
                            .DynamicContext();
                    await cipherData.WriteBytesAsync(options.KeyExchangeData, cancellationToken).DynamicContext();
                }
                if (options.KdfAlgorithmIncluded)
                {
                    await cipherData.WriteNumberAsync(KdfHelper.GetAlgorithmValue(options.KdfAlgorithm ??= KdfHelper.DefaultAlgorithm.Name), cancellationToken).DynamicContext();
                    await cipherData.WriteNumberAsync(options.KdfIterations, cancellationToken).DynamicContext();
                    await cipherData.WriteBytesAsync(options.KdfSalt, cancellationToken).DynamicContext();
                    if (options.UsingCounterKdf && options.CounterKdfAlgorithmIncluded)
                    {
                        await cipherData.WriteNumberAsync(
                            KdfHelper.GetAlgorithmValue(options.CounterKdfAlgorithm ??= HybridAlgorithmHelper.KdfAlgorithm?.Name ?? KdfHelper.DefaultAlgorithm.Name), cancellationToken
                            ).DynamicContext();
                        await cipherData.WriteNumberAsync(options.CounterKdfIterations, cancellationToken).DynamicContext();
                        await cipherData.WriteBytesAsync(options.CounterKdfSalt, cancellationToken).DynamicContext();
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
                throw new CryptographicException(ex.Message, ex);
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
            /*
             * Stream data structure:
             * 
             * - 3 byte flags
             * - 1 byte header version
             * - 1 byte serializer version
             * - MAC algorithm
             * - MAC (fixed length, depending on the algorithm)
             * - Encryption algorithm
             * - Asymmetric algorithm
             * - Asymmetric counter algorithm
             * - Key exchange data
             * - KDF algorithm
             * - KDF interations
             * - KDF salt
             * - Counter KDF algorithm
             * - Counter KDF interations
             * - Counter KDF salt
             * - Payload
             * - Timestamp
             * - IV bytes
             * - Cipher data
             *      - Compression options
             *      - Compressed data
             */
            EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
            CryptoOptions? givenOptions = options;
            try
            {
                // Ensure having options and work with cloned options
                options = options?.Clone() ?? DefaultOptions;
                givenOptions?.Clear();
                if (options.HeaderProcessed) return options;
                options.ValidateObject();
                // Prepare the password
                if (pwd != null)
                {
                    options.Password ??= (byte[]?)pwd?.Clone();
                }
                else
                {
                    options.RequireKeyExchangeData = true;
                }
                // Read unauthenticated options
                if (options.FlagsIncluded)
                    using (RentedArray<byte> buffer = new(len: 3))
                    {
                        if (cipherData.Read(buffer.Span) != buffer.Length) throw new IOException("Failed to read the crypto flags");
                        int flags = buffer[0];
                        flags |= buffer[1] << 8;
                        flags |= buffer[2] << 16;
                        options.Flags = (CryptoFlags)flags;
                    }
                options.ValidateRequirements();
                if (options.HeaderVersionIncluded)
                {
                    options.HeaderVersion = cipherData.ReadOneByte();
                    if (options.HeaderVersion < 1 || options.HeaderVersion > CryptoOptions.HEADER_VERSION) throw new InvalidDataException($"Invalid header version {options.HeaderVersion}");
                }
                int? serializerVersion = null;
                if (options.SerializerVersionIncluded)
                {
                    serializerVersion = cipherData.ReadOneByte();
                    if (serializerVersion < 1 || serializerVersion > StreamSerializer.VERSION) throw new InvalidDataException($"Unsupported serializer version {serializerVersion}");
                    options.SerializerVersion = serializerVersion;
                }
                // Read the MAC
                MacAlgorithmBase? mac = null;
                if (options.MacIncluded)
                {
                    options.MacAlgorithm = options.MacAlgorithmIncluded
                        ? MacHelper.GetAlgorithmName(cipherData.ReadNumber<int>(serializerVersion))
                        : MacHelper.DefaultAlgorithm.Name;
                    if (options.UsingCounterMac && options.CounterMacAlgorithmIncluded) options.CounterMacAlgorithm = MacHelper.GetAlgorithmName(cipherData.ReadNumber<int>(serializerVersion));
                    options.MacPosition = cipherData.Position;
                    mac = MacHelper.GetAlgorithm(
                        options.UsingCounterMac
                            ? options.CounterMacAlgorithm ?? HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name
                            : options.MacAlgorithm
                        );
                    options.Mac = new byte[mac.MacLength];
                    if (cipherData.Read(options.Mac) != mac.MacLength) throw new IOException("Failed to read the MAC");
                }
                // Read authenticated options
                if (options.KeyExchangeDataIncluded)
                {
                    if (options.AsymmetricAlgorithmIncluded) options.AsymmetricAlgorithm = AsymmetricHelper.GetAlgorithmName(cipherData.ReadNumber<int>(serializerVersion));
                    if (options.AsymmetricCounterAlgorithmIncluded) options.AsymmetricCounterAlgorithm = AsymmetricHelper.GetAlgorithmName(cipherData.ReadNumber<int>(serializerVersion));
                    options.KeyExchangeData = cipherData.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
                    options.Password = options.UsingAsymmetricCounterAlgorithm
                        ? HybridAlgorithmHelper.DeriveKey(options.KeyExchangeData, options)
                        : options.DeriveExchangedKey();
                }
                if (options.KdfAlgorithmIncluded)
                {
                    options.KdfAlgorithm = KdfHelper.GetAlgorithmName(cipherData.ReadNumber<int>(serializerVersion));
                    options.KdfIterations = cipherData.ReadNumber<int>(serializerVersion);
                    options.KdfSalt = cipherData.ReadBytes(serializerVersion, minLen: 0, maxLen: byte.MaxValue).Value;
                    pwd = options.Password ?? throw new CryptographicException("No password yet");
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
                            options.CounterKdfAlgorithm = KdfHelper.GetAlgorithmName(cipherData.ReadNumber<int>(serializerVersion));
                            options.CounterKdfIterations = cipherData.ReadNumber<int>(serializerVersion);
                            options.CounterKdfSalt = cipherData.ReadBytes(serializerVersion, minLen: 0, maxLen: byte.MaxValue).Value;
                            options.Password = HybridAlgorithmHelper.StretchPassword(pwd, options);
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
                    if (options.MaximumTimeOffset != null)
                    {
                        if (options.Time >= DateTime.UtcNow)
                        {
                            options.Time = options.Time.Value - options.MaximumTimeOffset.Value;
                        }
                        else
                        {
                            options.Time = options.Time.Value + options.MaximumTimeOffset.Value;
                        }
                        if (options.Time >= DateTime.UtcNow) options.Time = DateTime.UtcNow;
                    }
                    if (options.MaximumAge != null && DateTime.UtcNow - options.Time.Value > options.MaximumAge) throw new CryptographicException("Maximum age exceeded");
                }
                // Authenticate the options and the cipher data using the MAC
                if (options.MacIncluded && (RequireMacAuthentication || options.ForceMacCoverWhole))
                {
                    long pos = cipherData.Position;
                    cipherData.Position = options.MacPosition + options.Mac!.Length;
                    CryptoOptions macOptions = mac!.DefaultOptions;
                    macOptions.LeaveOpen = true;
                    using MacStreams macStream = mac.GetMacStream(options.Password ?? throw new CryptographicException("No password yet"), options: macOptions);
                    cipherData.CopyTo(macStream.Stream);
                    macStream.Stream.FlushFinalBlock();
                    byte[] redMac = macStream.Transform.Hash ?? throw new InvalidProgramException();
                    if (options.UsingCounterMac) redMac = HybridAlgorithmHelper.ComputeMac(redMac, options);
                    if (!options.Mac!.AsSpan().SlowCompare(redMac)) throw new CryptographicException("MAC mismatch");
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
                throw new CryptographicException(ex.Message, ex);
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
            EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
            CryptoOptions? givenOptions = options;
            try
            {
                // Ensure having options and work with cloned options
                options = options?.Clone() ?? DefaultOptions;
                givenOptions?.Clear();
                if (options.HeaderProcessed) return options;
                options.ValidateObject();
                // Prepare the password
                if (pwd != null)
                {
                    options.Password ??= (byte[]?)pwd?.Clone();
                }
                else
                {
                    options.RequireKeyExchangeData = true;
                }
                // Read unauthenticated options
                if (options.FlagsIncluded)
                    using (RentedArray<byte> buffer = new(len: 3))
                    {
                        if (await cipherData.ReadAsync(buffer.Memory, cancellationToken).DynamicContext() != buffer.Length) throw new IOException("Failed to read the crypto flags");
                        int flags = buffer[0];
                        flags |= buffer[1] << 8;
                        flags |= buffer[2] << 16;
                        options.Flags = (CryptoFlags)flags;
                    }
                options.ValidateRequirements();
                if (options.HeaderVersionIncluded)
                {
                    options.HeaderVersion = await cipherData.ReadOneByteAsync(cancellationToken: cancellationToken).DynamicContext();
                    if (options.HeaderVersion < 1 || options.HeaderVersion > CryptoOptions.HEADER_VERSION) throw new InvalidDataException($"Invalid header version {options.HeaderVersion}");
                }
                int? serializerVersion = null;
                if (options.SerializerVersionIncluded)
                {
                    serializerVersion = await cipherData.ReadOneByteAsync(cancellationToken: cancellationToken).DynamicContext();
                    if (serializerVersion < 1 || serializerVersion > StreamSerializer.VERSION) throw new InvalidDataException($"Unsupported serializer version {serializerVersion}");
                }
                // Read the MAC
                MacAlgorithmBase? mac = null;
                if (options.MacIncluded)
                {
                    options.MacAlgorithm = options.MacAlgorithmIncluded
                        ? MacHelper.GetAlgorithmName(await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext())
                        : MacHelper.DefaultAlgorithm.Name;
                    if (options.UsingCounterMac && options.CounterMacAlgorithmIncluded)
                        options.CounterMacAlgorithm = MacHelper.GetAlgorithmName(await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext());
                    options.MacPosition = cipherData.Position;
                    mac = MacHelper.GetAlgorithm(
                        options.UsingCounterMac
                            ? options.CounterMacAlgorithm ?? HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name
                            : options.MacAlgorithm
                            );
                    options.Mac = new byte[mac.MacLength];
                    if (await cipherData.ReadAsync(options.Mac, cancellationToken).DynamicContext() != mac.MacLength) throw new IOException("Failed to read the MAC");
                }
                // Read authenticated options
                if (options.KeyExchangeDataIncluded)
                {
                    if (options.AsymmetricAlgorithmIncluded)
                        options.AsymmetricAlgorithm = AsymmetricHelper.GetAlgorithmName(await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken)
                            .DynamicContext());
                    if (options.AsymmetricCounterAlgorithmIncluded)
                        options.AsymmetricCounterAlgorithm = AsymmetricHelper.GetAlgorithmName(await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken)
                            .DynamicContext());
                    options.KeyExchangeData = (await cipherData.ReadBytesAsync(serializerVersion, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
                    options.Password = options.UsingAsymmetricCounterAlgorithm
                        ? HybridAlgorithmHelper.DeriveKey(options.KeyExchangeData, options)
                        : options.DeriveExchangedKey();
                }
                if (options.KdfAlgorithmIncluded)
                {
                    options.KdfAlgorithm = KdfHelper.GetAlgorithmName(await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext());
                    options.KdfIterations = await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext();
                    options.KdfSalt = (await cipherData.ReadBytesAsync(serializerVersion, minLen: 0, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
                    pwd = options.Password ?? throw new CryptographicException("No password yet");
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
                            options.CounterKdfAlgorithm = KdfHelper.GetAlgorithmName(await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext());
                            options.CounterKdfIterations = await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext();
                            options.CounterKdfSalt = (await cipherData.ReadBytesAsync(serializerVersion, minLen: 0, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
                            options.Password = HybridAlgorithmHelper.StretchPassword(pwd, options);
                        }
                        finally
                        {
                            pwd.Clear();
                        }
                }
                if (options.PayloadIncluded)
                    options.PayloadData = (await cipherData.ReadBytesAsync(serializerVersion, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
                if (options.TimeIncluded)
                {
                    options.Time = new DateTime(await cipherData.ReadNumberAsync<long>(serializerVersion, cancellationToken: cancellationToken).DynamicContext());
                    if (options.MaximumTimeOffset != null)
                    {
                        options.Time = options.Time >= DateTime.UtcNow
                            ? options.Time.Value - options.MaximumTimeOffset.Value
                            : options.Time.Value + options.MaximumTimeOffset.Value;
                        if (options.Time >= DateTime.UtcNow) options.Time = DateTime.UtcNow;
                    }
                    if (options.MaximumAge != null && DateTime.UtcNow - options.Time.Value > options.MaximumAge) throw new CryptographicException("Maximum age exceeded");
                }
                // Authenticate the options and the cipher data using the MAC
                if (options.MacIncluded && (RequireMacAuthentication || options.ForceMacCoverWhole))
                {
                    long pos = cipherData.Position;
                    cipherData.Position = options.MacPosition + options.Mac!.Length;
                    CryptoOptions macOptions = mac!.DefaultOptions;
                    macOptions.LeaveOpen = true;
                    using MacStreams macStream = mac.GetMacStream(options.Password ?? throw new CryptographicException("No password yet"), options: macOptions);
                    await cipherData.CopyToAsync(macStream.Stream, cancellationToken).DynamicContext();
                    macStream.Stream.FlushFinalBlock();
                    byte[] redMac = macStream.Transform.Hash ?? throw new InvalidProgramException();
                    if (options.UsingCounterMac) redMac = HybridAlgorithmHelper.ComputeMac(redMac, options);
                    if (!options.Mac!.AsSpan().SlowCompare(redMac)) throw new CryptographicException("MAC mismatch");
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
                throw new CryptographicException(ex.Message, ex);
            }
        }
    }
}
