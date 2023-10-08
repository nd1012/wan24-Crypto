using System.Buffers;
using wan24.Core;
using wan24.ObjectValidation;
using wan24.StreamSerializerExtensions;

namespace wan24.Crypto
{
    // Header methods
    public partial record class EncryptionAlgorithmBase
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
                options?.Tracer?.WriteTrace($"Writing {GetType()} crypto header");
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                // Ensure having options and work with cloned options
                options = options?.GetCopy() ?? DefaultOptions;
                EncryptionHelper.GetDefaultOptions(options);
                if (options.HeaderProcessed) throw new InvalidOperationException();
                options.Password?.Clear();
                options.Password = pwd?.CloneArray();
                options.ValidateObject();
                /*List<ValidationResult> results = new();
                if (!options.TryValidateObject(results))
                    foreach (var result in results)
                        Console.WriteLine($"{result.MemberNames.FirstOrDefault()}: {result.ErrorMessage}");*/
                // Write unauthenticated options
                if (options.FlagsIncluded)
                    using (RentedArrayRefStruct<byte> buffer = new(len: 3))
                    {
                        options.Tracer?.WriteTrace($"Including crypto options flags {options.Flags}");
                        EncodeFlags(options.Flags, buffer.Span);
                        cipherData.Write(buffer.Span);
                    }
                if (options.HeaderVersionIncluded)
                {
                    options.Tracer?.WriteTrace($"Including crypto header version {options.HeaderVersion}");
                    cipherData.Write((byte)options.HeaderVersion);
                }
                if (options.SerializerVersionIncluded)
                {
                    options.Tracer?.WriteTrace($"Including serializer version {StreamSerializer.Version}");
                    cipherData.WriteSerializerVersion();
                }
                // Finalize the password to use
                if (options.KeyExchangeDataIncluded)
                {
                    options.Tracer?.WriteTrace("Generating key exchange data");
                    options.SetKeyExchangeData();
                }
                if (options.Password is null) throw new ArgumentException("Password required", nameof(pwd));
                if (options.KdfAlgorithmIncluded)
                {
                    options.Tracer?.WriteTrace($"Applying KDF {options.KdfAlgorithm}");
                    pwd = options.Password;
                    try
                    {
                        (options.Password, options.KdfSalt) = pwd.Stretch(KeySize, options: options);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                    if (options.UsingCounterKdf)
                    {
                        options.Tracer?.WriteTrace($"Applying counter KDF {options.CounterKdfAlgorithm}");
                        HybridAlgorithmHelper.StretchPassword(options);
                    }
                }
                if (!IsKeyLengthValid(options.Password.Length))
                {
                    options.Tracer?.WriteTrace("Deriving required key byte length");
                    pwd = options.Password;
                    try
                    {
                        options.Password = EnsureValidKeyLength(pwd);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                }
                // Switch to a MAC stream
                MacStreams? macStream = null;
                if (options.MacIncluded)
                {
                    options.Tracer?.WriteTrace("Using MAC");
                    if (options.MacAlgorithmIncluded)
                    {
                        options.Tracer?.WriteTrace($"Including MAC algorithm {options.MacAlgorithm}");
                        cipherData.WriteNumber(MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name).Value);
                        if (options.UsingCounterMac)
                        {
                            options.Tracer?.WriteTrace($"Including counter MAC algorithm {options.CounterMacAlgorithm}");
                            cipherData.WriteNumber(MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).Value);
                        }
                    }
                    options.MacPosition = cipherData.Position;
                    using (RentedArrayRefStruct<byte> buffer = options.UsingCounterMac
                        ? new(MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).MacLength)
                        : new(MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name).MacLength))
                    {
                        options.Tracer?.WriteTrace("Writing MAC placeholder");
                        cipherData.Write(buffer.Span);
                    }
                    bool coverWhole = RequireMacAuthentication || options.ForceMacCoverWhole;
                    options.Tracer?.WriteTrace($"MAC will cover {(coverWhole ? "everything" : "the crypto header")}");
                    CryptoOptions macOptions = coverWhole ? options : options.GetCopy();
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
                if (options.PrivateKeyRevisionIncluded)
                {
                    options.Tracer?.WriteTrace($"Including private key revision {options.PrivateKeyRevision}");
                    cipherData.WriteNumber(options.PrivateKeyRevision);
                }
                if (options.KeyExchangeDataIncluded)
                {
                    options.Tracer?.WriteTrace("Including key exchange data");
                    if (options.KeyExchangeData is null) throw new InvalidOperationException("Missing key exchange data");
                    cipherData.WriteSerialized(options.KeyExchangeData);
                }
                if (options.KdfAlgorithmIncluded)
                {
                    options.Tracer?.WriteTrace("Including KDF algorithm");
                    cipherData.WriteNumber(KdfHelper.GetAlgorithm(options.KdfAlgorithm ??= KdfHelper.DefaultAlgorithm.Name).Value);
                    cipherData.WriteNumber(options.KdfIterations);
                    cipherData.WriteBytes(options.KdfSalt);
                    cipherData.WriteStringNullable(options.KdfOptions);
                    if (options.UsingCounterKdf)
                    {
                        options.Tracer?.WriteTrace("Including counter KDF algorithm");
                        cipherData.WriteNumber(KdfHelper.GetAlgorithm(options.CounterKdfAlgorithm ??= HybridAlgorithmHelper.KdfAlgorithm?.Name ?? KdfHelper.DefaultAlgorithm.Name).Value);
                        cipherData.WriteNumber(options.CounterKdfIterations);
                        cipherData.WriteBytes(options.CounterKdfSalt);
                        cipherData.WriteStringNullable(options.CounterKdfOptions);
                    }
                }
                if (options.PayloadData is not null)
                {
                    options.Tracer?.WriteTrace("Including payload");
                    cipherData.WriteBytes(options.PayloadData);
                }
                if (options.TimeIncluded)
                {
                    options.Tracer?.WriteTrace("Including encryption time");
                    cipherData.WriteNumber((options.Time ??= DateTime.UtcNow).Ticks);
                }
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
                options?.Tracer?.WriteTrace($"Writing {GetType()} crypto header");
                if (CryptoHelper.StrictPostQuantumSafety && !IsPostQuantum) throw new InvalidOperationException($"Post quantum safety-forced - {Name} isn't post quantum");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: true, options);
                // Ensure having options and work with cloned options
                options = options?.GetCopy() ?? DefaultOptions;
                options = EncryptionHelper.GetDefaultOptions(options);
                if (options.HeaderProcessed) throw new InvalidOperationException();
                options.Password?.Clear();
                options.Password = pwd?.CloneArray();
                options.ValidateObject();
                // Write unauthenticated options
                MacStreams? macStream = null;
                if (options.FlagsIncluded)
                    using (RentedArrayStructSimple<byte> buffer = new(len: 3))
                    {
                        options.Tracer?.WriteTrace($"Including crypto options flags {options.Flags}");
                        EncodeFlags(options.Flags, buffer.Span);
                        await cipherData.WriteAsync(buffer.Memory, cancellationToken).DynamicContext();
                    }
                if (options.HeaderVersionIncluded)
                {
                    options.Tracer?.WriteTrace($"Including crypto header version {options.HeaderVersion}");
                    await cipherData.WriteAsync((byte)options.HeaderVersion, cancellationToken).DynamicContext();
                }
                if (options.SerializerVersionIncluded)
                {
                    options.Tracer?.WriteTrace($"Including serializer version {StreamSerializer.Version}");
                    await cipherData.WriteSerializerVersionAsync(cancellationToken).DynamicContext();
                }
                // Finalize the password to use
                if (options.KeyExchangeDataIncluded)
                {
                    options.Tracer?.WriteTrace("Generating key exchange data");
                    options.SetKeyExchangeData();
                }
                if (options.Password is null) throw new ArgumentException("Password required", nameof(pwd));
                if (options.KdfAlgorithmIncluded)
                {
                    options.Tracer?.WriteTrace($"Applying KDF {options.KdfAlgorithm}");
                    pwd = options.Password;
                    try
                    {
                        (options.Password, options.KdfSalt) = pwd.Stretch(KeySize, options: options);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                    if (options.UsingCounterKdf)
                    {
                        options.Tracer?.WriteTrace($"Applying counter KDF {options.CounterKdfAlgorithm}");
                        HybridAlgorithmHelper.StretchPassword(options);
                    }
                }
                if (!IsKeyLengthValid(options.Password.Length))
                {
                    options.Tracer?.WriteTrace("Deriving required key byte length");
                    pwd = options.Password;
                    try
                    {
                        options.Password = EnsureValidKeyLength(pwd);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                }
                // Switch to a MAC stream
                if (options.MacIncluded)
                {
                    options.Tracer?.WriteTrace("Using MAC");
                    if (options.MacAlgorithmIncluded)
                    {
                        options.Tracer?.WriteTrace($"Including MAC algorithm {options.MacAlgorithm}");
                        await cipherData.WriteNumberAsync(MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name).Value, cancellationToken).DynamicContext();
                        if (options.UsingCounterMac)
                        {
                            options.Tracer?.WriteTrace($"Including counter MAC algorithm {options.CounterMacAlgorithm}");
                            await cipherData.WriteNumberAsync(
                                MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).Value,
                                cancellationToken
                                ).DynamicContext();
                        }
                    }
                    options.MacPosition = cipherData.Position;
                    bool coverWhole = RequireMacAuthentication || options.ForceMacCoverWhole;
                    options.Tracer?.WriteTrace($"MAC will cover {(coverWhole ? "everything" : "the crypto header")}");
                    using (RentedArrayStruct<byte> buffer = options.UsingCounterMac
                        ? new(MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).MacLength)
                        : new(MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name).MacLength))
                        await cipherData.WriteAsync(buffer.Memory, cancellationToken).DynamicContext();
                    CryptoOptions macOptions = coverWhole ? options : options.GetCopy();
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
                if (options.PrivateKeyRevisionIncluded)
                {
                    options.Tracer?.WriteTrace($"Including private key revision {options.PrivateKeyRevision}");
                    await cipherData.WriteNumberAsync(options.PrivateKeyRevision, cancellationToken).DynamicContext();
                }
                if (options.KeyExchangeDataIncluded)
                {
                    options.Tracer?.WriteTrace("Including key exchange data");
                    if (options.KeyExchangeData is null) throw new InvalidOperationException("Missing key exchange data");
                    await cipherData.WriteSerializedAsync(options.KeyExchangeData, cancellationToken).DynamicContext();
                }
                if (options.KdfAlgorithmIncluded)
                {
                    options.Tracer?.WriteTrace("Including KDF algorithm");
                    await cipherData.WriteNumberAsync(KdfHelper.GetAlgorithm(options.KdfAlgorithm ??= KdfHelper.DefaultAlgorithm.Name).Value, cancellationToken).DynamicContext();
                    await cipherData.WriteNumberAsync(options.KdfIterations, cancellationToken).DynamicContext();
                    await cipherData.WriteBytesAsync(options.KdfSalt, cancellationToken).DynamicContext();
                    await cipherData.WriteStringNullableAsync(options.KdfOptions, cancellationToken).DynamicContext();
                    if (options.UsingCounterKdf)
                    {
                        options.Tracer?.WriteTrace("Including counter KDF algorithm");
                        await cipherData.WriteNumberAsync(
                            KdfHelper.GetAlgorithm(options.CounterKdfAlgorithm ??= HybridAlgorithmHelper.KdfAlgorithm?.Name ?? KdfHelper.DefaultAlgorithm.Name).Value, cancellationToken
                            ).DynamicContext();
                        await cipherData.WriteNumberAsync(options.CounterKdfIterations, cancellationToken).DynamicContext();
                        await cipherData.WriteBytesAsync(options.CounterKdfSalt, cancellationToken).DynamicContext();
                        await cipherData.WriteStringNullableAsync(options.CounterKdfOptions, cancellationToken).DynamicContext();
                    }
                }
                if (options.PayloadData is not null)
                {
                    options.Tracer?.WriteTrace("Including payload");
                    await cipherData.WriteBytesAsync(options.PayloadData, cancellationToken).DynamicContext();
                }
                if (options.TimeIncluded)
                {
                    options.Tracer?.WriteTrace("Including encryption time");
                    await cipherData.WriteNumberAsync((options.Time ??= DateTime.UtcNow).Ticks, cancellationToken).DynamicContext();
                }
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
                throw await CryptographicException.FromAsync(ex);
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
                options?.Tracer?.WriteTrace($"Reading {GetType()} crypto header");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
                // Ensure having options and work with cloned options
                options = options?.GetCopy() ?? DefaultOptions;
                options = EncryptionHelper.GetDefaultOptions(options);
                if (options.HeaderProcessed) return options;
                options.ValidateObject();
                // Prepare the password
                if (pwd is not null)
                {
                    options.Tracer?.WriteTrace("Using given password");
                    options.Password?.Clear();
                    options.Password = pwd.CloneArray();
                }
                else
                {
                    options.Tracer?.WriteTrace("Using password from the crypto options");
                    options.KeyExchangeDataIncluded = true;
                    options.RequireKeyExchangeData = true;
                }
                // Read unauthenticated options
                if (options.FlagsIncluded)
                    using (RentedArrayRefStruct<byte> buffer = new(len: 3))
                    {
                        options.Tracer?.WriteTrace("Reading crypto flags");
                        if (cipherData.Read(buffer.Span) != buffer.Length) throw new IOException("Failed to read the crypto flags");
                        options.Flags = DecodeFlags(buffer.Span);
                        options.Tracer?.WriteTrace($"Using crypto flags {options.Flags}");
                    }
                options.ValidateRequirements();
                if (options.HeaderVersionIncluded)
                {
                    options.Tracer?.WriteTrace("Reading crypto header version");
                    options.HeaderVersion = cipherData.ReadOneByte();
                    options.Tracer?.WriteTrace($"Crypto header version {options.HeaderVersion}");
                    if (options.HeaderVersion < 1 || options.HeaderVersion > CryptoOptions.HEADER_VERSION) throw new InvalidDataException($"Invalid header version {options.HeaderVersion}");
                }
                int? serializerVersion = options.SerializerVersionIncluded ? options.CustomSerializerVersion = cipherData.ReadSerializerVersion() : null;
                options.Tracer?.WriteTrace($"Serializer version {serializerVersion?.ToString() ?? "unknown"}");
                // Read the MAC
                MacAlgorithmBase? mac = null;
                if (options.MacIncluded)
                {
                    options.Tracer?.WriteTrace("Using MAC");
                    if (options.MacAlgorithmIncluded)
                    {
                        options.Tracer?.WriteTrace("Reading MAC algorithm");
                        options.MacAlgorithm = options.MacAlgorithmIncluded
                            ? MacHelper.GetAlgorithm(cipherData.ReadNumber<int>(serializerVersion)).Name
                            : options.MacAlgorithm ?? MacHelper.GetDefaultOptions(options).MacAlgorithm;
                        options.Tracer?.WriteTrace($"Using MAC algorithm {options.MacAlgorithm}");
                        if (options.UsingCounterMac)
                        {
                            options.Tracer?.WriteTrace("Reading counter MAC algorithm");
                            options.CounterMacAlgorithm = MacHelper.GetAlgorithm(cipherData.ReadNumber<int>(serializerVersion)).Name;
                            options.Tracer?.WriteTrace($"Using counter MAC algorithm {options.CounterMacAlgorithm}");
                        }
                    }
                    options.MacPosition = cipherData.Position;
                    mac = MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name);
                    int len = options.UsingCounterMac
                        ? MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).MacLength
                        : mac.MacLength;
                    options.Mac = new byte[len];
                    options.Tracer?.WriteTrace($"Reading MAC with {len} byte");
                    int red = cipherData.Read(options.Mac);
                    if (red != len) throw new IOException($"Failed to read the MAC (got only {red}/{len} byte)");
                }
                // Read authenticated options
                if (options.PrivateKeyRevisionIncluded)
                {
                    options.Tracer?.WriteTrace("Reading private key revision");
                    if (options.PrivateKeysStore is null) throw new ArgumentException("Missing private keys store", nameof(options));
                    options.PrivateKeyRevision = cipherData.ReadNumber<int>(serializerVersion);
                    options.Tracer?.WriteTrace($"Using private key revision {options.PrivateKeyRevision}");
                    options.ApplyPrivateKeySuite(options.PrivateKeysStore[options.PrivateKeyRevision]);
                }
                if (options.KeyExchangeDataIncluded)
                {
                    options.Tracer?.WriteTrace("Reading key exchange data");
                    options.KeyExchangeData = cipherData.ReadSerialized<KeyExchangeDataContainer>(serializerVersion);
                    options.Tracer?.WriteTrace("Deriving new key bytes");
                    options.Password = options.DeriveExchangedKey();
                }
                if (options.Password is null) throw new ArgumentException("Password required", nameof(pwd));
                if (options.KdfAlgorithmIncluded)
                {
                    options.Tracer?.WriteTrace("Reading KDF algorithm");
                    options.KdfAlgorithm = KdfHelper.GetAlgorithm(cipherData.ReadNumber<int>(serializerVersion)).Name;
                    options.KdfIterations = cipherData.ReadNumber<int>(serializerVersion);
                    options.KdfSalt = cipherData.ReadBytes(serializerVersion, minLen: 1, maxLen: byte.MaxValue).Value;
                    options.KdfOptions = cipherData.ReadStringNullable(serializerVersion, minLen: 0, maxLen: byte.MaxValue);
                    options.Tracer?.WriteTrace($"Using KDF algorithm {options.KdfAlgorithm} with {options.KdfIterations} iterations and {options.KdfSalt.Length} byte salt");
                    if (options.KdfOptions is not null && options.Tracer is not null) options.Tracer.WriteTrace($"KDF options {options.KdfOptions}");
                    pwd = options.Password;
                    try
                    {
                        (options.Password, _) = pwd.Stretch(KeySize, options.KdfSalt, options);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                    if (options.UsingCounterKdf)
                        try
                        {
                            options.Tracer?.WriteTrace("Reading counter KDF algorithm");
                            pwd = options.Password;
                            options.CounterKdfAlgorithm = KdfHelper.GetAlgorithm(cipherData.ReadNumber<int>(serializerVersion)).Name;
                            options.CounterKdfIterations = cipherData.ReadNumber<int>(serializerVersion);
                            options.CounterKdfSalt = cipherData.ReadBytes(serializerVersion, minLen: 1, maxLen: byte.MaxValue).Value;
                            options.CounterKdfOptions = cipherData.ReadStringNullable(serializerVersion, minLen: 0, maxLen: byte.MaxValue);
                            options.Tracer?.WriteTrace($"Using KDF algorithm {options.CounterKdfAlgorithm} with {options.CounterKdfIterations} iterations and {options.CounterKdfSalt.Length} byte salt");
                            if (options.CounterKdfOptions is not null && options.Tracer is not null) options.Tracer.WriteTrace($"KDF options {options.CounterKdfOptions}");
                            HybridAlgorithmHelper.StretchPassword(options);
                        }
                        finally
                        {
                            pwd.Clear();
                        }
                }
                if (!IsKeyLengthValid(options.Password.Length))
                {
                    options.Tracer?.WriteTrace("Deriving required key byte length");
                    pwd = options.Password;
                    try
                    {
                        options.Password = EnsureValidKeyLength(pwd);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                }
                if (options.PayloadIncluded)
                {
                    options.Tracer?.WriteTrace("Reading payload");
                    options.PayloadData = cipherData.ReadBytes(serializerVersion, minLen: 1, maxLen: ushort.MaxValue).Value;
                    options.Tracer?.WriteTrace($"Got {options.PayloadData.Length} payload byte");
                }
                if (options.TimeIncluded)
                {
                    options.Tracer?.WriteTrace("Reading encryption time");
                    options.Time = new DateTime(cipherData.ReadNumber<long>(serializerVersion));
                    options.Tracer?.WriteTrace($"Using encryption time {options.Time}");
                    if (options.MaximumTimeOffset is not null)
                    {
                        options.Tracer?.WriteTrace("Applying maximum time offset");
                        options.Time = options.Time.Value.ApplyOffset(options.MaximumTimeOffset.Value, DateTime.UtcNow);
                    }
                    if (options.MaximumAge is not null && DateTime.UtcNow - options.Time.Value > options.MaximumAge) throw new InvalidOperationException("Maximum age exceeded");
                }
                options.ValidateRequirements();
                // Authenticate the options and the cipher data using the MAC
                if (options.MacIncluded && (RequireMacAuthentication || options.ForceMacCoverWhole))
                {
                    options.Tracer?.WriteTrace("Authenticating the crypto header using the MAC");
                    long pos = cipherData.Position;
                    cipherData.Position = options.MacPosition + options.Mac!.Length;
                    CryptoOptions macOptions = mac!.DefaultOptions;
                    macOptions.LeaveOpen = true;
                    using MacStreams macStream = mac.GetMacStream(options.Password, options: macOptions);
                    cipherData.CopyTo(macStream.Stream);
                    macStream.Stream.Dispose();
                    byte[] redMac = options.Mac;
                    options.Mac = macStream.Transform.Hash ?? throw new InvalidProgramException();
                    if (options.UsingCounterMac)
                    {
                        options.Tracer?.WriteTrace("Authenticating the crypto header using the counter MAC");
                        HybridAlgorithmHelper.ComputeMac(options);
                    }
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
                options?.Tracer?.WriteTrace($"Reading {GetType()} crypto header");
                EncryptionHelper.ValidateStreams(rawData, cipherData, forEncryption: false, options);
                // Ensure having options and work with cloned options
                options = options?.GetCopy() ?? DefaultOptions;
                options = EncryptionHelper.GetDefaultOptions(options);
                if (options.HeaderProcessed) return options;
                options.ValidateObject();
                // Prepare the password
                if (pwd is not null)
                {
                    options.Tracer?.WriteTrace("Using given password");
                    options.Password?.Clear();
                    options.Password = pwd.CloneArray();
                }
                else
                {
                    options.Tracer?.WriteTrace("Using password from the crypto options");
                    options.KeyExchangeDataIncluded = true;
                    options.RequireKeyExchangeData = true;
                }
                // Read unauthenticated options
                if (options.FlagsIncluded)
                    using (RentedArrayStructSimple<byte> buffer = new(len: 3))
                    {
                        options.Tracer?.WriteTrace("Reading crypto flags");
                        if (await cipherData.ReadAsync(buffer.Memory, cancellationToken).DynamicContext() != buffer.Length) throw new IOException("Failed to read the crypto flags");
                        options.Flags = DecodeFlags(buffer.Span);
                        options.Tracer?.WriteTrace($"Using crypto flags {options.Flags}");
                    }
                options.ValidateRequirements();
                if (options.HeaderVersionIncluded)
                {
                    options.Tracer?.WriteTrace("Reading crypto header version");
                    options.HeaderVersion = await cipherData.ReadOneByteAsync(cancellationToken: cancellationToken).DynamicContext();
                    options.Tracer?.WriteTrace($"Crypto header version {options.HeaderVersion}");
                    if (options.HeaderVersion < 1 || options.HeaderVersion > CryptoOptions.HEADER_VERSION) throw new InvalidDataException($"Invalid header version {options.HeaderVersion}");
                }
                int? serializerVersion = options.SerializerVersionIncluded ? options.CustomSerializerVersion = await cipherData.ReadSerializerVersionAsync(cancellationToken).DynamicContext() : null;
                options.Tracer?.WriteTrace($"Serializer version {serializerVersion?.ToString() ?? "unknown"}");
                // Read the MAC
                MacAlgorithmBase? mac = null;
                if (options.MacIncluded)
                {
                    options.Tracer?.WriteTrace("Using MAC");
                    if (options.MacAlgorithmIncluded)
                    {
                        options.Tracer?.WriteTrace("Reading MAC algorithm");
                        options.MacAlgorithm = options.MacAlgorithmIncluded
                            ? MacHelper.GetAlgorithm(await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext()).Name
                            : options.MacAlgorithm ?? MacHelper.DefaultAlgorithm.Name;
                        options.Tracer?.WriteTrace($"Using MAC algorithm {options.MacAlgorithm}");
                        if (options.UsingCounterMac)
                        {
                            options.Tracer?.WriteTrace("Reading counter MAC algorithm");
                            options.CounterMacAlgorithm = MacHelper.GetAlgorithm(
                                await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext()
                                ).Name;
                            options.Tracer?.WriteTrace($"Using counter MAC algorithm {options.CounterMacAlgorithm}");
                        }
                    }
                    options.MacPosition = cipherData.Position;
                    mac = MacHelper.GetAlgorithm(options.MacAlgorithm ??= MacHelper.DefaultAlgorithm.Name);
                    int len = options.UsingCounterMac
                        ? MacHelper.GetAlgorithm(options.CounterMacAlgorithm ??= HybridAlgorithmHelper.MacAlgorithm?.Name ?? MacHelper.DefaultAlgorithm.Name).MacLength
                        : mac.MacLength;
                    options.Tracer?.WriteTrace($"Reading MAC with {len} byte");
                    options.Mac = new byte[len];
                    int red = await cipherData.ReadAsync(options.Mac, cancellationToken).DynamicContext();
                    if (red != len) throw new IOException($"Failed to read the MAC (got only {red}/{len} byte)");
                }
                // Read authenticated options
                if (options.PrivateKeyRevisionIncluded)
                {
                    options.Tracer?.WriteTrace("Reading private key revision");
                    if (options.PrivateKeysStore is null) throw new ArgumentException("Missing private keys store", nameof(options));
                    options.PrivateKeyRevision = await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext();
                    options.Tracer?.WriteTrace($"Using private key revision {options.PrivateKeyRevision}");
                    options.ApplyPrivateKeySuite(options.PrivateKeysStore[options.PrivateKeyRevision]);
                }
                if (options.KeyExchangeDataIncluded)
                {
                    options.Tracer?.WriteTrace("Reading key exchange data");
                    options.KeyExchangeData = await cipherData.ReadSerializedAsync<KeyExchangeDataContainer>(serializerVersion, cancellationToken: cancellationToken).DynamicContext();
                    options.Tracer?.WriteTrace("Deriving new key bytes");
                    options.Password = options.DeriveExchangedKey();
                }
                if (options.Password is null) throw new ArgumentException("Password required", nameof(pwd));
                if (options.KdfAlgorithmIncluded)
                {
                    options.Tracer?.WriteTrace("Reading KDF algorithm");
                    options.KdfAlgorithm = KdfHelper.GetAlgorithm(await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext()).Name;
                    options.KdfIterations = await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext();
                    options.KdfSalt = (await cipherData.ReadBytesAsync(serializerVersion, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
                    options.KdfOptions = await cipherData.ReadStringNullableAsync(serializerVersion, minLen: 0, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext();
                    options.Tracer?.WriteTrace($"Using KDF algorithm {options.KdfAlgorithm} with {options.KdfIterations} iterations and {options.KdfSalt.Length} byte salt");
                    if (options.KdfOptions is not null && options.Tracer is not null) options.Tracer.WriteTrace($"KDF options {options.KdfOptions}");
                    pwd = options.Password;
                    try
                    {
                        (options.Password, _) = pwd.Stretch(KeySize, options.KdfSalt, options);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                    if (options.UsingCounterKdf)
                    {
                        options.Tracer?.WriteTrace("Reading counter KDF algorithm");
                        options.CounterKdfAlgorithm = KdfHelper.GetAlgorithm(
                            await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext()
                            ).Name;
                        options.CounterKdfIterations = await cipherData.ReadNumberAsync<int>(serializerVersion, cancellationToken: cancellationToken).DynamicContext();
                        options.CounterKdfSalt = (await cipherData.ReadBytesAsync(serializerVersion, minLen: 1, maxLen: byte.MaxValue, cancellationToken: cancellationToken).DynamicContext())
                            .Value;
                        options.CounterKdfOptions = await cipherData.ReadStringNullableAsync(serializerVersion, minLen: 0, maxLen: byte.MaxValue, cancellationToken: cancellationToken)
                            .DynamicContext();
                        options.Tracer?.WriteTrace($"Using KDF algorithm {options.CounterKdfAlgorithm} with {options.CounterKdfIterations} iterations and {options.CounterKdfSalt.Length} byte salt");
                        if (options.CounterKdfOptions is not null && options.Tracer is not null) options.Tracer.WriteTrace($"KDF options {options.CounterKdfOptions}");
                        HybridAlgorithmHelper.StretchPassword(options);
                    }
                }
                if (!IsKeyLengthValid(options.Password.Length))
                {
                    options.Tracer?.WriteTrace("Deriving required key byte length");
                    pwd = options.Password;
                    try
                    {
                        options.Password = EnsureValidKeyLength(pwd);
                    }
                    finally
                    {
                        pwd.Clear();
                    }
                }
                if (options.PayloadIncluded)
                {
                    options.Tracer?.WriteTrace("Reading payload");
                    options.PayloadData = (await cipherData.ReadBytesAsync(serializerVersion, minLen: 1, maxLen: ushort.MaxValue, cancellationToken: cancellationToken).DynamicContext()).Value;
                    options.Tracer?.WriteTrace($"Got {options.PayloadData.Length} payload byte");
                }
                if (options.TimeIncluded)
                {
                    options.Tracer?.WriteTrace("Reading encryption time");
                    options.Time = new DateTime(await cipherData.ReadNumberAsync<long>(serializerVersion, cancellationToken: cancellationToken).DynamicContext());
                    options.Tracer?.WriteTrace($"Using encryption time {options.Time}");
                    if (options.MaximumTimeOffset is not null)
                    {
                        options.Tracer?.WriteTrace("Applying maximum time offset");
                        options.Time = options.Time.Value.ApplyOffset(options.MaximumTimeOffset.Value, DateTime.UtcNow);
                    }
                    if (options.MaximumAge is not null && DateTime.UtcNow - options.Time.Value > options.MaximumAge) throw new InvalidOperationException("Maximum age exceeded");
                }
                options.ValidateRequirements();
                // Authenticate the options and the cipher data using the MAC
                if (options.MacIncluded && (RequireMacAuthentication || options.ForceMacCoverWhole))
                {
                    options.Tracer?.WriteTrace("Authenticating the crypto header using the MAC");
                    long pos = cipherData.Position;
                    cipherData.Position = options.MacPosition + options.Mac!.Length;
                    CryptoOptions macOptions = mac!.DefaultOptions;
                    macOptions.LeaveOpen = true;
                    using MacStreams macStream = mac.GetMacStream(options.Password, options: macOptions);
                    await cipherData.CopyToAsync(macStream.Stream, cancellationToken).DynamicContext();
                    macStream.Stream.Dispose();
                    byte[] redMac = options.Mac;
                    options.Mac = macStream.Transform.Hash ?? throw new InvalidProgramException();
                    if (options.UsingCounterMac)
                    {
                        options.Tracer?.WriteTrace("Authenticating the crypto header using the counter MAC");
                        HybridAlgorithmHelper.ComputeMac(options);
                    }
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
                throw await CryptographicException.FromAsync(ex);
            }
        }
    }
}
