using Crypto.Interfaces;
using Crypto.Modes;
using Crypto.Padding;

namespace Crypto;

///<summary>сим алгоритм шифр и дешифр данных произвол длины в заданном шифре и режиме и набивке</summary>
public sealed class CipherContext
{
    private readonly ISymmetricCipher _cipher;
    private readonly CipherMode _mode;
    private readonly PaddingMode _padding;
    private readonly byte[]? _iv;
    private readonly byte[]? _delta;
    private const int ChunkSize = 1 << 20; // 1 MB

    /// <param name="cipher">Алгоритм шифрования блоков</param>
    /// <param name="key">Ключ шифрования.</param>
    /// <param name="mode">Режим шифрования.</param>
    /// <param name="padding">Режим набивки.</param>
    /// <param name="iv">Вектор инициализации; обязателен для всех режимов, кроме ECB.</param>
    /// <param name="modeParameters">Дополнительные параметры режима (delta для Random Delta).</param>

    public CipherContext(ISymmetricCipher cipher, byte[] key, CipherMode mode, PaddingMode padding, byte[]? iv = null, params object[] modeParameters)
    {
        ArgumentNullException.ThrowIfNull(cipher);
        ArgumentNullException.ThrowIfNull(key);

        if (!Enum.IsDefined(mode))
        {
            throw new ArgumentOutOfRangeException(nameof(mode), "Недопустимый режим шифрования.");
        }

        if (!Enum.IsDefined(padding))
        {
            throw new ArgumentOutOfRangeException(nameof(padding), "Недопустимый режим набивки.");
        }

        if (mode != CipherMode.Ecb && (iv == null || iv.Length != cipher.BlockSize))
        {
            throw new ArgumentException($"IV должен быть длиной {cipher.BlockSize} байт для режима {mode}.", nameof(iv));
        }

        byte[]? delta = mode switch
        {
            CipherMode.Ctr => ToBlock(1, cipher.BlockSize),
            CipherMode.RandomDelta => ParseDelta(modeParameters, cipher.BlockSize),
            _ => null
        };

        cipher.SetKey(key);

        _cipher = cipher;
        _mode = mode;
        _padding = padding;
        _iv = (byte[]?)iv?.Clone();
        _delta = delta;
    }

    ///<summary>асинх шифр данные. Len кратна размеру блока</summary>
    ///<returns>Шифр — новый массив, длина кратна размеру блока.</returns>
    public Task<byte[]> EncryptAsync(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);
        return Task.Run(() => EncryptCore(data));
    }

    public Task<byte[]> DecryptAsync(byte[] data)
    {
        ArgumentNullException.ThrowIfNull(data);

        if (data.Length % _cipher.BlockSize != 0)
        {
            throw new ArgumentException("Длина данных не кратна размеру блока.", nameof(data));
        }

        return Task.Run(() => DecryptCore(data));
    }

    public Task EncryptAsync(string inputPath, string outputPath)
    {
        ValidatePaths(inputPath, outputPath);
        return ProcessFileAsync(inputPath, outputPath, encrypt: true);
    }

    public Task DecryptAsync(string inputPath, string outputPath)
    {
        ValidatePaths(inputPath, outputPath);
        return ProcessFileAsync(inputPath, outputPath, encrypt: false);
    }

    private byte[] EncryptCore(byte[] data)
    {
        byte[] buffer = BlockPadding.Apply(data, _cipher.BlockSize, _padding);
        CreateModeProcessor().Encrypt(buffer);
        return buffer;
    }

    private byte[] DecryptCore(byte[] data)
    {
        byte[] buffer = (byte[])data.Clone();
        CreateModeProcessor().Decrypt(buffer);
        return BlockPadding.Remove(buffer, _cipher.BlockSize, _padding);
    }

    private ICipherModeProcessor CreateModeProcessor() => _mode switch
    {
        CipherMode.Ecb => new EcbMode(_cipher),
        CipherMode.Cbc => new CbcMode(_cipher, _iv!),
        CipherMode.Pcbc => new PcbcMode(_cipher, _iv!),
        CipherMode.Cfb => new CfbMode(_cipher, _iv!),
        CipherMode.Ofb => new OfbMode(_cipher, _iv!),
        CipherMode.Ctr or CipherMode.RandomDelta => new CounterMode(_cipher, _iv!, _delta!),
        _ => throw new InvalidOperationException($"Неизвестный режим {_mode}.")
    };

    ///<summary>шаг дельта из доп парамтр проверк</summary>
    private static byte[] ParseDelta(object[]? parametrs, int blockSize)
    {
        if (parametrs == null || parametrs.Length == 0)
        {
            throw new ArgumentException("Для режима Random Delta требуется параметр delta.", nameof(parametrs));
        }

        byte[] delta = parametrs[0] switch
        {
            byte[] bytes when bytes.Length == blockSize => (byte[])bytes.Clone(),
            byte[] bytes => throw new ArgumentException($"delta должен быть длиной {blockSize} байт.", nameof(parametrs)),

            int value when value > 0 => ToBlock((ulong)value, blockSize),
            long value when value > 0 => ToBlock((ulong)value, blockSize),
            _ => throw new ArgumentException("delta должен быть положительным целым числом или массивом байт.", nameof(parametrs))
        };

        if (delta.All(b => b == 0))
        {
            throw new ArgumentException("delta не может быть нулевым массивом.", nameof(parametrs));
        }

        return delta;
    }

    private static byte[] ToBlock(ulong value, int blockSize)
    {
        byte[] block = new byte[blockSize];
        for (int i = blockSize - 1; i >= 0 && value != 0; i--)
        {
            block[i] = (byte)value;
            value >>= 8;
        }
        return block;
    }

    private static void ValidatePaths(string inputPath, string outputPath)
    {
        ArgumentException.ThrowIfNullOrEmpty(inputPath, nameof(inputPath));
        ArgumentException.ThrowIfNullOrEmpty(outputPath, nameof(outputPath));

        if (!File.Exists(inputPath))
        {
            throw new FileNotFoundException($"Файл не найден: {inputPath}", inputPath);
        }

        if (string.Equals(Path.GetFullPath(inputPath), Path.GetFullPath(outputPath), StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Путь к входному и выходному файлу не может быть одинаковым.", nameof(outputPath));
        }
    }

    private async Task ProcessFileAsync(string inputPath, string outputPath, bool encrypt)
    {
        try
        {
            await TransformFileAsync(inputPath, outputPath, encrypt).ConfigureAwait(false);
        }
        catch
        {
            if (File.Exists(outputPath))
            {
                File.Delete(outputPath);
            }
            throw;
        }
    }

    private async Task TransformFileAsync(string inputPath, string outputPath, bool encrypt)
    {
        int blockSize = _cipher.BlockSize;
        int chunkSize = ChunkSize - (ChunkSize % blockSize);

        await using var input = new FileStream(inputPath, new FileStreamOptions
        {
            Mode = FileMode.Open,
            Access = FileAccess.Read,
            Share = FileShare.Read,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan
        });

        await using var output = new FileStream(outputPath, new FileStreamOptions
        {
            Mode = FileMode.Create,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan
        });

        long remaining = input.Length;

        if (!encrypt && remaining % blockSize != 0)
        {
            throw new InvalidDataException("Длина зашифрованного файла не кратна размеру блока.");
        }

        ICipherModeProcessor processor = CreateModeProcessor();
        byte[] chunk = new byte[chunkSize];
        bool isLast;

        do
        {
            int toRead = (int)Math.Min(chunkSize, remaining);
            int read = await input.ReadAtLeastAsync(chunk.AsMemory(0, toRead), toRead, throwOnEndOfStream: true).ConfigureAwait(false);

            remaining -= read;
            isLast = remaining == 0;

            byte[] result = encrypt
                ? await Task.Run(() => EncryptChunk(processor, chunk, read, isLast)).ConfigureAwait(false)
                : await Task.Run(() => DecryptChunk(processor, chunk, read, isLast)).ConfigureAwait(false);

            await output.WriteAsync(result).ConfigureAwait(false);
        }
        while (!isLast);
    }


    private byte[] EncryptChunk(ICipherModeProcessor processor, byte[] chunk, int length, bool isLast)
    {
        byte[] buffer = isLast ? BlockPadding.Apply(chunk[..length], _cipher.BlockSize, _padding) : chunk;

        processor.Encrypt(buffer);
        return buffer;
    }

    private byte[] DecryptChunk(ICipherModeProcessor processor, byte[] chunk, int length, bool isLast)
    {
        byte[] buffer = isLast ? chunk[..length] : chunk;
        processor.Decrypt(buffer);

        return isLast ? BlockPadding.Remove(buffer, _cipher.BlockSize, _padding) : buffer;
    }
}