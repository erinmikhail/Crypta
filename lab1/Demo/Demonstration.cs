using System.Buffers.Binary;
using System.Diagnostics;
using System.Numerics;
using System.Text;
using Crypto;
using Crypto.Interfaces;
using Crypto.Modes;
using Crypto.Padding;

namespace Demo;


internal static class Demonstration
{
    private static readonly Dictionary<CipherMode, (bool Encrypt, bool Decrypt)> Parallelism = new()
    {
        [CipherMode.Ecb] = (true, true),
        [CipherMode.Cbc] = (false, true),
        [CipherMode.Pcbc] = (false, false),
        [CipherMode.Cfb] = (false, true),
        [CipherMode.Ofb] = (false, false),
        [CipherMode.Ctr] = (true, true),
        [CipherMode.RandomDelta] = (true, true),
    };

    private sealed record Setup(string Name, Func<ISymmetricCipher> CreateCipher, byte[] Key, byte[] Iv,
        byte[] Delta, string OutputDir)
    {
        public int BlockSize { get; } = CreateCipher().BlockSize;

        public CipherContext Context(CipherMode mode, PaddingMode padding = PaddingMode.Pkcs7) =>
            new(CreateCipher(), Key, mode, padding, Iv, Delta);
    }

    public static async Task RunAsync(string name, Func<ISymmetricCipher> createCipher, int keySize,
        string samplesDir, string outputRoot, long maxFileSize, int speedTestBytes)
    {
        int blockSize = createCipher().BlockSize;
        byte[] delta = RandomBytes(blockSize);
        delta[^1] |= 1;   

        var setup = new Setup(name, createCipher, RandomBytes(keySize), RandomBytes(blockSize), delta,
            Path.Combine(outputRoot, name));
        Directory.CreateDirectory(setup.OutputDir);

        Console.WriteLine();
        Console.WriteLine($"Демонстрация {name}: блок {blockSize * 8} бит, ключ {keySize * 8} бит");
        Console.WriteLine($"Ключ: {Convert.ToHexString(setup.Key)}");
        Console.WriteLine($"IV:   {Convert.ToHexString(setup.Iv)}");
        Console.WriteLine($"delta:    {Convert.ToHexString(setup.Delta)}");

        await RandomSequencesAsync(setup);
        await FilesAsync(setup, samplesDir, maxFileSize);
        await ImageAsync(setup, samplesDir);
        await ErrorPropagationAsync(setup);
        Avalanche(setup);
        await SpeedAsync(setup, speedTestBytes);
    }


    private static async Task RandomSequencesAsync(Setup setup)
    {
        Console.WriteLine();
        Console.WriteLine("1.Псевдослучайные последовательности байтов");

        int bs = setup.BlockSize;
        int[] lengths = [0, 1, bs - 1, bs, bs + 1, 1000, 100_003];
        byte[] sample = RandomBytes(2 * bs);

        Console.WriteLine($"Длины: {string.Join(", ", lengths)}. Пример: {Blocks(sample, bs)}");

        foreach (CipherMode mode in Enum.GetValues<CipherMode>())
        {
            CipherContext ctx = setup.Context(mode);
            int ok = 0;

            foreach (int length in lengths)
            {
                byte[] data = RandomBytes(length);
                if ((await ctx.DecryptAsync(await ctx.EncryptAsync(data))).SequenceEqual(data))
                    ok++;
            }

            byte[] sampleEncrypted = await ctx.EncryptAsync(sample);
            Console.WriteLine($"   [{Status(ok == lengths.Length)}] {mode,-11} {ok}/{lengths.Length} | шифр примера: " +
                              Blocks(sampleEncrypted[..(2 * bs)], bs));
        }
    }

    
    private static async Task FilesAsync(Setup setup, string samplesDir, long maxFileSize)
    {
        Console.WriteLine();
        Console.WriteLine($"2.Файлы из {samplesDir}");

        if (!Directory.Exists(samplesDir) || !Directory.EnumerateFiles(samplesDir).Any())
        {
            Console.WriteLine("Папка пуста. Положите туда текст, музыку, картинку, видео, исходный код и запустите снова.");
            return;
        }

        string filesDir = Path.Combine(setup.OutputDir, "files");
        Directory.CreateDirectory(filesDir);

        foreach (string path in Directory.GetFiles(samplesDir).OrderBy(p => p))
        {
            long size = new FileInfo(path).Length;

            if (size > maxFileSize)
            {
                Console.WriteLine($"{Path.GetFileName(path)} ({FormatSize(size)}) - пропущен: больше {FormatSize(maxFileSize)}");
                continue;
            }

            Console.WriteLine($"   {Path.GetFileName(path)} ({FormatSize(size)})");
            string baseName = Path.GetFileNameWithoutExtension(path);
            string extension = Path.GetExtension(path);

            foreach (CipherMode mode in Enum.GetValues<CipherMode>())
            {
                string encPath = Path.Combine(filesDir, $"{baseName}.{mode}.enc");
                string decPath = Path.Combine(filesDir, $"{baseName}.{mode}.dec{extension}");
                CipherContext ctx = setup.Context(mode);

                var stopwatch = Stopwatch.StartNew();
                await ctx.EncryptAsync(path, encPath);
                long encryptMs = stopwatch.ElapsedMilliseconds;

                stopwatch.Restart();
                await ctx.DecryptAsync(encPath, decPath);
                long decryptMs = stopwatch.ElapsedMilliseconds;

                byte[] original = await File.ReadAllBytesAsync(path);
                byte[] restored = await File.ReadAllBytesAsync(decPath);

                Console.WriteLine($"[{Status(original.SequenceEqual(restored))}] {mode,-11} " +
                                  $"шифрование {encryptMs,6} мс, расшифровка {decryptMs,6} мс");
            }
        }

        Console.WriteLine($"Результаты: {filesDir}");
    }


    private static async Task ImageAsync(Setup setup, string samplesDir)
    {
        Console.WriteLine();
        Console.WriteLine("3.Картинка: ECB против CBC");

        string? bmpPath = Directory.Exists(samplesDir)
            ? Directory.GetFiles(samplesDir, "*.bmp").OrderBy(p => p).FirstOrDefault()
            : null;

        if (bmpPath is null)
        {
            Console.WriteLine("В samples нет .bmp. Сохраните любую картинку как BMP.");
            Console.WriteLine("На PNG и JPG эффект не виден: они сжаты, одинак блоков почти нет.");
            return;
        }

        byte[] bmp = await File.ReadAllBytesAsync(bmpPath);
        int pixelOffset = BinaryPrimitives.ReadInt32LittleEndian(bmp.AsSpan(10));   
        byte[] header = bmp[..pixelOffset];
        byte[] pixels = bmp[pixelOffset..];

        foreach (CipherMode mode in new[] { CipherMode.Ecb, CipherMode.Cbc })
        {
            
            byte[] encrypted = await setup.Context(mode, PaddingMode.Zeros).EncryptAsync(pixels);
            byte[] picture = [.. header, .. encrypted[..pixels.Length]];

            string outPath = Path.Combine(setup.OutputDir, $"{Path.GetFileNameWithoutExtension(bmpPath)}_{mode}.bmp");
            await File.WriteAllBytesAsync(outPath, picture);
            Console.WriteLine($"   {outPath}");
        }

    }

    
    private static async Task ErrorPropagationAsync(Setup setup)
    {
        Console.WriteLine();
        Console.WriteLine($"4.Ошибка в 1 бите блока 3: сколько бит испорчено в каждом из 8 блоков (из {setup.BlockSize * 8})");

        int bs = setup.BlockSize;
        byte[] text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("The quick brown fox jumps. ", 20)))[..(8 * bs)];

        foreach (CipherMode mode in Enum.GetValues<CipherMode>())
        {
            CipherContext ctx = setup.Context(mode, PaddingMode.Zeros);
            byte[] encrypted = await ctx.EncryptAsync(text);
            encrypted[2 * bs] ^= 0x01;
            byte[] decrypted = await ctx.DecryptAsync(encrypted);

            int[] counts = new int[8];
            for (int i = 0; i < text.Length; i++)
            {
                byte actual = i < decrypted.Length ? decrypted[i] : (byte)0;
                counts[i / bs] += BitOperations.PopCount((uint)(text[i] ^ actual));
            }

            Console.WriteLine($"{mode,-11} {string.Join(" ", counts.Select(c => c.ToString().PadLeft(3)))}" +
                              $"испорчено блоков: {counts.Count(c => c > 0)}");
        }
    }

    
    private static void Avalanche(Setup setup)
    {
        Console.WriteLine();
        Console.WriteLine("5.Лавинный эффект");

        ISymmetricCipher cipher = setup.CreateCipher();
        cipher.SetKey(setup.Key);

        byte[] block = RandomBytes(setup.BlockSize);
        byte[] changedBlock = (byte[])block.Clone();
        changedBlock[^1] ^= 0x01;

        byte[] changedKey = (byte[])setup.Key.Clone();
        changedKey[0] ^= 0x02;   
        ISymmetricCipher other = setup.CreateCipher();
        other.SetKey(changedKey);

        int total = setup.BlockSize * 8;
        Console.WriteLine($"1 бит текста -> изменилось {DifferentBits(cipher.EncryptBlock(block), cipher.EncryptBlock(changedBlock))} из {total} бит шифра");
        Console.WriteLine($"1 бит ключа  -> изменилось {DifferentBits(cipher.EncryptBlock(block), other.EncryptBlock(block))} из {total} бит шифра");
    }

    
    private static async Task SpeedAsync(Setup setup, int bytes)
    {
        Console.WriteLine();
        Console.WriteLine($"6.Скорость на {FormatSize(bytes)}, ядер: {Environment.ProcessorCount}");

        byte[] data = RandomBytes(bytes);
        double megabytes = bytes / 1048576.0;

        foreach (CipherMode mode in Enum.GetValues<CipherMode>())
        {
            CipherContext ctx = setup.Context(mode);

            var stopwatch = Stopwatch.StartNew();
            byte[] encrypted = await ctx.EncryptAsync(data);
            double encryptSpeed = megabytes / stopwatch.Elapsed.TotalSeconds;

            stopwatch.Restart();
            await ctx.DecryptAsync(encrypted);
            double decryptSpeed = megabytes / stopwatch.Elapsed.TotalSeconds;

            var (parallelEncrypt, parallelDecrypt) = Parallelism[mode];
            Console.WriteLine($"{mode,-11} шифрование {encryptSpeed,6:F2} МБ/с {(parallelEncrypt ? "паралл" : "послед")}, " +
                              $"расшифровка {decryptSpeed,6:F2} МБ/с {(parallelDecrypt ? "паралл" : "послед")}");
        }
    }

    private static byte[] RandomBytes(int count) =>
        System.Security.Cryptography.RandomNumberGenerator.GetBytes(count);

    private static int DifferentBits(byte[] a, byte[] b)
    {
        int count = 0;
        for (int i = 0; i < a.Length; i++)
            count += BitOperations.PopCount((uint)(a[i] ^ b[i]));
        return count;
    }

    private static string Status(bool ok) => ok ? "OK" : "ERROR";

    private static string Blocks(byte[] bytes, int blockSize) =>
        string.Join(" ", bytes.Chunk(blockSize).Select(Convert.ToHexString));

    private static string FormatSize(long bytes) => bytes switch
    {
        >= 1 << 20 => $"{bytes / 1048576.0:F1} МБ",
        >= 1 << 10 => $"{bytes / 1024.0:F1} КБ",
        _ => $"{bytes} байт"
    };
}
