using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using Crypto;
using Crypto.Deal;
using Crypto.Des;
using Crypto.Interfaces;
using Crypto.Modes;
using Crypto.Padding;

namespace Demo;

/// <summary>Шифрование и дешифрование своих данных: выбор алгоритма, режима, набивки, ключа, IV и Δ.</summary>
internal static class Interactive
{
    public static async Task RunAsync()
    {
        Console.WriteLine();
        Console.WriteLine("Шифрование и дешифрование своих данных");

        bool isDes = Choose("Алгоритм", ["DES", "DEAL"]) == 0;
        int blockSize = isDes ? 8 : 16;
        int keySize = isDes ? 8 : new[] { 16, 24, 32 }[Choose("Длина ключа DEAL", ["128 бит", "192 бита", "256 бит"])];

        CipherMode mode = Enum.GetValues<CipherMode>()[Choose("Режим шифрования", Enum.GetNames<CipherMode>())];
        PaddingMode padding = Enum.GetValues<PaddingMode>()[Choose("Режим набивки", Enum.GetNames<PaddingMode>())];

        byte[] key = ReadHex($"Ключ: {keySize} байт = {keySize * 2} hex-символов", keySize);
        byte[]? iv = mode == CipherMode.Ecb
            ? null
            : ReadHex($"IV: {blockSize} байт = {blockSize * 2} hex-символов", blockSize);
        object[] modeParameters = mode == CipherMode.RandomDelta ? [ReadDelta(blockSize)] : [];

        ISymmetricCipher cipher = isDes ? new DesCipher() : new DealCipher();
        CipherContext context;

        try
        {
            context = new CipherContext(cipher, key, mode, padding, iv, modeParameters);
        }
        catch (ArgumentException ex)
        {
            Console.WriteLine($"Ошибка в параметрах: {ex.Message}");
            return;
        }

        Console.WriteLine();
        Console.WriteLine($"Параметры: {(isDes ? "DES" : $"DEAL-{keySize * 8}")}, режим {mode}, набивка {padding}");
        Console.WriteLine($"ключ: {Convert.ToHexString(key)}");
        if (iv is not null)
            Console.WriteLine($"  IV:   {Convert.ToHexString(iv)}");
        if (modeParameters.Length > 0)
            Console.WriteLine($"  delta:    {Convert.ToHexString((byte[])modeParameters[0])}");

        while (true)
        {
            Console.WriteLine();
            int action = Choose("Действие",
                ["зашифровать текст", "зашифровать hex", "расшифровать hex", "зашифровать файл", "расшифровать файл", "назад в меню"]);

            if (action == 5)
                return;

            try
            {
                switch (action)
                {
                    case 0:
                        await EncryptBytesAsync(context, Encoding.UTF8.GetBytes(ReadLine("Текст")), blockSize, showText: true);
                        break;
                    case 1:
                        await EncryptBytesAsync(context, Convert.FromHexString(ReadLine("Данные (hex)").Replace(" ", "")), blockSize, showText: false);
                        break;
                    case 2:
                        await DecryptBytesAsync(context, Convert.FromHexString(ReadLine("Шифртекст (hex)").Replace(" ", "")), blockSize);
                        break;
                    case 3:
                        await ProcessFileAsync(context, encrypt: true);
                        break;
                    case 4:
                        await ProcessFileAsync(context, encrypt: false);
                        break;
                }
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or InvalidDataException or IOException)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
            }
        }
    }

    private static async Task EncryptBytesAsync(CipherContext context, byte[] data, int blockSize, bool showText)
    {
        byte[] encrypted = await context.EncryptAsync(data);
        byte[] decrypted = await context.DecryptAsync(encrypted);

        Console.WriteLine($"Открытый текст ({data.Length} байт): {Blocks(data, blockSize)}");
        Console.WriteLine($"Шифртекст      ({encrypted.Length} байт): {Blocks(encrypted, blockSize)}");
        Console.WriteLine(showText
            ? $"Проверка - расшифровка: «{Encoding.UTF8.GetString(decrypted)}»"
            : $"Проверка - расшифровка: {Blocks(decrypted, blockSize)}");
        Console.WriteLine(decrypted.SequenceEqual(data) ? "Совпадает с исходными данными: OK" : "Не совпадает: ERROR");
    }

    private static async Task DecryptBytesAsync(CipherContext context, byte[] data, int blockSize)
    {
        byte[] decrypted = await context.DecryptAsync(data);

        Console.WriteLine($"Расшифровка ({decrypted.Length} байт): {Blocks(decrypted, blockSize)}");
        Console.WriteLine($"Как текст UTF-8: «{Encoding.UTF8.GetString(decrypted)}»");
    }

    private static async Task ProcessFileAsync(CipherContext context, bool encrypt)
    {
        string input = ReadLine("Путь к входному файлу").Trim('"');
        string defaultOutput = encrypt ? input + ".enc" : (input.EndsWith(".enc") ? input[..^4] + ".dec" : input + ".dec");
        string output = ReadLine($"Путь к выходному файлу (Enter - {defaultOutput})").Trim('"');
        if (output.Length == 0)
            output = defaultOutput;

        var stopwatch = Stopwatch.StartNew();
        if (encrypt)
            await context.EncryptAsync(input, output);
        else
            await context.DecryptAsync(input, output);

        Console.WriteLine($"Готово за {stopwatch.ElapsedMilliseconds} мс: {output} ({new FileInfo(output).Length} байт)");
    }



    private static int Choose(string title, string[] options)
    {
        Console.WriteLine($"{title}:");
        for (int i = 0; i < options.Length; i++)
            Console.WriteLine($"  {i + 1} - {options[i]}");

        while (true)
        {
            Console.Write("> ");
            if (int.TryParse(Console.ReadLine(), out int choice) && choice >= 1 && choice <= options.Length)
                return choice - 1;
            Console.WriteLine($"Введите число от 1 до {options.Length}.");
        }
    }

    private static string ReadLine(string prompt)
    {
        Console.Write($"{prompt}: ");
        return Console.ReadLine() ?? "";
    }

    /// <summary>Hex заданной длины; пустой ввод - случайные байты.</summary>
    private static byte[] ReadHex(string prompt, int length)
    {
        while (true)
        {
            string input = ReadLine($"{prompt} (Enter - случайный)").Replace(" ", "");

            if (input.Length == 0)
            {
                byte[] random = System.Security.Cryptography.RandomNumberGenerator.GetBytes(length);
                Console.WriteLine($"  сгенерирован: {Convert.ToHexString(random)}");
                return random;
            }

            try
            {
                byte[] bytes = Convert.FromHexString(input);
                if (bytes.Length == length)
                    return bytes;
                Console.WriteLine($"Нужно ровно {length} байт ({length * 2} hex-символов), введено {bytes.Length}.");
            }
            catch (FormatException)
            {
                Console.WriteLine("Это не hex: допустимы символы 0–9 и A–F.");
            }
        }
    }

    /// <summary>delta для Random Delta: десятичное число или hex длиной в блок; пустой ввод случайный.</summary>
    private static byte[] ReadDelta(int blockSize)
    {
        while (true)
        {
            string input = ReadLine($"delta: число (например 7) или hex из {blockSize * 2} символов (Enter - случайный)").Replace(" ", "");

            if (input.Length == 0)
            {
                byte[] random = System.Security.Cryptography.RandomNumberGenerator.GetBytes(blockSize);
                random[^1] |= 1;   
                Console.WriteLine($"сгенерирован: {Convert.ToHexString(random)}");
                return random;
            }

            if (input.Length == blockSize * 2)
            {
                try
                {
                    return Convert.FromHexString(input);
                }
                catch (FormatException)
                {
                    Console.WriteLine("Это не hex.");
                    continue;
                }
            }

            if (ulong.TryParse(input, out ulong number) && number > 0)
            {
                byte[] delta = new byte[blockSize];
                BinaryPrimitives.WriteUInt64BigEndian(delta.AsSpan(blockSize - 8), number);
                return delta;
            }

            Console.WriteLine("Введите положительное число или hex длиной в блок.");
        }
    }

    private static string Blocks(byte[] bytes, int blockSize) =>
        string.Join(" ", bytes.Chunk(blockSize).Select(Convert.ToHexString));
}
