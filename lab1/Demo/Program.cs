using System.Text;
using Crypto.Deal;
using Crypto.Des;
using Demo;

Console.OutputEncoding = Encoding.UTF8;

string samplesDir = Path.GetFullPath("samples");
string outputDir = Path.GetFullPath("demo_out");

if (args.Length > 0)
{
    if (args[0] == "des") await RunDesDemoAsync();
    else if (args[0] == "deal") await RunDealDemoAsync();
    else Console.WriteLine("Аргументы: des | deal. Без аргументов - меню.");
    return;
}

while (true)
{
    Console.WriteLine();
    Console.WriteLine("Лабораторная работа №1: DES и DEAL");
    Console.WriteLine("1 - зашифровать / расшифровать свои данные");
    Console.WriteLine("2 - демонстрация DES (задание 5)");
    Console.WriteLine("3 - демонстрация DEAL (задание 7)");
    Console.WriteLine("0 - выход");
    Console.Write("> ");

    switch (Console.ReadLine()?.Trim())
    {
        case "1":
            await Interactive.RunAsync();
            break;
        case "2":
            await RunDesDemoAsync();
            break;
        case "3":
            await RunDealDemoAsync();
            break;
        case "0" or null:
            return;
        default:
            Console.WriteLine("Нет такого пункта.");
            break;
    }
}

// DES: файлы до 4 МБ. DEAL в каждом раунде выполняет целый DES, поэтому медленнее: файлы до 1 МБ.
Task RunDesDemoAsync() => Demonstration.RunAsync("DES", () => new DesCipher(), DesCipher.KeySize,
    samplesDir, outputDir, maxFileSize: 4L << 20, speedTestBytes: 1 << 20);

Task RunDealDemoAsync() => Demonstration.RunAsync("DEAL", () => new DealCipher(), 16,
    samplesDir, outputDir, maxFileSize: 1L << 20, speedTestBytes: 1 << 18);
