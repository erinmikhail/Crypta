using Crypto.Des;
using Crypto.Modes;
using Crypto.Padding;

namespace Crypto.Tests;

public class CipherContextTests
{
    private static readonly byte[] Key = Convert.FromHexString("0123456789ABCDEF");
    private static readonly byte[] Iv = Convert.FromHexString("1234567890ABCDEF");

    [Fact(DisplayName = "Режиму, кроме ECB, без IV - исключение")]
    public void IvRequired() =>
        Assert.Throws<ArgumentException>(() =>
            new CipherContext(new DesCipher(), Key, CipherMode.Cbc, PaddingMode.Pkcs7));

    [Fact(DisplayName = "IV не длиной в блок - исключение")]
    public void IvWrongLength() =>
        Assert.Throws<ArgumentException>(() =>
            new CipherContext(new DesCipher(), Key, CipherMode.Cbc, PaddingMode.Pkcs7, new byte[5]));

    [Fact(DisplayName = "Random Delta: delta не передан, равен нулю, отрицательный, не того типа или длины - исключение")]
    public void InvalidDelta()
    {
        object[][] bad = [[], [0], [-5], ["семь"], [new byte[3]], [new byte[8]]];

        foreach (object[] parameters in bad)
        {
            Assert.Throws<ArgumentException>(() =>
                new CipherContext(new DesCipher(), Key, CipherMode.RandomDelta, PaddingMode.Pkcs7, Iv, parameters));
        }
    }

    [Fact(DisplayName = "ECB: одинаковые блоки дают одинаковый шифр, CBC - нет")]
    public async Task EcbShowsRepeats()
    {
        byte[] data = new byte[16];   

        byte[] ecb = await new CipherContext(new DesCipher(), Key, CipherMode.Ecb, PaddingMode.Zeros).EncryptAsync(data);
        byte[] cbc = await new CipherContext(new DesCipher(), Key, CipherMode.Cbc, PaddingMode.Zeros, Iv).EncryptAsync(data);

        Assert.Equal(ecb[..8], ecb[8..]);
        Assert.NotEqual(cbc[..8], cbc[8..]);
    }

    [Theory(DisplayName = "Счётчик CTR / Random Delta с переносом между байтами")]
    [InlineData("00000000000000FF", 1, "0000000000000100")]     
    [InlineData("FFFFFFFFFFFFFFFF", 1, "0000000000000000")]     
    [InlineData("0000000000000000", 256, "0000000000000100")]  
    public async Task CounterIncrement(string ivHex, int delta, string secondCounterHex)
    {
        byte[] iv = Convert.FromHexString(ivHex);
        CipherMode mode = delta == 1 ? CipherMode.Ctr : CipherMode.RandomDelta;
        var context = new CipherContext(new DesCipher(), Key, mode, PaddingMode.Zeros, iv, delta);

        
        byte[] masks = await context.EncryptAsync(new byte[16]);

        var des = new DesCipher();
        des.SetKey(Key);
        Assert.Equal(des.EncryptBlock(iv), masks[..8]);
        Assert.Equal(des.EncryptBlock(Convert.FromHexString(secondCounterHex)), masks[8..]);
    }

    [Fact(DisplayName = "Повторное шифрование тем же контекстом даёт тот же результат")]
    public async Task NoStateLeak()
    {
        var context = new CipherContext(new DesCipher(), Key, CipherMode.Cbc, PaddingMode.Pkcs7, Iv);
        byte[] data = new byte[100];

        Assert.Equal(await context.EncryptAsync(data), await context.EncryptAsync(data));
    }

    [Theory(DisplayName = "Файл больше 1 МБ (несколько кусков): шифр совпадает с шифром массива, расшифровка - с исходником")]
    [InlineData(CipherMode.Ecb)]
    [InlineData(CipherMode.Cbc)]
    [InlineData(CipherMode.Pcbc)]
    [InlineData(CipherMode.Cfb)]
    [InlineData(CipherMode.Ofb)]
    [InlineData(CipherMode.Ctr)]
    [InlineData(CipherMode.RandomDelta)]
    public async Task Files(CipherMode mode)
    {
        string dir = Path.Combine(Path.GetTempPath(), "CryptoLab1Tests", mode.ToString());
        Directory.CreateDirectory(dir);
        string plainPath = Path.Combine(dir, "plain.bin");
        string encPath = Path.Combine(dir, "plain.enc");
        string decPath = Path.Combine(dir, "plain.dec");

        byte[] data = new byte[(1 << 20) + 13];
        new Random(5).NextBytes(data);
        await File.WriteAllBytesAsync(plainPath, data);

        var context = new CipherContext(new DesCipher(), Key, mode, PaddingMode.Pkcs7, Iv, 7);

        await context.EncryptAsync(plainPath, encPath);
        await context.DecryptAsync(encPath, decPath);

        byte[] fromFile = await File.ReadAllBytesAsync(encPath);
        byte[] fromArray = await context.EncryptAsync(data);
        byte[] restored = await File.ReadAllBytesAsync(decPath);

        Directory.Delete(dir, recursive: true);

        Assert.Equal(fromArray, fromFile);
        Assert.Equal(data, restored);
    }

    [Fact(DisplayName = "Пустой файл: набивка PKCS7 даёт один блок, расшифровка - пустой файл")]
    public async Task EmptyFile()
    {
        string dir = Path.Combine(Path.GetTempPath(), "CryptoLab1Tests", "empty");
        Directory.CreateDirectory(dir);
        string plainPath = Path.Combine(dir, "empty.bin");
        await File.WriteAllBytesAsync(plainPath, []);

        var context = new CipherContext(new DesCipher(), Key, CipherMode.Cbc, PaddingMode.Pkcs7, Iv);
        await context.EncryptAsync(plainPath, plainPath + ".enc");
        await context.DecryptAsync(plainPath + ".enc", plainPath + ".dec");

        long encryptedLength = new FileInfo(plainPath + ".enc").Length;
        long decryptedLength = new FileInfo(plainPath + ".dec").Length;
        Directory.Delete(dir, recursive: true);

        Assert.Equal(8, encryptedLength);
        Assert.Equal(0, decryptedLength);
    }

    [Fact(DisplayName = "Один и тот же файл на входе и выходе - исключение")]
    public async Task SameFile()
    {
        string path = Path.GetTempFileName();
        var context = new CipherContext(new DesCipher(), Key, CipherMode.Cbc, PaddingMode.Pkcs7, Iv);

        await Assert.ThrowsAsync<ArgumentException>(() => context.EncryptAsync(path, path));
        File.Delete(path);
    }
}
