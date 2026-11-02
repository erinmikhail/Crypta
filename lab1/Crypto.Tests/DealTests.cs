using Crypto.Deal;
using Crypto.Des;
using Crypto.Modes;
using Crypto.Padding;

namespace Crypto.Tests;


public class DealTests
{
    private static readonly byte[] Plain = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");

    [Theory(DisplayName = "6. DEAL-128/192/256: контрольный шифртекст и обратно")]
    [InlineData("0123456789ABCDEFFEDCBA9876543210", "C0585FBDE51E5C1915E0D31DA1DA8BFE")]
    [InlineData("0123456789ABCDEFFEDCBA98765432100011223344556677", "570C3A300AAA115E2E4DDA2291E33D29")]
    [InlineData("0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF", "E758079903418B820A7D5423F8CC165D")]
    public void ReferenceVectors(string keyHex, string expectedHex)
    {
        var deal = new DealCipher();
        deal.SetKey(Convert.FromHexString(keyHex));

        byte[] encrypted = deal.EncryptBlock(Plain);

        Assert.Equal(expectedHex, Convert.ToHexString(encrypted));
        Assert.Equal(Plain, deal.DecryptBlock(encrypted));
    }

    [Theory(DisplayName = "6. Число раундов: 6 для 128 и 192 бит, 8 для 256 бит")]
    [InlineData(16, 6)]
    [InlineData(24, 6)]
    [InlineData(32, 8)]
    public void RoundCount(int keyLength, int rounds) =>
        Assert.Equal(rounds, new DealKeyExpansion().GenerateRoundKeys(new byte[keyLength]).Length);

    [Fact(DisplayName = "6. Адаптер: F(R, K) — это шифрование R алгоритмом DES на ключе K")]
    public void AdapterIsDes()
    {
        byte[] block = Convert.FromHexString("0123456789ABCDEF");
        byte[] key = Convert.FromHexString("133457799BBCDFF1");

        var des = new DesCipher();
        des.SetKey(key);

        Assert.Equal(des.EncryptBlock(block), new DesRoundFunctionAdapter().Transform(block, key));
    }

    [Theory(DisplayName = "DEAL: зашифровать -> расшифровать в каждом режиме")]
    [InlineData(CipherMode.Ecb)]
    [InlineData(CipherMode.Cbc)]
    [InlineData(CipherMode.Pcbc)]
    [InlineData(CipherMode.Cfb)]
    [InlineData(CipherMode.Ofb)]
    [InlineData(CipherMode.Ctr)]
    [InlineData(CipherMode.RandomDelta)]
    public async Task RoundTrip(CipherMode mode)
    {
        byte[] key = Convert.FromHexString("0123456789ABCDEFFEDCBA9876543210");
        byte[] iv = Convert.FromHexString("000102030405060708090A0B0C0D0E0F");
        var context = new CipherContext(new DealCipher(), key, mode, PaddingMode.Pkcs7, iv, 7);

        byte[] data = new byte[16 * 1024 + 5];   // 1025 блоков - работает и параллельная обработка
        new Random(6).NextBytes(data);

        Assert.Equal(data, await context.DecryptAsync(await context.EncryptAsync(data)));
    }

    [Theory(DisplayName = "Ключ не 16/24/32 байта - исключение")]
    [InlineData(8)]
    [InlineData(15)]
    [InlineData(40)]
    public void InvalidKeyLength(int length) =>
        Assert.Throws<ArgumentException>(() => new DealCipher().SetKey(new byte[length]));
}
