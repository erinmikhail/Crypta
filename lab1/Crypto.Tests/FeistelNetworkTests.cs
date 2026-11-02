using Crypto.Feistel;
using Crypto.Interfaces;
using Crypto.Modes;
using Crypto.Padding;

namespace Crypto.Tests;

/// <summary>сеть Фейстеля отдельно от DES.</summary>
public class FeistelNetworkTests
{
    private sealed class XorKeyExpansion(int rounds) : IKeyExpansion
    {
        public byte[][] GenerateRoundKeys(byte[] key) =>
            Enumerable.Range(1, rounds).Select(r => key.Select(b => (byte)(b ^ r)).ToArray()).ToArray();
    }

    private sealed class SquareRoundFunction : IRoundFunction
    {
        public byte[] Transform(byte[] block, byte[] roundKey) =>
            block.Select((b, i) => (byte)(b * b + roundKey[i % roundKey.Length])).ToArray();
    }

    [Fact(DisplayName = "Два раунда - значение")]
    public void TwoRoundsByHand()
    {
        var network = new FeistelNetwork(new XorKeyExpansion(2), new SquareRoundFunction(), blockSize: 2);
        network.SetKey([0x05]);  

        byte[] encrypted = network.EncryptBlock([0x0A, 0x03]);

        Assert.Equal("3B07", Convert.ToHexString(encrypted));
        Assert.Equal("0A03", Convert.ToHexString(network.DecryptBlock(encrypted)));
    }

    [Theory(DisplayName = "Необратимая F, 16 раундов: расшифровка восстанавливает данные в каждом режиме")]
    [InlineData(CipherMode.Ecb)]
    [InlineData(CipherMode.Cbc)]
    [InlineData(CipherMode.Pcbc)]
    [InlineData(CipherMode.Cfb)]
    [InlineData(CipherMode.Ofb)]
    [InlineData(CipherMode.Ctr)]
    [InlineData(CipherMode.RandomDelta)]
    public async Task NonInvertibleFunction(CipherMode mode)
    {
        var network = new FeistelNetwork(new XorKeyExpansion(16), new SquareRoundFunction(), blockSize: 8);
        var context = new CipherContext(network, [1, 2, 3, 4, 5, 6, 7, 8], mode, PaddingMode.Pkcs7,
            new byte[8], 7);

        byte[] data = new byte[1000];
        new Random(3).NextBytes(data);

        Assert.Equal(data, await context.DecryptAsync(await context.EncryptAsync(data)));
    }

    [Fact(DisplayName = "Шифрование без SetKey - исключение")]
    public void WithoutKey() =>
        Assert.Throws<InvalidOperationException>(() =>
            new FeistelNetwork(new XorKeyExpansion(2), new SquareRoundFunction(), 2).EncryptBlock([1, 2]));

    [Fact(DisplayName = "Нечётный размер блока - исключение")]
    public void OddBlockSize() =>
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new FeistelNetwork(new XorKeyExpansion(2), new SquareRoundFunction(), 3));
}
