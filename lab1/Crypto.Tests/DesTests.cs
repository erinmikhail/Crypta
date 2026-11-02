using System.Text;
using Crypto.Des;
using Crypto.Modes;
using Crypto.Padding;

namespace Crypto.Tests;


public class DesTests
{
    private static readonly byte[] FipsKey = Convert.FromHexString("0123456789ABCDEF");
    private static readonly byte[] FipsIv = Convert.FromHexString("1234567890ABCDEF");
    private static readonly byte[] FipsText = Encoding.ASCII.GetBytes("Now is the time for all ");

    [Fact(DisplayName = "Расписание ключей: K1 и K16 для ключа 133457799BBCDFF1")]
    public void RoundKeys()
    {
        byte[][] keys = new DesKeyExpansion().GenerateRoundKeys(Convert.FromHexString("133457799BBCDFF1"));

        Assert.Equal(16, keys.Length);
        Assert.Equal("1B02EFFC7072", Convert.ToHexString(keys[0]));
        Assert.Equal("CB3D8B0E17F5", Convert.ToHexString(keys[15]));
    }

    [Fact(DisplayName = "Один блок: DES(0123456789ABCDEF) = 85E813540F0AB405 и обратно")]
    public void SingleBlock()
    {
        var des = new DesCipher();
        des.SetKey(Convert.FromHexString("133457799BBCDFF1"));

        byte[] encrypted = des.EncryptBlock(Convert.FromHexString("0123456789ABCDEF"));

        Assert.Equal("85E813540F0AB405", Convert.ToHexString(encrypted));
        Assert.Equal("0123456789ABCDEF", Convert.ToHexString(des.DecryptBlock(encrypted)));
    }

    [Theory(DisplayName = "4. «Now is the time for all »: эталонный шифртекст в каждом режиме")]
    [InlineData(CipherMode.Ecb, "3FA40E8A984D48156A271787AB8883F9893D51EC4B563B53")]
    [InlineData(CipherMode.Cbc, "E5C7CDDE872BF27C43E934008C389C0F683788499A7C05F6")]
    [InlineData(CipherMode.Pcbc, "E5C7CDDE872BF27CCB70B78C59494228265F223FC0C655A5")]
    [InlineData(CipherMode.Cfb, "F3096249C7F46E51A69E839B1A92F78403467133898EA622")]
    [InlineData(CipherMode.Ofb, "F3096249C7F46E5135F24A242EEB3D3F3D6D5BE3255AF8C3")]
    [InlineData(CipherMode.Ctr, "F3096249C7F46E51163A8CA0FFC94C27FA2F80F480B86F75")]
    [InlineData(CipherMode.RandomDelta, "F3096249C7F46E51D1627A190B7F76DB1E0A699D0F71195B")]
    public async Task ReferenceVectors(CipherMode mode, string expectedHex)
    {
        
        var context = new CipherContext(new DesCipher(), FipsKey, mode, PaddingMode.Zeros, FipsIv, 7);

        byte[] encrypted = await context.EncryptAsync(FipsText);

        Assert.Equal(expectedHex, Convert.ToHexString(encrypted));
        Assert.Equal(FipsText, await context.DecryptAsync(encrypted));
    }

    public static TheoryData<CipherMode, PaddingMode> AllModesAndPaddings()
    {
        var cases = new TheoryData<CipherMode, PaddingMode>();
        foreach (CipherMode mode in Enum.GetValues<CipherMode>())
            foreach (PaddingMode padding in Enum.GetValues<PaddingMode>())
                cases.Add(mode, padding);
        return cases;
    }

    [Theory(DisplayName = "Зашифровать -> расшифровать: каждый режим × каждая набивка × разные длины")]
    [MemberData(nameof(AllModesAndPaddings))]
    public async Task RoundTrip(CipherMode mode, PaddingMode padding)
    {
        var context = new CipherContext(new DesCipher(), FipsKey, mode, padding, FipsIv, 7);

        
        foreach (int length in new[] { 0, 1, 7, 8, 9, 100, 64 * 1024 + 3 })
        {
            byte[] data = new byte[length];
            new Random(length).NextBytes(data);
            if (padding == PaddingMode.Zeros && length > 0)
                data[^1] |= 1;   

            Assert.Equal(data, await context.DecryptAsync(await context.EncryptAsync(data)));
        }
    }

    [Theory(DisplayName = "Параллельная обработка даёт тот же шифр, что последовательная")]
    [InlineData(CipherMode.Ecb)]
    [InlineData(CipherMode.Ctr)]
    [InlineData(CipherMode.RandomDelta)]
    public async Task ParallelEqualsSequential(CipherMode mode)
    {
        var context = new CipherContext(new DesCipher(), FipsKey, mode, PaddingMode.Pkcs7, FipsIv, 7);

        byte[] big = new byte[64 * 1024];     // 8192 блока  → параллельно
        new Random(1).NextBytes(big);
        byte[] head = big[..4096];            // 512 блоков  → по очереди

        byte[] bigEncrypted = await context.EncryptAsync(big);
        byte[] headEncrypted = await context.EncryptAsync(head);

        Assert.Equal(headEncrypted[..head.Length], bigEncrypted[..head.Length]);
    }

    [Fact(DisplayName = "Ключ не 8 байт - исключение")]
    public void InvalidKeyLength() =>
        Assert.Throws<ArgumentException>(() => new DesCipher().SetKey(new byte[7]));
}
