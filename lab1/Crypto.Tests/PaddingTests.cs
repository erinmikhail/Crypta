using Crypto.Padding;

namespace Crypto.Tests;

/// <summary>режимы набивки (блок 8 байт).</summary>
public class PaddingTests
{
    private static readonly byte[] Source = Convert.FromHexString("AABBCCDDEEFF1122");

    [Theory(DisplayName = "2.4. Набивка: точные байты")]
    [InlineData(PaddingMode.Zeros, 5, "AABBCCDDEE000000")]
    [InlineData(PaddingMode.AnsiX923, 5, "AABBCCDDEE000003")]
    [InlineData(PaddingMode.Pkcs7, 5, "AABBCCDDEE030303")]
    [InlineData(PaddingMode.Zeros, 8, "AABBCCDDEEFF1122")]
    [InlineData(PaddingMode.AnsiX923, 8, "AABBCCDDEEFF1122" + "0000000000000008")]
    [InlineData(PaddingMode.Pkcs7, 8, "AABBCCDDEEFF1122" + "0808080808080808")]
    [InlineData(PaddingMode.Pkcs7, 0, "0808080808080808")]
    public void ExactBytes(PaddingMode mode, int length, string expectedHex) =>
        Assert.Equal(expectedHex, Convert.ToHexString(BlockPadding.Apply(Source[..length], 8, mode)));

    [Fact(DisplayName = "2.4. ISO 10126: последний байт — длина, остальное случайно")]
    public void Iso10126()
    {
        byte[] padded = BlockPadding.Apply(Source[..5], 8, PaddingMode.Iso10126);

        Assert.Equal(8, padded.Length);
        Assert.Equal(3, padded[^1]);
        Assert.Equal(Source[..5], padded[..5]);
    }

    public static TheoryData<PaddingMode, int> AllModesAndLengths()
    {
        var cases = new TheoryData<PaddingMode, int>();
        foreach (PaddingMode mode in Enum.GetValues<PaddingMode>())
            foreach (int length in new[] { 0, 1, 7, 8, 9, 100 })
                cases.Add(mode, length);
        return cases;
    }

    [Theory(DisplayName = "Набивка: добавить -> снять = исходные данные")]
    [MemberData(nameof(AllModesAndLengths))]
    public void RoundTrip(PaddingMode mode, int length)
    {
        byte[] data = Enumerable.Range(1, length).Select(i => (byte)i).ToArray();
        byte[] padded = BlockPadding.Apply(data, 8, mode);

        Assert.Equal(0, padded.Length % 8);
        Assert.Equal(data, BlockPadding.Remove(padded, 8, mode));
    }

    [Fact(DisplayName = "PKCS7: повреждённая набивка обнаруживается")]
    public void CorruptedPkcs7() =>
        Assert.Throws<InvalidDataException>(() =>
            BlockPadding.Remove([1, 2, 3, 4, 5, 6, 7, 0x09], 8, PaddingMode.Pkcs7));

    [Fact(DisplayName = "Zeros: нули в конце данных теряются (свойство режима)")]
    public void ZerosLimitation() =>
        Assert.Equal("AABB", Convert.ToHexString(
            BlockPadding.Remove(BlockPadding.Apply([0xAA, 0xBB, 0x00, 0x00], 8, PaddingMode.Zeros), 8, PaddingMode.Zeros)));
}
