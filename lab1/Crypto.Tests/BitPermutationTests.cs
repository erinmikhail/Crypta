using Crypto.Bits;

namespace Crypto.Tests;

/// <summary>перестановка битов.</summary>
public class BitPermutationTests
{
    private static readonly byte[] Value = [0xB1];                    
    private static readonly int[] RotateTable = [2, 3, 4, 5, 6, 7, 8, 1];

    [Fact(DisplayName = "От старшего, с 1: таблица даёт сдвиг влево (B1 -> 63)")]
    public void MsbFirstFromOne() =>
        Assert.Equal("63", Hex(BitPermutation.Permute(Value, RotateTable, BitOrder.MsbFirst, 1)));

    [Fact(DisplayName = "От младшего, с 1: та же таблица даёт сдвиг вправо (B1 -> D8)")]
    public void LsbFirstFromOne() =>
        Assert.Equal("D8", Hex(BitPermutation.Permute(Value, RotateTable, BitOrder.LsbFirst, 1)));

    [Fact(DisplayName = "Нумерация с 0: таблица [1..7, 0] даёт тот же результат")]
    public void MsbFirstFromZero() =>
        Assert.Equal("63", Hex(BitPermutation.Permute(Value, [1, 2, 3, 4, 5, 6, 7, 0], BitOrder.MsbFirst, 0)));

    [Fact(DisplayName = "Нумерация сквозная по всему массиву: обмен байтов (B10F -> 0FB1)")]
    public void ThroughWholeArray() =>
        Assert.Equal("0FB1", Hex(BitPermutation.Permute([0xB1, 0x0F],
            [8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7], BitOrder.MsbFirst, 0)));

    [Fact(DisplayName = "Расширение: таблица длиннее входа (8 -> 16 бит)")]
    public void Expansion() =>
        Assert.Equal("B1B1", Hex(BitPermutation.Permute(Value,
            [1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8], BitOrder.MsbFirst, 1)));

    [Fact(DisplayName = "Сжатие: таблица короче входа (8 -> 4 бита)")]
    public void Compression() =>
        Assert.Equal("B0", Hex(BitPermutation.Permute(Value, [1, 2, 3, 4], BitOrder.MsbFirst, 1)));

    [Fact(DisplayName = "Номер бита вне значения - исключение")]
    public void IndexOutOfRange() =>
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            BitPermutation.Permute(Value, [9], BitOrder.MsbFirst, 1));

    [Fact(DisplayName = "Начальный номер не 0 и не 1 - исключение")]
    public void InvalidStartIndex() =>
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            BitPermutation.Permute(Value, RotateTable, BitOrder.MsbFirst, 2));

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes);
}
