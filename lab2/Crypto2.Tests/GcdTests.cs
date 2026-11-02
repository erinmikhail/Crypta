using System.Numerics;
using Crypto2.NumberTheory;

namespace Crypto2.Tests;

public class GcdTests
{
    private readonly NumberTheoryService _service = new();

    [Theory]
    [InlineData(1071, 462, 21)]
    [InlineData(462, 1071, 21)]
    [InlineData(55, 34, 1)]
    [InlineData(0, 5, 5)]
    [InlineData(5, 0, 5)]
    [InlineData(0, 0, 0)]
    [InlineData(-12, 18, 6)]
    [InlineData(-4, -6, 2)]
    public void Gcd_SmallNumbers(long a, long b, long expected)
    {
        BigInteger result = _service.Gcd(a, b);

        Assert.Equal(new BigInteger(expected), result);
    }

    [Fact]
    public void Gcd_BigNumbers()
    {
        BigInteger a = 3 * (BigInteger.One << 100);
        BigInteger b = 9 * (BigInteger.One << 90);
        BigInteger expected = 3 * (BigInteger.One << 90);

        Assert.Equal(expected, _service.Gcd(a, b));
    }
}