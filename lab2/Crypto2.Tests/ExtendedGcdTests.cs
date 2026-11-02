using System.Numerics;
using Crypto2.NumberTheory;

namespace Crypto2.Tests;

public class ExtendedGcdTests
{
    private readonly NumberTheoryService _service = new();

    [Fact]
    public void ExtendedGcd_ReturnsCoefficientsFromTable()
    {
        var (gcd, x, y) = _service.ExtendedGcd(240, 46);

        Assert.Equal(new BigInteger(2), gcd);
        Assert.Equal(new BigInteger(-9), x);
        Assert.Equal(new BigInteger(47), y);
    }

    [Theory]
    [InlineData(240, 46)]
    [InlineData(-240, 46)]
    [InlineData(240, -46)]
    [InlineData(17, 3120)]
    [InlineData(0, 5)]
    [InlineData(5, 0)]
    [InlineData(0, 0)]
    public void ExtendedGcd_SatisfiesBezout(long a, long b)
    {
        var (gcd, x, y) = _service.ExtendedGcd(a, b);

        Assert.Equal(_service.Gcd(a, b), gcd);
        Assert.Equal(gcd, a * x + b * y);
    }

    [Theory]
    [InlineData(-7, 3, 2)]
    [InlineData(7, 3, 1)]
    [InlineData(-9, 3, 0)]
    public void Mod_ReturnsNonNegativeRemainder(long value, long modulus, long expected)
    {
        Assert.Equal(new BigInteger(expected), _service.Mod(value, modulus));
    }

    [Theory]
    [InlineData(3, 7, 5)]
    [InlineData(17, 3120, 2753)]
    [InlineData(-3, 7, 2)]
    public void ModInverse_ReturnsInverse(long a, long modulus, long expected)
    {
        BigInteger inverse = _service.ModInverse(a, modulus);

        Assert.Equal(new BigInteger(expected), inverse);
        Assert.Equal(BigInteger.One, _service.Mod(a * inverse, modulus));
    }

    [Fact]
    public void ModInverse_ThrowsWhenNotCoprime()
    {
        Assert.Throws<ArgumentException>(() => _service.ModInverse(6, 9));
    }

    [Fact]
    public void Mod_ThrowsOnNonPositiveModulus()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _service.Mod(5, 0));
    }
}