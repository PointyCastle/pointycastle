// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.ecc.ecc_f2m;

/*
import "package:cipher/api.dart";
import "package:cipher/src/ecc/ecc.dart";

/*
/**
 * Class representing the Elements of the finite field
 * <code>F<sub>2<sup>m</sup></sub></code> in polynomial basis (PB)
 * representation. Both trinomial (TPB) and pentanomial (PPB) polynomial
 * basis representations are supported. Gaussian normal basis (GNB)
 * representation is not supported.
 */
public static class F2m extends ECFieldElement
{
/**
 * Indicates gaussian normal basis representation (GNB). Number chosen
 * according to X9.62. GNB is not implemented at present.
 */
public static final int GNB = 1;

/**
 * Indicates trinomial basis representation (TPB). Number chosen
 * according to X9.62.
 */
public static final int TPB = 2;

/**
 * Indicates pentanomial basis representation (PPB). Number chosen
 * according to X9.62.
 */
public static final int PPB = 3;

/**
 * TPB or PPB.
 */
private int representation;

/**
 * The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
 */
private int m;

/**
 * TPB: The integer <code>k</code> where <code>x<sup>m</sup> +
 * x<sup>k</sup> + 1</code> represents the reduction polynomial
 * <code>f(z)</code>.<br>
 * PPB: The integer <code>k1</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.<br>
 */
private int k1;

/**
 * TPB: Always set to <code>0</code><br>
 * PPB: The integer <code>k2</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.<br>
 */
private int k2;

/**
 * TPB: Always set to <code>0</code><br>
 * PPB: The integer <code>k3</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.<br>
 */
private int k3;

/**
 * The <code>IntArray</code> holding the bits.
 */
private IntArray x;

/**
 * The number of <code>int</code>s required to hold <code>m</code> bits.
 */
private int t;

/**
 * Constructor for PPB.
 * @param m  The exponent <code>m</code> of
 * <code>F<sub>2<sup>m</sup></sub></code>.
 * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.
 * @param k2 The integer <code>k2</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.
 * @param k3 The integer <code>k3</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.
 * @param x The BigInteger representing the value of the field element.
 */
public F2m(
int m, 
int k1, 
int k2, 
int k3,
BigInteger x)
{
// t = m / 32 rounded up to the next integer
t = (m + 31) >> 5;
this.x = new IntArray(x, t);

if ((k2 == 0) && (k3 == 0))
{
this.representation = TPB;
}
else
{
if (k2 >= k3)
{
throw new IllegalArgumentException(
"k2 must be smaller than k3");
}
if (k2 <= 0)
{
throw new IllegalArgumentException(
"k2 must be larger than 0");
}
this.representation = PPB;
}

if (x.signum() < 0)
{
throw new IllegalArgumentException("x value cannot be negative");
}

this.m = m;
this.k1 = k1;
this.k2 = k2;
this.k3 = k3;
}

/**
 * Constructor for TPB.
 * @param m  The exponent <code>m</code> of
 * <code>F<sub>2<sup>m</sup></sub></code>.
 * @param k The integer <code>k</code> where <code>x<sup>m</sup> +
 * x<sup>k</sup> + 1</code> represents the reduction
 * polynomial <code>f(z)</code>.
 * @param x The BigInteger representing the value of the field element.
 */
public F2m(int m, int k, BigInteger x)
{
// Set k1 to k, and set k2 and k3 to 0
this(m, k, 0, 0, x);
}

private F2m(int m, int k1, int k2, int k3, IntArray x)
{
t = (m + 31) >> 5;
this.x = x;
this.m = m;
this.k1 = k1;
this.k2 = k2;
this.k3 = k3;

if ((k2 == 0) && (k3 == 0))
{
this.representation = TPB;
}
else
{
this.representation = PPB;
}

}

public BigInteger toBigInteger()
{
return x.toBigInteger();
}

public String getFieldName()
{
return "F2m";
}

public int getFieldSize()
{
return m;
}

/**
 * Checks, if the ECFieldElements <code>a</code> and <code>b</code>
 * are elements of the same field <code>F<sub>2<sup>m</sup></sub></code>
 * (having the same representation).
 * @param a field element.
 * @param b field element to be compared.
 * @throws IllegalArgumentException if <code>a</code> and <code>b</code>
 * are not elements of the same field
 * <code>F<sub>2<sup>m</sup></sub></code> (having the same
 * representation). 
 */
public static void checkFieldElements(
ECFieldElement a,
ECFieldElement b)
{
if ((!(a instanceof F2m)) || (!(b instanceof F2m)))
{
throw new IllegalArgumentException("Field elements are not "
+ "both instances of ECFieldElement.F2m");
}

ECFieldElement.F2m aF2m = (ECFieldElement.F2m)a;
ECFieldElement.F2m bF2m = (ECFieldElement.F2m)b;

if ((aF2m.m != bF2m.m) || (aF2m.k1 != bF2m.k1)
|| (aF2m.k2 != bF2m.k2) || (aF2m.k3 != bF2m.k3))
{
throw new IllegalArgumentException("Field elements are not "
+ "elements of the same field F2m");
}

if (aF2m.representation != bF2m.representation)
{
// Should never occur
throw new IllegalArgumentException(
"One of the field "
+ "elements are not elements has incorrect representation");
}
}

public ECFieldElement add(final ECFieldElement b)
{
// No check performed here for performance reasons. Instead the
// elements involved are checked in ECPoint.F2m
// checkFieldElements(this, b);
IntArray iarrClone = (IntArray)this.x.clone();
F2m bF2m = (F2m)b;
iarrClone.addShifted(bF2m.x, 0);
return new F2m(m, k1, k2, k3, iarrClone);
}

public ECFieldElement subtract(final ECFieldElement b)
{
// Addition and subtraction are the same in F2m
return add(b);
}

public ECFieldElement multiply(final ECFieldElement b)
{
// Right-to-left comb multiplication in the IntArray
// Input: Binary polynomials a(z) and b(z) of degree at most m-1
// Output: c(z) = a(z) * b(z) mod f(z)

// No check performed here for performance reasons. Instead the
// elements involved are checked in ECPoint.F2m
// checkFieldElements(this, b);
F2m bF2m = (F2m)b;
IntArray mult = x.multiply(bF2m.x, m);
mult.reduce(m, new int[]{k1, k2, k3});
return new F2m(m, k1, k2, k3, mult);
}

public ECFieldElement divide(final ECFieldElement b)
{
// There may be more efficient implementations
ECFieldElement bInv = b.invert();
return multiply(bInv);
}

public ECFieldElement negate()
{
// -x == x holds for all x in F2m
return this;
}

public ECFieldElement square()
{
IntArray squared = x.square(m);
squared.reduce(m, new int[]{k1, k2, k3});
return new F2m(m, k1, k2, k3, squared);
}


public ECFieldElement invert()
{
// Inversion in F2m using the extended Euclidean algorithm
// Input: A nonzero polynomial a(z) of degree at most m-1
// Output: a(z)^(-1) mod f(z)

// u(z) := a(z)
IntArray uz = (IntArray)this.x.clone();

// v(z) := f(z)
IntArray vz = new IntArray(t);
vz.setBit(m);
vz.setBit(0);
vz.setBit(this.k1);
if (this.representation == PPB) 
{
vz.setBit(this.k2);
vz.setBit(this.k3);
}

// g1(z) := 1, g2(z) := 0
IntArray g1z = new IntArray(t);
g1z.setBit(0);
IntArray g2z = new IntArray(t);

// while u != 0
while (!uz.isZero())
//            while (uz.getUsedLength() > 0)
//            while (uz.bitLength() > 1)
{
// j := deg(u(z)) - deg(v(z))
int j = uz.bitLength() - vz.bitLength();

// If j < 0 then: u(z) <-> v(z), g1(z) <-> g2(z), j := -j
if (j < 0) 
{
final IntArray uzCopy = uz;
uz = vz;
vz = uzCopy;

final IntArray g1zCopy = g1z;
g1z = g2z;
g2z = g1zCopy;

j = -j;
}

// u(z) := u(z) + z^j * v(z)
// Note, that no reduction modulo f(z) is required, because
// deg(u(z) + z^j * v(z)) <= max(deg(u(z)), j + deg(v(z)))
// = max(deg(u(z)), deg(u(z)) - deg(v(z)) + deg(v(z))
// = deg(u(z))
// uz = uz.xor(vz.shiftLeft(j));
// jInt = n / 32
int jInt = j >> 5;
// jInt = n % 32
int jBit = j & 0x1F;
IntArray vzShift = vz.shiftLeft(jBit);
uz.addShifted(vzShift, jInt);

// g1(z) := g1(z) + z^j * g2(z)
//                g1z = g1z.xor(g2z.shiftLeft(j));
IntArray g2zShift = g2z.shiftLeft(jBit);
g1z.addShifted(g2zShift, jInt);

}
return new ECFieldElement.F2m(
this.m, this.k1, this.k2, this.k3, g2z);
}

public ECFieldElement sqrt()
{
throw new RuntimeException("Not implemented");
}

/**
 * @return the representation of the field
 * <code>F<sub>2<sup>m</sup></sub></code>, either of
 * TPB (trinomial
 * basis representation) or
 * PPB (pentanomial
 * basis representation).
 */
public int getRepresentation()
{
return this.representation;
}

/**
 * @return the degree <code>m</code> of the reduction polynomial
 * <code>f(z)</code>.
 */
public int getM()
{
return this.m;
}

/**
 * @return TPB: The integer <code>k</code> where <code>x<sup>m</sup> +
 * x<sup>k</sup> + 1</code> represents the reduction polynomial
 * <code>f(z)</code>.<br>
 * PPB: The integer <code>k1</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.<br>
 */
public int getK1()
{
return this.k1;
}

/**
 * @return TPB: Always returns <code>0</code><br>
 * PPB: The integer <code>k2</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.<br>
 */
public int getK2()
{
return this.k2;
}

/**
 * @return TPB: Always set to <code>0</code><br>
 * PPB: The integer <code>k3</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.<br>
 */
public int getK3()
{
return this.k3;
}

public boolean equals(Object anObject)
{
if (anObject == this) 
{
return true;
}

if (!(anObject instanceof ECFieldElement.F2m)) 
{
return false;
}

ECFieldElement.F2m b = (ECFieldElement.F2m)anObject;

return ((this.m == b.m) && (this.k1 == b.k1) && (this.k2 == b.k2)
&& (this.k3 == b.k3)
&& (this.representation == b.representation)
&& (this.x.equals(b.x)));
}

public int hashCode()
{
return x.hashCode() ^ m ^ k1 ^ k2 ^ k3;
}
}
 */

/*
/**
 * Elliptic curve points over F2m
 */
public static class F2m extends ECPoint
{
  /**
   * @param curve base curve
   * @param x x point
   * @param y y point
   */
  public F2m(ECCurve curve, ECFieldElement x, ECFieldElement y)
  {
    this(curve, x, y, false);
  }
  
  /**
   * @param curve base curve
   * @param x x point
   * @param y y point
   * @param withCompression true if encode with point compression.
   */
  public F2m(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
  {
    super(curve, x, y);

    if ((x != null && y == null) || (x == null && y != null))
    {
      throw new IllegalArgumentException("Exactly one of the field elements is null");
    }
    
    if (x != null)
    {
      // Check if x and y are elements of the same field
      ECFieldElement.F2m.checkFieldElements(this.x, this.y);
      
      // Check if x and a are elements of the same field
      if (curve != null)
      {
        ECFieldElement.F2m.checkFieldElements(this.x, this.curve.getA());
      }
    }
    
    this.withCompression = withCompression;
  }

  /* (non-Javadoc)
   * @see org.bouncycastle.math.ec.ECPoint#getEncoded()
   */
  public byte[] getEncoded(boolean compressed)
  {
    if (this.isInfinity()) 
    {
      return new byte[1];
    }

    int byteCount = converter.getByteLength(this.x);
    byte[] X = converter.integerToBytes(this.getX().toBigInteger(), byteCount);
    byte[] PO;

    if (compressed)
    {
      // See X9.62 4.3.6 and 4.2.2
      PO = new byte[byteCount + 1];

      PO[0] = 0x02;
      // X9.62 4.2.2 and 4.3.6:
      // if x = 0 then ypTilde := 0, else ypTilde is the rightmost
      // bit of y * x^(-1)
      // if ypTilde = 0, then PC := 02, else PC := 03
      // Note: PC === PO[0]
      if (!(this.getX().toBigInteger().equals(ECConstants.ZERO)))
      {
        if (this.getY().multiply(this.getX().invert())
            .toBigInteger().testBit(0))
        {
          // ypTilde = 1, hence PC = 03
              PO[0] = 0x03;
        }
      }

      System.arraycopy(X, 0, PO, 1, byteCount);
    }
    else
    {
      byte[] Y = converter.integerToBytes(this.getY().toBigInteger(), byteCount);
      
      PO = new byte[byteCount + byteCount + 1];
      
      PO[0] = 0x04;
      System.arraycopy(X, 0, PO, 1, byteCount);
      System.arraycopy(Y, 0, PO, byteCount + 1, byteCount);    
    }

    return PO;
  }

  /**
   * Check, if two <code>ECPoint</code>s can be added or subtracted.
   * @param a The first <code>ECPoint</code> to check.
   * @param b The second <code>ECPoint</code> to check.
   * @throws IllegalArgumentException if <code>a</code> and <code>b</code>
   * cannot be added.
   */
  private static void checkPoints(ECPoint a, ECPoint b)
  {
    // Check, if points are on the same curve
    if (!(a.curve.equals(b.curve)))
    {
      throw new IllegalArgumentException("Only points on the same "
          + "curve can be added or subtracted");
    }

//            ECFieldElement.F2m.checkFieldElements(a.x, b.x);
  }

  /* (non-Javadoc)
   * @see org.bouncycastle.math.ec.ECPoint#add(org.bouncycastle.math.ec.ECPoint)
   */
  public ECPoint add(ECPoint b)
  {
    checkPoints(this, b);
    return addSimple((ECPoint.F2m)b);
  }

  /**
   * Adds another <code>ECPoints.F2m</code> to <code>this</code> without
   * checking if both points are on the same curve. Used by multiplication
   * algorithms, because there all points are a multiple of the same point
   * and hence the checks can be omitted.
   * @param b The other <code>ECPoints.F2m</code> to add to
   * <code>this</code>.
   * @return <code>this + b</code>
   */
  public ECPoint.F2m addSimple(ECPoint.F2m b)
  {
    ECPoint.F2m other = b;
    if (this.isInfinity())
    {
      return other;
    }

    if (other.isInfinity())
    {
      return this;
    }

    ECFieldElement.F2m x2 = (ECFieldElement.F2m)other.getX();
    ECFieldElement.F2m y2 = (ECFieldElement.F2m)other.getY();

    // Check if other = this or other = -this
        if (this.x.equals(x2))
        {
          if (this.y.equals(y2))
          {
            // this = other, i.e. this must be doubled
            return (ECPoint.F2m)this.twice();
          }

          // this = -other, i.e. the result is the point at infinity
          return (ECPoint.F2m)this.curve.getInfinity();
        }

        ECFieldElement.F2m lambda
        = (ECFieldElement.F2m)(this.y.add(y2)).divide(this.x.add(x2));

        ECFieldElement.F2m x3
        = (ECFieldElement.F2m)lambda.square().add(lambda).add(this.x).add(x2).add(this.curve.getA());

        ECFieldElement.F2m y3
        = (ECFieldElement.F2m)lambda.multiply(this.x.add(x3)).add(x3).add(this.y);

        return new ECPoint.F2m(curve, x3, y3, withCompression);
  }

  /* (non-Javadoc)
   * @see org.bouncycastle.math.ec.ECPoint#subtract(org.bouncycastle.math.ec.ECPoint)
   */
  public ECPoint subtract(ECPoint b)
  {
    checkPoints(this, b);
    return subtractSimple((ECPoint.F2m)b);
  }

  /**
   * Subtracts another <code>ECPoints.F2m</code> from <code>this</code>
   * without checking if both points are on the same curve. Used by
   * multiplication algorithms, because there all points are a multiple
   * of the same point and hence the checks can be omitted.
   * @param b The other <code>ECPoints.F2m</code> to subtract from
   * <code>this</code>.
   * @return <code>this - b</code>
   */
  public ECPoint.F2m subtractSimple(ECPoint.F2m b)
  {
    if (b.isInfinity())
    {
      return this;
    }

    // Add -b
    return addSimple((ECPoint.F2m)b.negate());
  }

  /* (non-Javadoc)
   * @see org.bouncycastle.math.ec.ECPoint#twice()
   */
  public ECPoint twice()
  {
    if (this.isInfinity()) 
    {
      // Twice identity element (point at infinity) is identity
      return this;
    }

    if (this.x.toBigInteger().signum() == 0) 
    {
      // if x1 == 0, then (x1, y1) == (x1, x1 + y1)
      // and hence this = -this and thus 2(x1, y1) == infinity
      return this.curve.getInfinity();
    }

    ECFieldElement.F2m lambda
    = (ECFieldElement.F2m)this.x.add(this.y.divide(this.x));

    ECFieldElement.F2m x3
    = (ECFieldElement.F2m)lambda.square().add(lambda).
    add(this.curve.getA());

    ECFieldElement ONE = this.curve.fromBigInteger(ECConstants.ONE);
    ECFieldElement.F2m y3
    = (ECFieldElement.F2m)this.x.square().add(
        x3.multiply(lambda.add(ONE)));

    return new ECPoint.F2m(this.curve, x3, y3, withCompression);
  }

  public ECPoint negate()
  {
    return new ECPoint.F2m(curve, this.getX(), this.getY().add(this.getX()), withCompression);
  }

  /**
   * Sets the appropriate <code>ECMultiplier</code>, unless already set. 
   */
  synchronized void assertECMultiplier()
  {
    if (this.multiplier == null)
    {
      if (((ECCurve.F2m)this.curve).isKoblitz())
      {
        this.multiplier = new WTauNafMultiplier();
      }
      else
      {
        this.multiplier = new WNafMultiplier();
      }
    }
  }
}
*/

/*
/**
 * Elliptic curves over F2m. The Weierstrass equation is given by
 * <code>y<sup>2</sup> + xy = x<sup>3</sup> + ax<sup>2</sup> + b</code>.
 */
public static class F2m extends ECCurve
{
/**
 * The exponent <code>m</code> of <code>F<sub>2<sup>m</sup></sub></code>.
 */
private int m;  // can't be final - JDK 1.1

/**
 * TPB: The integer <code>k</code> where <code>x<sup>m</sup> +
 * x<sup>k</sup> + 1</code> represents the reduction polynomial
 * <code>f(z)</code>.<br>
 * PPB: The integer <code>k1</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.<br>
 */
private int k1;  // can't be final - JDK 1.1

/**
 * TPB: Always set to <code>0</code><br>
 * PPB: The integer <code>k2</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.<br>
 */
private int k2;  // can't be final - JDK 1.1

/**
 * TPB: Always set to <code>0</code><br>
 * PPB: The integer <code>k3</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.<br>
 */
private int k3;  // can't be final - JDK 1.1

/**
 * The order of the base point of the curve.
 */
private BigInteger n;  // can't be final - JDK 1.1

/**
 * The cofactor of the curve.
 */
private BigInteger h;  // can't be final - JDK 1.1

/**
 * The point at infinity on this curve.
 */
private ECPoint.F2m infinity;  // can't be final - JDK 1.1

/**
 * The parameter <code>&mu;</code> of the elliptic curve if this is
 * a Koblitz curve.
 */
private byte mu = 0;

/**
 * The auxiliary values <code>s<sub>0</sub></code> and
 * <code>s<sub>1</sub></code> used for partial modular reduction for
 * Koblitz curves.
 */
private BigInteger[] si = null;

/**
 * Constructor for Trinomial Polynomial Basis (TPB).
 * @param m  The exponent <code>m</code> of
 * <code>F<sub>2<sup>m</sup></sub></code>.
 * @param k The integer <code>k</code> where <code>x<sup>m</sup> +
 * x<sup>k</sup> + 1</code> represents the reduction
 * polynomial <code>f(z)</code>.
 * @param a The coefficient <code>a</code> in the Weierstrass equation
 * for non-supersingular elliptic curves over
 * <code>F<sub>2<sup>m</sup></sub></code>.
 * @param b The coefficient <code>b</code> in the Weierstrass equation
 * for non-supersingular elliptic curves over
 * <code>F<sub>2<sup>m</sup></sub></code>.
 */
public F2m(
int m,
int k,
BigInteger a,
BigInteger b)
{
this(m, k, 0, 0, a, b, null, null);
}

/**
 * Constructor for Trinomial Polynomial Basis (TPB).
 * @param m  The exponent <code>m</code> of
 * <code>F<sub>2<sup>m</sup></sub></code>.
 * @param k The integer <code>k</code> where <code>x<sup>m</sup> +
 * x<sup>k</sup> + 1</code> represents the reduction
 * polynomial <code>f(z)</code>.
 * @param a The coefficient <code>a</code> in the Weierstrass equation
 * for non-supersingular elliptic curves over
 * <code>F<sub>2<sup>m</sup></sub></code>.
 * @param b The coefficient <code>b</code> in the Weierstrass equation
 * for non-supersingular elliptic curves over
 * <code>F<sub>2<sup>m</sup></sub></code>.
 * @param n The order of the main subgroup of the elliptic curve.
 * @param h The cofactor of the elliptic curve, i.e.
 * <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>.
 */
public F2m(
int m, 
int k, 
BigInteger a, 
BigInteger b,
BigInteger n,
BigInteger h)
{
this(m, k, 0, 0, a, b, n, h);
}

/**
 * Constructor for Pentanomial Polynomial Basis (PPB).
 * @param m  The exponent <code>m</code> of
 * <code>F<sub>2<sup>m</sup></sub></code>.
 * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.
 * @param k2 The integer <code>k2</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.
 * @param k3 The integer <code>k3</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.
 * @param a The coefficient <code>a</code> in the Weierstrass equation
 * for non-supersingular elliptic curves over
 * <code>F<sub>2<sup>m</sup></sub></code>.
 * @param b The coefficient <code>b</code> in the Weierstrass equation
 * for non-supersingular elliptic curves over
 * <code>F<sub>2<sup>m</sup></sub></code>.
 */
public F2m(
int m,
int k1,
int k2,
int k3,
BigInteger a,
BigInteger b)
{
this(m, k1, k2, k3, a, b, null, null);
}

/**
 * Constructor for Pentanomial Polynomial Basis (PPB).
 * @param m  The exponent <code>m</code> of
 * <code>F<sub>2<sup>m</sup></sub></code>.
 * @param k1 The integer <code>k1</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.
 * @param k2 The integer <code>k2</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.
 * @param k3 The integer <code>k3</code> where <code>x<sup>m</sup> +
 * x<sup>k3</sup> + x<sup>k2</sup> + x<sup>k1</sup> + 1</code>
 * represents the reduction polynomial <code>f(z)</code>.
 * @param a The coefficient <code>a</code> in the Weierstrass equation
 * for non-supersingular elliptic curves over
 * <code>F<sub>2<sup>m</sup></sub></code>.
 * @param b The coefficient <code>b</code> in the Weierstrass equation
 * for non-supersingular elliptic curves over
 * <code>F<sub>2<sup>m</sup></sub></code>.
 * @param n The order of the main subgroup of the elliptic curve.
 * @param h The cofactor of the elliptic curve, i.e.
 * <code>#E<sub>a</sub>(F<sub>2<sup>m</sup></sub>) = h * n</code>.
 */
public F2m(
int m, 
int k1, 
int k2, 
int k3,
BigInteger a, 
BigInteger b,
BigInteger n,
BigInteger h)
{
this.m = m;
this.k1 = k1;
this.k2 = k2;
this.k3 = k3;
this.n = n;
this.h = h;

if (k1 == 0)
{
throw new IllegalArgumentException("k1 must be > 0");
}

if (k2 == 0)
{
if (k3 != 0)
{
throw new IllegalArgumentException("k3 must be 0 if k2 == 0");
}
}
else
{
if (k2 <= k1)
{
throw new IllegalArgumentException("k2 must be > k1");
}

if (k3 <= k2)
{
throw new IllegalArgumentException("k3 must be > k2");
}
}

this.a = fromBigInteger(a);
this.b = fromBigInteger(b);
this.infinity = new ECPoint.F2m(this, null, null);
}

public int getFieldSize()
{
return m;
}

public ECFieldElement fromBigInteger(BigInteger x)
{
return new ECFieldElement.F2m(this.m, this.k1, this.k2, this.k3, x);
}

public ECPoint createPoint(BigInteger x, BigInteger y, boolean withCompression)
{
return new ECPoint.F2m(this, fromBigInteger(x), fromBigInteger(y), withCompression);
}

public ECPoint getInfinity()
{
return infinity;
}

/**
 * Returns true if this is a Koblitz curve (ABC curve).
 * @return true if this is a Koblitz curve (ABC curve), false otherwise
 */
public boolean isKoblitz()
{
return ((n != null) && (h != null) &&
((a.toBigInteger().equals(ECConstants.ZERO)) ||
(a.toBigInteger().equals(ECConstants.ONE))) &&
(b.toBigInteger().equals(ECConstants.ONE)));
}

/**
 * Returns the parameter <code>&mu;</code> of the elliptic curve.
 * @return <code>&mu;</code> of the elliptic curve.
 * @throws IllegalArgumentException if the given ECCurve is not a
 * Koblitz curve.
 */
synchronized byte getMu()
{
if (mu == 0)
{
mu = Tnaf.getMu(this);
}
return mu;
}

/**
 * @return the auxiliary values <code>s<sub>0</sub></code> and
 * <code>s<sub>1</sub></code> used for partial modular reduction for
 * Koblitz curves.
 */
synchronized BigInteger[] getSi()
{
if (si == null)
{
si = Tnaf.getSi(this);
}
return si;
}

/**
 * Decompresses a compressed point P = (xp, yp) (X9.62 s 4.2.2).
 * 
 * @param yTilde
 *            ~yp, an indication bit for the decompression of yp.
 * @param X1
 *            The field element xp.
 * @return the decompressed point.
 */
protected ECPoint decompressPoint(int yTilde, BigInteger X1)
{
ECFieldElement xp = fromBigInteger(X1);
ECFieldElement yp = null;
if (xp.toBigInteger().equals(ECConstants.ZERO))
{
yp = (ECFieldElement.F2m)b;
for (int i = 0; i < m - 1; i++)
{
yp = yp.square();
}
}
else
{
ECFieldElement beta = xp.add(a).add(b.multiply(xp.square().invert()));
ECFieldElement z = solveQuadradicEquation(beta);
if (z == null)
{
throw new IllegalArgumentException("Invalid point compression");
}
int zBit = z.toBigInteger().testBit(0) ? 1 : 0;
if (zBit != yTilde)
{
z = z.add(fromBigInteger(ECConstants.ONE));
}
yp = xp.multiply(z);
}

return new ECPoint.F2m(this, xp, yp, true);
}

/**
 * Solves a quadratic equation <code>z<sup>2</sup> + z = beta</code>(X9.62
 * D.1.6) The other solution is <code>z + 1</code>.
 * 
 * @param beta
 *            The value to solve the qradratic equation for.
 * @return the solution for <code>z<sup>2</sup> + z = beta</code> or
 *         <code>null</code> if no solution exists.
 */
private ECFieldElement solveQuadradicEquation(ECFieldElement beta)
{
ECFieldElement zeroElement = new ECFieldElement.F2m(
this.m, this.k1, this.k2, this.k3, ECConstants.ZERO);

if (beta.toBigInteger().equals(ECConstants.ZERO))
{
return zeroElement;
}

ECFieldElement z = null;
ECFieldElement gamma = zeroElement;

Random rand = new Random();
do
{
ECFieldElement t = new ECFieldElement.F2m(this.m, this.k1,
this.k2, this.k3, new BigInteger(m, rand));
z = zeroElement;
ECFieldElement w = beta;
for (int i = 1; i <= m - 1; i++)
{
ECFieldElement w2 = w.square();
z = z.square().add(w2.multiply(t));
w = w2.add(beta);
}
if (!w.toBigInteger().equals(ECConstants.ZERO))
{
return null;
}
gamma = z.square().add(z);
}
while (gamma.toBigInteger().equals(ECConstants.ZERO));

return z;
}

public boolean equals(
Object anObject)
{
if (anObject == this) 
{
return true;
}

if (!(anObject instanceof ECCurve.F2m)) 
{
return false;
}

ECCurve.F2m other = (ECCurve.F2m)anObject;

return (this.m == other.m) && (this.k1 == other.k1)
&& (this.k2 == other.k2) && (this.k3 == other.k3)
&& a.equals(other.a) && b.equals(other.b);
}

public int hashCode()
{
return this.a.hashCode() ^ this.b.hashCode() ^ m ^ k1 ^ k2 ^ k3;
}

public int getM()
{
return m;
}

/**
 * Return true if curve uses a Trinomial basis.
 * 
 * @return true if curve Trinomial, false otherwise.
 */
public boolean isTrinomial()
{
return k2 == 0 && k3 == 0;
}

public int getK1()
{
return k1;
}

public int getK2()
{
return k2;
}

public int getK3()
{
return k3;
}

public BigInteger getN()
{
return n;
}

public BigInteger getH()
{
return h;
}
}
*/
*/
