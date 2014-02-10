// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.key_generators.rsa_key_generator;

import "package:bignum/bignum.dart";

import "package:cipher/api.dart";
import "package:cipher/api/rsa.dart";
import "package:cipher/params/parameters_with_random.dart";
import "package:cipher/params/key_generators/rsa_key_generator_parameters.dart";

class RSAKeyGenerator implements KeyGenerator {

  SecureRandom _random;
  RSAKeyGeneratorParameters _params;

  String get algorithmName => "RSA";

  @override
  void init(CipherParameters params) {
    if( params is ParametersWithRandom ) {
      _random = params.random;
      _params = params.parameters;
    } else {
      _random = new SecureRandom();
      _params = params;
    }

    if (_params.bitStrength < 12) {
      throw new ArgumentError("key bit strength cannot be smaller than 12");
    }

    if (!_params.publicExponent.testBit(0)) {
      throw new ArgumentError("Public exponent cannot be even");
    }
  }

  AsymmetricKeyPair generateKeyPair() {
    var p, q, n, e;

    // p and q values should have a length of half the strength in bits
    var strength = _params.bitStrength;
    var pbitlength = (strength + 1) ~/ 2;
    var qbitlength = strength - pbitlength;
    var mindiffbits = strength ~/ 3;

    e = _params.publicExponent;

    // TODO Consider generating safe primes for p, q (see DHParametersHelper.generateSafePrimes)
    // (then p-1 and q-1 will not consist of only small factors - see "Pollard's algorithm")

    // generate p, prime and (p-1) relatively prime to e
    for ( ; ; ) {
      p = generateProbablePrime(pbitlength, 1, _random);

      if (p.mod(e) == 1) {
        continue;
      }

      if (!p.isProbablePrime(_params.certainty)) {
        continue;
      }

      if (e.gcd(p - BigInteger.ONE) == 1) {
        break;
      }
    }

    // generate a modulus of the required length
    for ( ; ; ) {

      // generate q, prime and (q-1) relatively prime to e, and not equal to p
      for (;;) {
        q = generateProbablePrime(pbitlength, 1, _random);

        if ((q - p).abs().bitLength() < mindiffbits) {
          continue;
        }

        if (q.mod(e) == 1) {
          continue;
        }

        if (!q.isProbablePrime(_params.certainty)) {
          continue;
        }

        if (e.gcd(q - BigInteger.ONE) == 1) {
          break;
        }
      }

      // calculate the modulus
      n = p.multiply(q);

      if (n.bitLength() == _params.bitStrength) {
        break;
      }

      // if we get here our primes aren't big enough, make the largest of the two p and try again
      p = p.max(q);
    }

    // Swap p and q if necessary
    if (p < q) {
      var swap = p;
      p = q;
      q = swap;
    }

    // calculate the private exponent
    var pSub1 = (p - BigInteger.ONE);
    var qSub1 = (q - BigInteger.ONE);
    var phi = (pSub1 * qSub1);
    var d = e.modInverse(phi);

    return new AsymmetricKeyPair(new RSAPublicKey(n, e), new RSAPrivateKey(n, d, p, q));
  }

}

BigInteger generateProbablePrime(int bitLength, int certainty, SecureRandom rnd) {
  var candidate;

  if(bitLength < 2) {
    candidate = new BigInteger(1);
  } else {
    candidate = rnd.nextBigInteger(bitLength); //this.fromNumber(bitLength, rnd, null);
    if (!candidate.testBit(bitLength-1)) {  // force MSB set
      candidate.bitwiseTo(BigInteger.ONE.shiftLeft(bitLength-1), (x,y) => x|y, candidate); // "(x,y) => x|y" ==> "op_or"
    }
    if (candidate.isEven()) {
      candidate.dAddOffset(1,0); // force odd
    }
    //print("{");
    while (!candidate.isProbablePrime(certainty)) {
      //print("==> candidate: "+candidate.toString());
      candidate.dAddOffset(2,0);
      if (candidate.bitLength() > bitLength) {
        candidate.subTo(BigInteger.ONE.shiftLeft(bitLength-1), candidate);
      }
    }
    //print("}");
  }

  return candidate;
}

//  fromNumber(a,b,c) {
//    //if("number" == typeof b) {
//    if (b is num || b is int || b is double) {
//      // new BigInteger(int,int,RNG)
//      if(a < 2) {
//        this.fromInt(1);
//      } else {
//        this.fromNumber(a,c, null);
//        if(!this.testBit(a-1))  // force MSB set
//          this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
//        if(this.isEven()) this.dAddOffset(1,0); // force odd
//        while(!this.isProbablePrime(b)) {
//          this.dAddOffset(2,0);
//          if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
//        }
//      }
//    }
//    else {
//      // new BigInteger(int,RNG)
//      var x = new Map();
//      StringBuffer sb = new StringBuffer();
//      //x[0] = 0;
//      var t = a & 7;
//      // x.length = (a>>3)+1; // TODO: do we really need to set the length for the Array when using something like map?
//      if(t > 0) {
//        x[0] = ((1<<t)-1);
//      } else {
//        x[0] = 0;
//      }
//
//      this.fromString(x,256);
//    }
//  }


/*
BigInteger generateProbablePrime(int bitLength, int certainty, SecureRandom rnd) {
  if (bitLength < 2) {
    throw new ArgumentError("Bit length must be at least 2");
  }

  BigInteger p = new BigInteger(bitLength, rnd).setBit(bitLength-1);
  p.array[p.array.data.length-1] &= 0xfffffffe; //p.mag[p.mag.length-1] &= 0xfffffffe;

  // Use a sieve length likely to contain the next prime number
  int searchLen = (bitLength ~/ 20) * 64;
  BitSieve searchSieve = new BitSieve(p, searchLen);
  BigInteger candidate = searchSieve.retrieve(p, certainty, rnd);

  while ((candidate == null) || (candidate.bitLength() != bitLength)) {
      p = p.add(new BigInteger(2*searchLen));
      if (p.bitLength() != bitLength) {
        p = new BigInteger(bitLength, rnd).setBit(bitLength-1);
      }
      p.array[p.array.data.length-1] &= 0xfffffffe; //p.mag[p.mag.length-1] &= 0xfffffffe;
      searchSieve = new BitSieve(p, searchLen);
      candidate = searchSieve.retrieve(p, certainty, rnd);
  }
  return candidate;
}

class BitSieve {
    /**
     * Stores the bits in this bitSieve.
     */
    List<Uint64> bits;

    /**
     * Length is how many bits this sieve holds.
     */
    int length;

    /**
     * A small sieve used to filter out multiples of small primes in a search
     * sieve.
     */
    static BitSieve smallSieve = new BitSieve();

    /**
     * Construct a "small sieve" with a base of 0.  This constructor is
     * used internally to generate the set of "small primes" whose multiples
     * are excluded from sieves generated by the main (package private)
     * constructor, BitSieve(BigInteger base, int searchLen).  The length
     * of the sieve generated by this constructor was chosen for performance;
     * it controls a tradeoff between how much time is spent constructing
     * other sieves, and how much time is wasted testing composite candidates
     * for primality.  The length was chosen experimentally to yield good
     * performance.
     */
    /*
    BitSieve() {
        length = 150 * 64;
        bits = new long[(unitIndex(length - 1) + 1)];

        // Mark 1 as composite
        set(0);
        int nextIndex = 1;
        int nextPrime = 3;

        // Find primes and remove their multiples from sieve
        do {
            sieveSingle(length, nextIndex + nextPrime, nextPrime);
            nextIndex = sieveSearch(length, nextIndex + 1);
            nextPrime = 2*nextIndex + 1;
        } while((nextIndex > 0) && (nextPrime < length));
    }
*/
    /**
     * Construct a bit sieve of searchLen bits used for finding prime number
     * candidates. The new sieve begins at the specified base, which must
     * be even.
     */
    BitSieve(BigInteger base, int searchLen) {
      /*
       * Candidates are indicated by clear bits in the sieve. As a candidates
       * nonprimality is calculated, a bit is set in the sieve to eliminate
       * it. To reduce storage space and increase efficiency, no even numbers
       * are represented in the sieve (each bit in the sieve represents an
       * odd number).
       */
      bits = new List<Uint64>(unitIndex(searchLen-1) + 1);
      length = searchLen;
      int start = 0;

      int step = smallSieve.sieveSearch(smallSieve.length, start);
      int convertedStep = (step *2) + 1;

      // Construct the large sieve at an even offset specified by base
      BigInteger b = new BigInteger(base);
      BigInteger q = new BigInteger();
      do {
        // Calculate base mod convertedStep
        start = b.divideOneWord(convertedStep, q);

        // Take each multiple of step out of sieve
        start = convertedStep - start;
        if (start%2 == 0)
            start += convertedStep;
        sieveSingle(searchLen, (start-1)/2, convertedStep);

        // Find next prime from small sieve
        step = smallSieve.sieveSearch(smallSieve.length, step+1);
        convertedStep = (step *2) + 1;
      } while (step > 0);
    }

    /**
     * Given a bit index return unit index containing it.
     */
    int unitIndex(int bitIndex) {
      return bitIndex >> 6;
    }

    /**
     * Return a unit that masks the specified bit in its unit.
     */
    Uint64 bit(int bitIndex) {
      return new Uint64(1) << (bitIndex & ((1<<6) - 1));
    }

    /**
     * Get the value of the bit at the specified index.
     */
    bool get(int bitIndex) {
      int unitIndex = unitIndex(bitIndex);
      return ((bits[unitIndex] & bit(bitIndex)) != 0);
    }

    /**
     * Set the bit at the specified index.
     */
    void set(int bitIndex) {
      int unitIndex = unitIndex(bitIndex);
      bits[unitIndex] |= bit(bitIndex);
    }

    /**
     * This method returns the index of the first clear bit in the search
     * array that occurs at or after start. It will not search past the
     * specified limit. It returns -1 if there is no such clear bit.
     */
    int sieveSearch(int limit, int start) {
      if (start >= limit) {
        return -1;
      }

      int index = start;
      do {
        if (!get(index)) {
          return index;
        }
        index++;
      } while(index < limit-1);
      return -1;
    }

    /**
     * Sieve a single set of multiples out of the sieve. Begin to remove
     * multiples of the specified step starting at the specified start index,
     * up to the specified limit.
     */
    void sieveSingle(int limit, int start, int step) {
      while(start < limit) {
        set(start);
        start += step;
      }
    }

    /**
     * Test probable primes in the sieve and return successful candidates.
     */
    BigInteger retrieve(BigInteger initValue, int certainty, SecureRandom random) {
      // Examine the sieve one long at a time to find possible primes
      int offset = 1;
      for (int i=0; i<bits.length; i++) {
        Uint64 nextLong = ~bits[i];
        for (int j=0; j<64; j++) {
            if ((nextLong & 1) == 1) {
                BigInteger candidate = initValue.add(new BigInteger(offset));
                if (primeToCertainty(candidate, certainty, random))
                    return candidate;
            }
            nextLong >>= 1;
            offset+=2;
        }
      }
      return null;
    }

    boolean primeToCertainty(BigInteger candidate, int certainty, Random random) {
      int rounds = 0;
      int n = (min(certainty, 0x7fffffff-1)+1)~/2;

      // The relationship between the certainty and the number of rounds
      // we perform is given in the draft standard ANSI X9.80, "PRIME
      // NUMBER GENERATION, PRIMALITY TESTING, AND PRIMALITY CERTIFICATES".
      int sizeInBits = candidate.bitLength();
      if (sizeInBits < 100) {
          rounds = 50;
          rounds = n < rounds ? n : rounds;
          return candidate.millerRabin(rounds);// passesMillerRabin(rounds, random);
      }

      if (sizeInBits < 256) {
          rounds = 27;
      } else if (sizeInBits < 512) {
          rounds = 15;
      } else if (sizeInBits < 768) {
          rounds = 8;
      } else if (sizeInBits < 1024) {
          rounds = 4;
      } else {
          rounds = 2;
      }
      rounds = n < rounds ? n : rounds;

      return candidate.millerRabin(rounds);//passesMillerRabin(rounds, random) && passesLucasLehmer();
    }

    bool passesLucasLehmer() {
        BigInteger thisPlusOne = this.add(ONE);

        // Step 1
        int d = 5;
        while (jacobiSymbol(d, this) != -1) {
            // 5, -7, 9, -11, ...
            d = (d<0) ? Math.abs(d)+2 : -(d+2);
        }

        // Step 2
        BigInteger u = lucasLehmerSequence(d, thisPlusOne, this);

        // Step 3
        return u.mod(this).equals(ZERO);
    }
}
*/


















