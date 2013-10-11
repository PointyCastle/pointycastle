library cipher_engines_aes_fast;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/params/key_parameter.dart";
import "package:cipher/src/util.dart";

part "../src/engines/aes_fast/tables.dart";
part "../src/engines/aes_fast/functions.dart";
part "../src/engines/aes_fast/words_2d_matrix.dart";

/**
 * An implementation of the AES (Rijndael), from FIPS-197.
 *
 * For further details see: [http://csrc.nist.gov/encryption/aes/]
 *
 * This implementation is based on optimizations from Dr. Brian Gladman's paper
 * and C code at [http://fp.gladman.plus.com/cryptography_technology/rijndael/]
 *
 * There are three levels of tradeoff of speed vs memory and they are written
 * as three separate classes from which to choose.
 *
 * The fastest uses 8Kbytes of static tables to precompute round calculations,
 * 4 256 word tables for encryption and 4 for decryption.
 *
 * The middle performance version uses only one 256 word table for each, for a
 * total of 2Kbytes, adding 12 rotate operations per round to compute the values
 * contained in the other tables from the contents of the first.
 *
 * The slowest version uses no static tables at all and computes the values in
 * each round.

 * This file contains the fast version with 8Kbytes of static tables for round
 * precomputation.
 */
class AESFastEngine implements BlockCipher {

  static const _BLOCK_SIZE = 16;

  bool _forEncryption;
  _Words2dMatrix _workingKey;
  int _ROUNDS;
  int _C0, _C1, _C2, _C3;

  String get algorithmName => "AES";

  int get blockSize => _BLOCK_SIZE;

  void reset() {
    _ROUNDS = 0;
    _C0 = _C1 = _C2 = _C3 = 0;
    _forEncryption = false;
    _workingKey = null;
  }

  /**
   * initialise an AES cipher.
   * Calculate the necessary round keys
   * The number of calculations depends on key size and block size
   * AES specified a fixed block size of 128 bits and key sizes 128/192/256 bits
   * This code is written assuming those are the only possible values
   *
   * @param forEncryption whether or not we are for encryption.
   * @param params the parameters required to set up the cipher.
   * @exception IllegalArgumentException if the params argument is
   * inappropriate.
   */
  void init( bool forEncryption, KeyParameter params ) {
    var key = params.key;

    int KC = (key.lengthInBytes / 4).floor();  // key length in words
    if (((KC != 4) && (KC != 6) && (KC != 8)) || ((KC * 4) != key.lengthInBytes)) {
      throw new ArgumentError("Key length must be 128/192/256 bits");
    }

    this._forEncryption = forEncryption;
    _ROUNDS = KC + 6;  // This is not always true for the generalized Rijndael that allows larger block sizes
    _workingKey = new _Words2dMatrix(_ROUNDS+1,4); // 4 words in a block

    // copy the key into the round key array
    var keyView = new ByteData.view( params.key.buffer );
    for( var i=0, t=0 ; i<key.lengthInBytes ; i+=4, t++ ) {
      var value = keyView.getUint32( i, Endianness.LITTLE_ENDIAN );
      _workingKey.setWord( t>>2, t&3, value );
    }

    // while not enough round key material calculated calculate new values
    int k = (_ROUNDS + 1) << 2;
    for( int i=KC ; i<k ; i++ ) {
      int temp = _workingKey.getWord( (i-1)>>2, (i-1)&3 );
      if( (i%KC) == 0 ) {
        temp = _subWord( _shift(temp,8) ) ^ _rcon[((i / KC) - 1).floor()];
      } else if( (KC > 6) && ((i % KC) == 4) ) {
        temp = _subWord(temp);
      }

      var value = _workingKey.getWord( (i-KC)>>2, (i-KC)&3 ) ^ temp;
      _workingKey.setWord( i>>2, i&3, value);
    }

    if( !forEncryption ) {
      for( var j=1 ; j<_ROUNDS; j++ ) {
        for( var i=0 ; i<4; i++ ) {
          var value = _inv_mcol( _workingKey.getWord( j, i ) );
          _workingKey.setWord( j, i, value );
        }
      }
    }

    //print( "workingKey = ${workingKey}" );
  }

  int processBlock( Uint8List inp, int inpOff, Uint8List out, int outOff ) {

      if( _workingKey == null ) {
          throw new StateError("AES engine not initialised");
      }

      if( (inpOff + (32 / 2)) > inp.lengthInBytes ) {
          throw new ArgumentError("Input buffer too short");
      }

      if( (outOff + (32 / 2)) > out.lengthInBytes ) {
          throw new ArgumentError("Output buffer too short");
      }

      if (_forEncryption) {
          _unpackBlock(inp,inpOff);
          _encryptBlock(_workingKey);
          _packBlock(out,outOff);
      } else {
          _unpackBlock(inp,inpOff);
          _decryptBlock(_workingKey);
          _packBlock(out,outOff);
      }

      return _BLOCK_SIZE;

  }

  void _encryptBlock( _Words2dMatrix KW ) {
      int r, r0, r1, r2, r3;

      //print("before encrypt = $KW");
      //_printCs("pre");
      _C0 ^= KW.getWord( 0, 0 );
      _C1 ^= KW.getWord( 0, 1 );
      _C2 ^= KW.getWord( 0, 2 );
      _C3 ^= KW.getWord( 0, 3 );
      //_printCs("initial");

      r = 1;
      while( r < _ROUNDS-1 ) {
          r0  = _T0[_C0&255] ^ _T1[(_C1>>8)&255] ^ _T2[(_C2>>16)&255] ^ _T3[(_C3>>24)&255] ^ KW.getWord(r, 0);
          r1  = _T0[_C1&255] ^ _T1[(_C2>>8)&255] ^ _T2[(_C3>>16)&255] ^ _T3[(_C0>>24)&255] ^ KW.getWord(r, 1);
          r2  = _T0[_C2&255] ^ _T1[(_C3>>8)&255] ^ _T2[(_C0>>16)&255] ^ _T3[(_C1>>24)&255] ^ KW.getWord(r, 2);
          r3  = _T0[_C3&255] ^ _T1[(_C0>>8)&255] ^ _T2[(_C1>>16)&255] ^ _T3[(_C2>>24)&255] ^ KW.getWord(r, 3);
          r++;
          //_printRs("round $r", r0, r1, r2, r3);
          _C0 = _T0[r0&255] ^ _T1[(r1>>8)&255] ^ _T2[(r2>>16)&255] ^ _T3[(r3>>24)&255] ^ KW.getWord(r, 0);
          _C1 = _T0[r1&255] ^ _T1[(r2>>8)&255] ^ _T2[(r3>>16)&255] ^ _T3[(r0>>24)&255] ^ KW.getWord(r, 1);
          _C2 = _T0[r2&255] ^ _T1[(r3>>8)&255] ^ _T2[(r0>>16)&255] ^ _T3[(r1>>24)&255] ^ KW.getWord(r, 2);
          _C3 = _T0[r3&255] ^ _T1[(r0>>8)&255] ^ _T2[(r1>>16)&255] ^ _T3[(r2>>24)&255] ^ KW.getWord(r, 3);
          r++;
          //_printCs("round $r");
      }

      r0 = _T0[_C0&255] ^ _T1[(_C1>>8)&255] ^ _T2[(_C2>>16)&255] ^ _T3[(_C3>>24)&255] ^ KW.getWord(r, 0);
      r1 = _T0[_C1&255] ^ _T1[(_C2>>8)&255] ^ _T2[(_C3>>16)&255] ^ _T3[(_C0>>24)&255] ^ KW.getWord(r, 1);
      r2 = _T0[_C2&255] ^ _T1[(_C3>>8)&255] ^ _T2[(_C0>>16)&255] ^ _T3[(_C1>>24)&255] ^ KW.getWord(r, 2);
      r3 = _T0[_C3&255] ^ _T1[(_C0>>8)&255] ^ _T2[(_C1>>16)&255] ^ _T3[(_C2>>24)&255] ^ KW.getWord(r, 3);
      r++;

      // the final round's table is a simple function of S so we don't use a whole other four tables for it
      _C0 = (_S[r0&255]&255) ^ ((_S[(r1>>8)&255]&255)<<8) ^ ((_S[(r2>>16)&255]&255)<<16) ^ (_S[(r3>>24)&255]<<24) ^ KW.getWord(r, 0);
      _C1 = (_S[r1&255]&255) ^ ((_S[(r2>>8)&255]&255)<<8) ^ ((_S[(r3>>16)&255]&255)<<16) ^ (_S[(r0>>24)&255]<<24) ^ KW.getWord(r, 1);
      _C2 = (_S[r2&255]&255) ^ ((_S[(r3>>8)&255]&255)<<8) ^ ((_S[(r0>>16)&255]&255)<<16) ^ (_S[(r1>>24)&255]<<24) ^ KW.getWord(r, 2);
      _C3 = (_S[r3&255]&255) ^ ((_S[(r0>>8)&255]&255)<<8) ^ ((_S[(r1>>16)&255]&255)<<16) ^ (_S[(r2>>24)&255]<<24) ^ KW.getWord(r, 3);
      //_printCs("final round");
  }

  void _decryptBlock( _Words2dMatrix KW ) {
      int r, r0, r1, r2, r3;

      _C0 ^= KW.getWord(_ROUNDS,0);
      _C1 ^= KW.getWord(_ROUNDS,1);
      _C2 ^= KW.getWord(_ROUNDS,2);
      _C3 ^= KW.getWord(_ROUNDS,3);

      r = _ROUNDS-1;
      while( r > 1 ) {
          r0 = _Tinv0[_C0&255] ^ _Tinv1[(_C3>>8)&255] ^ _Tinv2[(_C2>>16)&255] ^ _Tinv3[(_C1>>24)&255] ^ KW.getWord(r, 0);
          r1 = _Tinv0[_C1&255] ^ _Tinv1[(_C0>>8)&255] ^ _Tinv2[(_C3>>16)&255] ^ _Tinv3[(_C2>>24)&255] ^ KW.getWord(r, 1);
          r2 = _Tinv0[_C2&255] ^ _Tinv1[(_C1>>8)&255] ^ _Tinv2[(_C0>>16)&255] ^ _Tinv3[(_C3>>24)&255] ^ KW.getWord(r, 2);
          r3 = _Tinv0[_C3&255] ^ _Tinv1[(_C2>>8)&255] ^ _Tinv2[(_C1>>16)&255] ^ _Tinv3[(_C0>>24)&255] ^ KW.getWord(r, 3);
          r--;
          _C0 = _Tinv0[r0&255] ^ _Tinv1[(r3>>8)&255] ^ _Tinv2[(r2>>16)&255] ^ _Tinv3[(r1>>24)&255] ^ KW.getWord(r, 0);
          _C1 = _Tinv0[r1&255] ^ _Tinv1[(r0>>8)&255] ^ _Tinv2[(r3>>16)&255] ^ _Tinv3[(r2>>24)&255] ^ KW.getWord(r, 1);
          _C2 = _Tinv0[r2&255] ^ _Tinv1[(r1>>8)&255] ^ _Tinv2[(r0>>16)&255] ^ _Tinv3[(r3>>24)&255] ^ KW.getWord(r, 2);
          _C3 = _Tinv0[r3&255] ^ _Tinv1[(r2>>8)&255] ^ _Tinv2[(r1>>16)&255] ^ _Tinv3[(r0>>24)&255] ^ KW.getWord(r, 3);
          r--;
      }

      r0 = _Tinv0[_C0&255] ^ _Tinv1[(_C3>>8)&255] ^ _Tinv2[(_C2>>16)&255] ^ _Tinv3[(_C1>>24)&255] ^ KW.getWord(r, 0);
      r1 = _Tinv0[_C1&255] ^ _Tinv1[(_C0>>8)&255] ^ _Tinv2[(_C3>>16)&255] ^ _Tinv3[(_C2>>24)&255] ^ KW.getWord(r, 1);
      r2 = _Tinv0[_C2&255] ^ _Tinv1[(_C1>>8)&255] ^ _Tinv2[(_C0>>16)&255] ^ _Tinv3[(_C3>>24)&255] ^ KW.getWord(r, 2);
      r3 = _Tinv0[_C3&255] ^ _Tinv1[(_C2>>8)&255] ^ _Tinv2[(_C1>>16)&255] ^ _Tinv3[(_C0>>24)&255] ^ KW.getWord(r, 3);

      // the final round's table is a simple function of Si so we don't use a whole other four tables for it
      _C0 = (_Si[r0&255]&255) ^ ((_Si[(r3>>8)&255]&255)<<8) ^ ((_Si[(r2>>16)&255]&255)<<16) ^ (_Si[(r1>>24)&255]<<24) ^ KW.getWord(0, 0);
      _C1 = (_Si[r1&255]&255) ^ ((_Si[(r0>>8)&255]&255)<<8) ^ ((_Si[(r3>>16)&255]&255)<<16) ^ (_Si[(r2>>24)&255]<<24) ^ KW.getWord(0, 1);
      _C2 = (_Si[r2&255]&255) ^ ((_Si[(r1>>8)&255]&255)<<8) ^ ((_Si[(r0>>16)&255]&255)<<16) ^ (_Si[(r3>>24)&255]<<24) ^ KW.getWord(0, 2);
      _C3 = (_Si[r3&255]&255) ^ ((_Si[(r2>>8)&255]&255)<<8) ^ ((_Si[(r1>>16)&255]&255)<<16) ^ (_Si[(r0>>24)&255]<<24) ^ KW.getWord(0, 3);
  }

  void _unpackBlock( Uint8List bytes, int off ) {
    var bytesView = new ByteData.view( bytes.buffer );
    _C0 = bytesView.getUint32( off, Endianness.LITTLE_ENDIAN );
    _C1 = bytesView.getUint32( off+4, Endianness.LITTLE_ENDIAN );
    _C2 = bytesView.getUint32( off+8, Endianness.LITTLE_ENDIAN );
    _C3 = bytesView.getUint32( off+12, Endianness.LITTLE_ENDIAN );
    //_printCs("unpackBlock");
  }

  void _packBlock( Uint8List bytes, int off ) {
    var bytesView = new ByteData.view( bytes.buffer );
    //_printCs("packBlock");
    bytesView.setUint32( off, _C0, Endianness.LITTLE_ENDIAN );
    bytesView.setUint32( off+4, _C1, Endianness.LITTLE_ENDIAN );
    bytesView.setUint32( off+8, _C2, Endianness.LITTLE_ENDIAN );
    bytesView.setUint32( off+12, _C3, Endianness.LITTLE_ENDIAN );
  }

  /*
  void _printCs( String desc ) {
    print("Cs ($desc): ${_wordToHex(_C0)} ${_wordToHex(_C1)} ${_wordToHex(_C2)} ${_wordToHex(_C3)}");
  }

  void _printRs( String desc, int r0, int r1, int r2, int r3 ) {
    print("Rs ($desc): ${_wordToHex(r0)} ${_wordToHex(r1)} ${_wordToHex(r2)} ${_wordToHex(r3)}");
  }

  String _wordToHex( int val ) {
    var bytes = new ByteData(4);
    bytes.setUint32(0, val, Endianness.LITTLE_ENDIAN);
    var sb = new StringBuffer();
    for( int i=0 ; i<4 ; i++ ) {
      var b = bytes.getUint8(i);
      if( b<16 ) {
        sb.write("0");
      }
      sb.write( b.toRadixString(16) );
    }
    return sb.toString();
  }
  */

}

