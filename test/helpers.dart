library cipher_test_helpers;

import "dart:typed_data";

import "package:cipher/api.dart";

String toHumanSize( num size ) {
  if( size<1024 ) return "$size B"; 
  if( size<1024*1024 ) return "${_format(size/1024)} KB"; 
  if( size<1024*1024*1024 ) return "${_format(size/(1024*1024))} MB"; 
  return "${_format(size/(1024*1024*1024))} GB"; 
}

String _format( double val ) { 
  if( val.isInfinite ) {
    return "INF";
  } else if( val.isNaN ) {
    return "NaN";
  } else {
    return val.floor().toString()+"."+(100*(val-val.toInt())).toInt().toString();
  }
}

Uint8List asUint8List_ListOfInt( List<int> bytes ) {
  var data = new Uint8List(bytes.length);
  for( var i=0 ; i<bytes.length ; i++ ) {
    data[i] = bytes[i];
  }
  return data;
}

Uint8List asUint8List_String( String s ) {
  var ret = new Uint8List(s.length);
  for( var i=0 ; i<s.length ; i++ ) {
    ret[i] = s.codeUnitAt(i);
  }
  return ret;
}

Uint8List createSequentialInput( int len ) {
  var ret = new Uint8List(len);
  for( var i=0 ; i<len ; i++ ) {
    ret[i] = i;
  }
  return ret;
}

Uint8List processBlocks( BlockCipher cipher, Uint8List inp ) {
  var out = new Uint8List(inp.lengthInBytes);
  for( var offset=0 ; offset<inp.lengthInBytes ; offset+=cipher.blockSize ) {
    cipher.processBlock( inp, offset, out, offset );
  }
  return out;
}


String toHexString_Uint8List(Uint8List bytes) {
  var result = new StringBuffer();
  for( var i=0 ; i<bytes.lengthInBytes ; i++ ) {
    var part = bytes[i];
    result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
  }
  return result.toString();
}

Uint8List toUint8List_String(String hex) {
  var result = new Uint8List((hex.length/2).floor());
  for( var i=0 ; i<hex.length ; i+=2 ) {
    var num = hex.substring(i, i+2);
    var byte = int.parse( num, radix: 16 );
    result[(i/2).floor()] = byte;
  }
  return result;
}

