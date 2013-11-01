// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

part of cipher.test.test.helpers;

Uint8List createUint8ListFromListOfInts( List<int> bytes ) {
  var data = new Uint8List(bytes.length);
  for( var i=0 ; i<bytes.length ; i++ ) {
    data[i] = bytes[i];
  }
  return data;
}

Uint8List createUint8ListFromString( String s ) {
  var ret = new Uint8List(s.length);
  for( var i=0 ; i<s.length ; i++ ) {
    ret[i] = s.codeUnitAt(i);
  }
  return ret;
}

Uint8List createUint8ListFromHexString(String hex) {
  var result = new Uint8List((hex.length/2).floor());
  for( var i=0 ; i<hex.length ; i+=2 ) {
    var num = hex.substring(i, i+2);
    var byte = int.parse( num, radix: 16 );
    result[(i/2).floor()] = byte;
  }
  return result;
}

Uint8List createUint8ListFromSequentialNumbers( int len ) {
  var ret = new Uint8List(len);
  for( var i=0 ; i<len ; i++ ) {
    ret[i] = i;
  }
  return ret;
}

