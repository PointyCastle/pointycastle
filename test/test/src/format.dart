// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

part of cipher.test.test.src.helpers;

String formatAsTruncated( String str ) {
  if( str.length>26 ) {
    return str.substring(0, 26)+"[...]";
  } else if( str.length==0 ) {
    return "(empty string)";
  } else {
    return str;
  }
}

String formatAsHumanSize( num size ) {
  if( size<1024 ) return "$size B";
  if( size<1024*1024 ) return "${_format(size/1024)} KB";
  if( size<1024*1024*1024 ) return "${_format(size/(1024*1024))} MB";
  return "${_format(size/(1024*1024*1024))} GB";
}

String formatBytesAsHexString(Uint8List bytes) {
  var result = new StringBuffer();
  for( var i=0 ; i<bytes.lengthInBytes ; i++ ) {
    var part = bytes[i];
    result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
  }
  return result.toString();
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

