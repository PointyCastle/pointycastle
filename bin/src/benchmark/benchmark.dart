// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.bin.src.benchmark;

import "dart:typed_data";
import "dart:mirrors";

import "package:cipher/cipher.dart";

import '../util.dart';

part "./block.dart";

void helpBenchmark() {
  print("""
SYNOPSIS
       cipher benchmark {block|stream|digest} <algorithm name>

DESCRIPTION
       Runs a benchmark for the specified block, stream or digest algorithm

OPTIONS
       block 
           Specifies that the algorithm name denotes a block cipher.

       stream
           Specifies that the algorithm name denotes a stream cipher.

       digest
           Specifies that the algorithm name denotes a digest cipher.

""");  
}

void doBenchmark( List<String> args ) {
  final algorithmType = arg(args,0);
  
  switch( algorithmType ) {
    case "block":  _doBenchmarkBlock(args.sublist(1)); break;
    case "stream": _doBenchmarkStream(args.sublist(1)); break;
    case "digest": _doBenchmarkDigest(args.sublist(1)); break;
    default:       print("cipher: invalid algorithm type '${algorithmType}'"); 
                   break;
  }
}

void _doBenchmarkStream(List<String> args) {
}

void _doBenchmarkDigest(List<String> args) {
}

String _formatAsHumanSize( num size ) {
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
