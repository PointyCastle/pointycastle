// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.bin.cipher;

import "package:cipher/cipher.dart";

import "./src/util.dart";
import "./src/benchmark/benchmark.dart";
import "./src/cipher/cipher.dart";
import "./src/decipher/decipher.dart";

final COMMANDS = {
  "help":      [ doHelp,      null,           null ],
  "benchmark": [ doBenchmark, helpBenchmark, "benchmark a specific algorithm and show results" ] ,
  "cipher":    [ doCipher,    helpCipher,    "cipher data with a specific algorithm/scheme" ],
  "decipher":  [ doDecipher,  helpDecipher,  "decipher data with a specific algorithm/scheme" ],
};

void main( List<String> args ) {

  initCipher();
  
  if( args.length==0 ) {
    showUsage();
  } else {
    var cmd = arg(args,0);
    var _command = COMMANDS[cmd][0];
    if( _command==null ) {
      print("cipher: '${cmd}' is not a valid command. Run 'cipher' without arguments to get some help.\n");
    } else {
      _command( args.sublist(1) );
    }
  }
  
}

void showUsage() {
  print("""
usage: cipher <command> [<args>]

Available commands:
""");
  for( var cmd in COMMANDS.keys ) {
    var text = COMMANDS[cmd][2];
    if( text!=null ) {
      print("   ${cmd}:   ${text}");
    }
  }
  print( "\nRun 'cipher help <command>' for more information on a specific command." );  
}

void doHelp( List<String> args ) {
  var cmd = arg(args,0);
  if( cmd==null ) {
    showUsage();
  } else {
    var command = COMMANDS[cmd];
    var helper = (command==null) ? null : command[1];

    if( helper!=null ) {
      helper();
    } else {
      print("cipher: '${cmd}' is not a valid command. Run 'cipher' without arguments to get some help.\n");
    }
  }
}



