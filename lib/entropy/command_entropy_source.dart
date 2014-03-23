// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy.command_entropy_source;

import "dart:async";
import "dart:typed_data";
import "dart:io";

import "package:cipher/api.dart";

/**
 * Reads the output of a command as binary values and returns it as entropy values. The unconsumed
 * values are buffered and the command is also rerun when new bytes are needed.
 */
class CommandEntropySource implements EntropySource {

  final String _executable;
  final List<String> _arguments;

  final _buffer;
  int _bufferCount;
  String _sourceName;

  String get sourceName => _sourceName;

  CommandEntropySource(int bufferSize, this._executable, this._arguments) :
    _buffer = new Uint8List(bufferSize),
    _bufferCount = 0 {
    _sourceName = "command:${_executable}";
    for (String argument in _arguments) {
      _sourceName += "|${argument}";
    }
  }

  void seed( CipherParameters params ) {
  }

  Future<Uint8List> getBytes(int count) {
    final completer = new Completer<Uint8List>();
    final bytes = new Uint8List(count);

    int bytesCount = _getEntropySync(bytes, 0, count);

    if (bytesCount == count) {
      completer.complete(bytes);
    } else {
      _getEntropyAsync(bytes, bytesCount, count - bytesCount).then((_){
        completer.complete(bytes);
      });
    }

    return completer.future;
  }

  Future _getEntropyAsync(Uint8List bytes, int bytesCount, int count) {
    if (count == 0) {
      return new Future.value();
    } else {
      return _harvestEntropy().then( (_) {
        final bytesRead = _getEntropySync(bytes, bytesCount, count);

        bytesCount += bytesRead;

        if (bytesCount == count) {
          return new Future.value();
        } else {
          return _getEntropyAsync(bytes, bytesCount, count - bytesRead);
        }
      });
    }
  }

  Future _harvestEntropy() =>
    Process.run(_executable, _arguments, runInShell: true, stdoutEncoding: null).then(
      (ProcessResult result) {
        var entropy = (result.stdout as List<int>);

        if (entropy[entropy.length-1] == 13) {
          entropy = entropy.sublist(0, entropy.length-1);
        }
        if (entropy[entropy.length-1] == 10) {
          entropy = entropy.sublist(0, entropy.length-1);
        }

        int end = _bufferCount + entropy.length;
        if (end > _buffer.length) {
          end = _buffer.length;
        }

        _buffer.setRange(_bufferCount, end, entropy);
        _bufferCount = end;
      });

  int _getEntropySync(Uint8List bytes, int start, int count) {
    if (count < _bufferCount) {
      bytes.setRange(start, start + count, _buffer);
      _buffer.setRange(0, (_bufferCount - count), _buffer, count);
      _bufferCount -= count;

      return count;
    } else if (_bufferCount > 0) {
      bytes.setRange(start, start + _bufferCount, _buffer);
      count = _bufferCount;
      _bufferCount = 0;

      return count;
    } else {
      return 0;
    }
  }

}