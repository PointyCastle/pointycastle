// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy.file_entropy_source;

import "dart:async";
import "dart:typed_data";
import "dart:io";

import "package:cipher/api.dart";

class FileEntropySource implements EntropySource {

	final _filePath;

	String get sourceName => "file://${_filePath}";

	FileEntropySource(this._filePath);

	void seed( CipherParameters params ) {
	}

	Future<Uint8List> getBytes( int count ) {
		var completer = new Completer<Uint8List>();

		var data = new Uint8List(count);
		var offset = 0;
		new File(_filePath).openRead(0, count).listen(
			(bytes) {
				data.setRange(offset, offset+bytes.length, bytes);
				offset += bytes.length;
			},
			onError: (error, stackTrace) {
				completer.completeError(error, stackTrace);
			},
			onDone: () {
				completer.complete(data);
			},
			cancelOnError: true
		);

		return completer.future;
  }

}