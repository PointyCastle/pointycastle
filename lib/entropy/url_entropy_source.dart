// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy.url_entropy_source;

import "dart:async";
import "dart:typed_data";
import "dart:io";

import "package:cipher/api.dart";

class UrlEntropySource implements EntropySource {

  final String _url;

  String get sourceName => _url;

  UrlEntropySource(this._url);

  void seed( CipherParameters params ) {
  }

  Future<Uint8List> getBytes( int count ) {
    var completer = new Completer<Uint8List>();

    var url = _url.replaceAll( "{count}", count.toString() );
    new HttpClient().getUrl(Uri.parse(url))
      .then( (HttpClientRequest request) {
        return request.close();
      })
      .then( (HttpClientResponse response) {
        var data = new Uint8List(count);
        var offset = 0;
        response.listen(
          (bytes) {
            data.setRange(offset, offset+bytes.length, bytes);
            offset += bytes.length;
          },
          onDone: () {
            completer.complete(data);
          },
          onError: (error, stackTrace) {
            completer.completeError(error,stackTrace);
          },
          cancelOnError: true
        );
      })
      .catchError( (error, stackTrace) {
        completer.completeError(error, stackTrace);
      });

    return completer.future;
  }

}