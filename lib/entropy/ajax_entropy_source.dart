// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy.ajax_entropy_source;

import "dart:async";
import "dart:typed_data";
import "dart:html";

import "package:cipher/api.dart";

//TODO: registrar y probar
class AjaxEntropySource implements EntropySource {

  final String _url;
  final String _sourceName;

  AjaxEntropySource(String url, {String sourceName})
      : _url = url,
        _sourceName = (sourceName == null) ? "${url}" : sourceName;

  String get sourceName => _sourceName;

  Future<Uint8List> getBytes(int count) {
    var completer = new Completer<Uint8List>();

    var url = _url.replaceAll("{count}", count.toString());
    HttpRequest.request(url).then((request) {
      final response = request.response;

      if (response is ByteBuffer) {
        completer.complete(new Uint8List.view(response));
      } else {
        completer.completeError(new StateError(
            "Unsupported data type returned from remote server: ${response.runtimeType}"));
      }

    }).catchError((error, stackTrace) {
      completer.completeError(error, stackTrace);
    });

    return completer.future;
  }

}
