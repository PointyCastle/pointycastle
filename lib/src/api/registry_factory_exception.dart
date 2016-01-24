
// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/// This kind of exception is thrown when a user tries to create an algorithm
/// or domain parameters that were not correctly registered. This can be
/// because the corresponding class was not imported, or because the algorithm
/// does not exist.
class RegistryFactoryException implements Exception {

  final String message;

  RegistryFactoryException(this.message);

  RegistryFactoryException.unknown(String algorithm, [String category]) : this(
    "No algorithm registered" +
      (category != null ? " in category $category" : "") +
      " with name: $algorithm"
  );

  RegistryFactoryException.invalid(String algorithm, [String category]) : this(
    "Algorithm name $algorithm is invalid" +
      (category != null ? " in category $category" : "")
  );

  RegistryFactoryException.category(String category)
      : this("No algorithms of category $category registered.");

  @override
  String toString() => "RegistryFactoryException: $message";

}