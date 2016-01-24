
part of pointycastle.api;

/// All algorithms defined by cipher inherit from this class.
abstract class Algorithm extends Registrable {

  /// Get this algorithm's standard name.
  String get algorithmName;

}