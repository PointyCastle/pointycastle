part of cipher_engines_aes_fast;

/**
 * A 2D matrix of words of 32 bits stored in big endian (natural binary order).
 */
class _Words2dMatrix {
  
  static const WORD_SIZE = 4;
  static const WORD_ENDIAN = Endianness.BIG_ENDIAN;
  
  final int _rows;
  final int _cols;
  List<ByteData> _data;
  
  _Words2dMatrix(this._rows,this._cols) {
    _data = new List(_rows);
    for( var row=0 ; row<_rows ; row++ ) {
      _data[row] = new ByteData(_cols*WORD_SIZE);
    }
  }
  
  void setWord( int row, int col, int value ) {
    _data[row].setUint32(col*WORD_SIZE, value, WORD_ENDIAN);
  }
  
  int getWord( int row, int col ) {
    return _data[row].getUint32(col*WORD_SIZE, WORD_ENDIAN);
  }
  
  String toString() {
    var sb = new StringBuffer();
    sb.write("[\n");
    for( var row=0 ; row<_rows ; row++ ) {
      var rdata = _data[row];
      for( var i=0 ; i<rdata.lengthInBytes ; i++ ) {
        var part = rdata.getUint8(i);
        if( i!=0 && i%WORD_SIZE == 0 ) {
          sb.write(" ");
        }
        sb.write('${part < 16 ? '0' : ''}${part.toRadixString(16).toUpperCase()}');
      }
      sb.write("\n");
    }
    sb.write("]");
    return sb.toString();
  }
}
