// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

part of cipher.test.test.src.helpers;

const isAllZeros = const _IsAllZeros();

class _IsAllZeros extends Matcher {

  const _IsAllZeros();

  bool matches( Iterable<int> item, Map matchState ) {
    for( var i in item ) {
      if( i!=0 ) return false;
    }
    return true;
  }

  Description describe( Description description ) =>
      description.add( 'is all zeros' );

  Description describeMismatch( item, Description mismatchDescription,
                                 Map matchState, bool verbose )
    => mismatchDescription.add( "is not all zeros" );

}

