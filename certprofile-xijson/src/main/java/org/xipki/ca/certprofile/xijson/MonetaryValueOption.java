// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.xipki.ca.certprofile.xijson.conf.QcStatements.Range2Type;

import static org.xipki.util.Args.notNull;

/**
 * Control of the MonetaryValue (in the extension QCStatements).
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

class MonetaryValueOption {

  private final Iso4217CurrencyCode currency;

  private final String currencyString;

  private final Range2Type amountRange;

  private final Range2Type exponentRange;

  public MonetaryValueOption(Iso4217CurrencyCode currency, Range2Type amountRange, Range2Type exponentRange) {
    this.currency = notNull(currency, "currency");
    this.amountRange = notNull(amountRange, "amountRange");
    this.exponentRange = notNull(exponentRange, "exponentRange");

    this.currencyString = currency.isAlphabetic() ? currency.getAlphabetic().toUpperCase()
        : Integer.toString(currency.getNumeric());
  }

  public Iso4217CurrencyCode getCurrency() {
    return currency;
  }

  public Range2Type getAmountRange() {
    return amountRange;
  }

  public Range2Type getExponentRange() {
    return exponentRange;
  }

  public String getCurrencyString() {
    return currencyString;
  }

}
