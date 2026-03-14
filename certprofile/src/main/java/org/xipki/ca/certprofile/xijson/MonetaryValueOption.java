// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.bouncycastle.asn1.x509.qualified.Iso4217CurrencyCode;
import org.xipki.ca.certprofile.xijson.conf.ExtensionValueConf;
import org.xipki.util.codec.Args;

/**
 * Control of the MonetaryValue (in the extension QCStatements).
 *
 * @author Lijun Liao (xipki)
 */

class MonetaryValueOption {

  private final Iso4217CurrencyCode currency;

  private final String currencyString;

  private final ExtensionValueConf.Range2Type amountRange;

  private final ExtensionValueConf.Range2Type exponentRange;

  public MonetaryValueOption(
      Iso4217CurrencyCode currency, ExtensionValueConf.Range2Type amountRange,
      ExtensionValueConf.Range2Type exponentRange) {
    this.currency = Args.notNull(currency, "currency");
    this.amountRange = Args.notNull(amountRange, "amountRange");
    this.exponentRange = Args.notNull(exponentRange, "exponentRange");

    this.currencyString = currency.isAlphabetic()
        ? currency.getAlphabetic().toUpperCase()
        : Integer.toString(currency.getNumeric());
  }

  public Iso4217CurrencyCode currency() {
    return currency;
  }

  public ExtensionValueConf.Range2Type amountRange() {
    return amountRange;
  }

  public ExtensionValueConf.Range2Type exponentRange() {
    return exponentRange;
  }

  public String currencyString() {
    return currencyString;
  }

}
