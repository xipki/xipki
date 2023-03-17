// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.xipki.util.Args;

/**
 * Control of the QC Statement (in the extension QCStatements).
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

class QcStatementOption {

  private final QCStatement statement;

  private final ASN1ObjectIdentifier statementId;

  private final MonetaryValueOption monetaryValueOption;

  public QcStatementOption(QCStatement statement) {
    this.statement = Args.notNull(statement, "statement");
    this.statementId = null;
    this.monetaryValueOption = null;
  }

  public QcStatementOption(ASN1ObjectIdentifier statementId, MonetaryValueOption monetaryValueOption) {
    this.statement = null;
    this.statementId = Args.notNull(statementId, "statementId");
    this.monetaryValueOption = Args.notNull(monetaryValueOption, "monetaryValueOption");
  }

  public QCStatement getStatement() {
    return statement;
  }

  public ASN1ObjectIdentifier getStatementId() {
    return statementId;
  }

  public MonetaryValueOption getMonetaryValueOption() {
    return monetaryValueOption;
  }

}
