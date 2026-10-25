// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.certprofile.xijson;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.pkix.asn1.x509.qualified.QCStatement;
import org.xipki.codec.util.Args;

/**
 * Control of the QC-Statement (in the extension QCStatements).
 *
 * @author Lijun Liao (xipki)
 */
class QcStatementOption {

  private final QCStatement statement;

  private final Asn1Oid statementId;

  private final MonetaryValueOption monetaryValueOption;

  public QcStatementOption(QCStatement statement) {
    this.statement = Args.notNull(statement, "statement");
    this.statementId = null;
    this.monetaryValueOption = null;
  }

  public QcStatementOption(Asn1Oid statementId,
                          MonetaryValueOption monetaryValueOption) {
    this.statement = null;
    this.statementId = Args.notNull(statementId, "statementId");
    this.monetaryValueOption =
        Args.notNull(monetaryValueOption, "monetaryValueOption");
  }

  public QCStatement statement() {
    return statement;
  }

  public Asn1Oid statementId() {
    return statementId;
  }

  public MonetaryValueOption monetaryValueOption() {
    return monetaryValueOption;
  }

}
