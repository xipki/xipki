/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.certprofile;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.xipki.common.util.ParamUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class QcStatementOption {

    private final QCStatement statement;

    private final ASN1ObjectIdentifier statementId;

    private final MonetaryValueOption monetaryValueOption;

    public QcStatementOption(final QCStatement statement) {
        this.statement = ParamUtil.requireNonNull("statement", statement);
        this.statementId = null;
        this.monetaryValueOption = null;
    }

    public QcStatementOption(final ASN1ObjectIdentifier statementId,
            final MonetaryValueOption monetaryValueOption) {
        this.statement = null;
        this.statementId = ParamUtil.requireNonNull("statementId", statementId);
        this.monetaryValueOption = ParamUtil.requireNonNull("monetaryValueOption",
                monetaryValueOption);
    }

    public QCStatement statement() {
        return statement;
    }

    public ASN1ObjectIdentifier statementId() {
        return statementId;
    }

    public MonetaryValueOption monetaryValueOption() {
        return monetaryValueOption;
    }

}
