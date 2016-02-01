/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.pki.scep.client;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.xipki.pki.scep.client.exception.ScepClientException;
import org.xipki.pki.scep.message.PkiMessage;
import org.xipki.pki.scep.transaction.FailInfo;
import org.xipki.pki.scep.transaction.MessageType;
import org.xipki.pki.scep.transaction.PkiStatus;
import org.xipki.pki.scep.util.ParamUtil;
import org.xipki.pki.scep.util.ScepUtil;

/**
 * @author Lijun Liao
 */

public final class EnrolmentResponse {

    private PkiMessage pkcsRep;

    private List<X509Certificate> certificates;

    public EnrolmentResponse(
            final PkiMessage pkcsRep)
    throws ScepClientException {
        ParamUtil.assertNotNull("pkcsRep", pkcsRep);
        MessageType messageType = pkcsRep.getMessageType();
        if (MessageType.CertRep != messageType) {
            throw new ScepClientException(
                    "messageType could not be other than CertRep: " + messageType);
        }
        this.pkcsRep = pkcsRep;

        if (PkiStatus.SUCCESS != pkcsRep.getPkiStatus()) {
            return;
        }

        ASN1Encodable messageData = pkcsRep.getMessageData();
        if (!(messageData instanceof ContentInfo)) {
            throw new ScepClientException("pkcsRep is not a ContentInfo");
        }

        ContentInfo ci = (ContentInfo) messageData;
        SignedData sd = SignedData.getInstance(ci.getContent());
        ASN1Set asn1Certs = sd.getCertificates();
        if (asn1Certs == null | asn1Certs.size() == 0) {
            throw new ScepClientException("no certificate is embedded in pkcsRep");
        }

        List<X509Certificate> certs;
        try {
            certs = ScepUtil.getCertsFromSignedData(sd);
        } catch (CertificateException e) {
            throw new ScepClientException(e.getMessage(), e);
        }
        this.certificates = Collections.unmodifiableList(certs);
    }

    /**
     * Returns <tt>true</tt> for a pending response, <tt>false</tt> otherwise.
     *
     * @return <tt>true</tt> for a pending response, <tt>false</tt> otherwise.
     */
    public boolean isPending() {
        return pkcsRep.getPkiStatus() == PkiStatus.PENDING;
    }

    public boolean isFailure() {
        return pkcsRep.getPkiStatus() == PkiStatus.FAILURE;
    }

    public boolean isSuccess() {
        return pkcsRep.getPkiStatus() == PkiStatus.SUCCESS;
    }

    public List<X509Certificate> getCertificates() {
        if (isSuccess()) {
            return certificates;
        }
        throw new IllegalStateException();
    }

    public FailInfo getFailInfo() {
        if (isFailure()) {
            return pkcsRep.getFailInfo();
        }
        throw new IllegalStateException();
    }

    public PkiMessage getPkcsRep() {
        return pkcsRep;
    }

}
