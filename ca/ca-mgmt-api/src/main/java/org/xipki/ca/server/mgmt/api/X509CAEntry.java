/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
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

package org.xipki.ca.server.mgmt.api;

import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.KeyUsage;
import org.xipki.common.util.IoUtil;
import org.xipki.common.util.SecurityUtil;

/**
 * @author Lijun Liao
 */

public class X509CAEntry
extends CAEntry
implements Serializable
{
    private static final long serialVersionUID = 1L;
    private List<String> crlUris;
    private List<String> deltaCrlUris;
    private List<String> ocspUris;
    private X509Certificate cert;
    private String crlSignerName;
    private long nextSerial;
    private int nextCRLNumber;
    private int numCrls;
    private CertRevocationInfo revocationInfo;
    private String subject;
    private String serialSeqName;

    public X509CAEntry(
            final String name,
            final long nextSerial,
            final int nextCRLNumber,
            final String signerType,
            final String signerConf,
            final List<String> ocspUris,
            final List<String> crlUris,
            final List<String> deltaCrlUris,
            final int numCrls,
            final int expirationPeriod)
    throws CAMgmtException
    {
        super(name, signerType, signerConf, expirationPeriod);
        init(nextSerial, nextCRLNumber, ocspUris, crlUris, deltaCrlUris, numCrls);
    }

    private void init(
            final long nextSerial,
            final int nextCRLNumber,
            final List<String> ocspUris,
            final List<String> crlUris,
            final List<String> deltaCrlUris,
            final int numCrls)
    throws CAMgmtException
    {
        if(nextSerial < 0)
        {
            throw new IllegalArgumentException("nextSerial is negative (" + nextSerial + " < 0)");
        }

        if(nextCRLNumber <= 0)
        {
            throw new IllegalArgumentException("nextCRLNumber is not positive (" + nextCRLNumber + " < 1)");
        }

        if(numCrls < 0)
        {
            throw new IllegalArgumentException("numCrls could not be negative");
        }
        this.numCrls = numCrls;

        this.serialSeqName = IoUtil.convertSequenceName("SERIAL_" + getName());
        this.nextSerial = nextSerial;
        this.nextCRLNumber = nextCRLNumber;

        this.ocspUris = (ocspUris == null) ?
                null : Collections.unmodifiableList(new ArrayList<>(ocspUris));
        this.crlUris = (crlUris == null) ?
                null : Collections.unmodifiableList(new ArrayList<>(crlUris));
        this.deltaCrlUris = (deltaCrlUris == null) ?
                null : Collections.unmodifiableList(new ArrayList<>(deltaCrlUris));
    }

    public void setCertificate(
            final X509Certificate cert)
    throws CAMgmtException
    {
    	if(cert == null)
    	{
    		this.cert = null;
    		this.subject = null;
    	}
    	else
    	{
	        if(SecurityUtil.hasKeyusage(cert, KeyUsage.keyCertSign) == false)
	        {
	            throw new CAMgmtException("CA certificate does not have keyusage keyCertSign");
	        }
	        this.cert = cert;
	        this.subject = SecurityUtil.getRFC4519Name(cert.getSubjectX500Principal());
    	}
    }

    public long getNextSerial()
    {
        return nextSerial;
    }

    public void setNextSerial(
            final long nextSerial)
    {
        this.nextSerial = nextSerial;
    }

    public int getNextCRLNumber()
    {
        return nextCRLNumber;
    }

    public void setNextCRLNumber(
            final int crlNumber)
    {
        this.nextCRLNumber = crlNumber;
    }

    public List<String> getCrlUris()
    {
        return crlUris;
    }

    public String getCrlUrisAsString()
    {
        return toString(crlUris);
    }

    public List<String> getDeltaCrlUris()
    {
        return deltaCrlUris;
    }

    public String getDeltaCrlUrisAsString()
    {
        return toString(deltaCrlUris);
    }

    public List<String> getOcspUris()
    {
        return ocspUris;
    }

    public String getOcspUrisAsString()
    {
        return toString(ocspUris);
    }

    public X509Certificate getCertificate()
    {
        return cert;
    }

    public String getCrlSignerName()
    {
        return crlSignerName;
    }

    public int getNumCrls()
    {
        return numCrls;
    }

    public void setCrlSignerName(
            final String crlSignerName)
    {
        this.crlSignerName = crlSignerName;
    }

    public String toString(
            final boolean verbose,
            final boolean ignoreSensitiveInfo)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(super.toString(verbose, ignoreSensitiveInfo));
        if(sb.charAt(sb.length() - 1) != '\n')
        {
            sb.append('\n');
        }
        sb.append("nextSerial: ").append(nextSerial).append('\n');
        sb.append("nextCrlNumber: ").append(nextCRLNumber).append('\n');
        sb.append("deltaCrlUris: ").append(getDeltaCrlUrisAsString()).append('\n');
        sb.append("crlUris: ").append(getCrlUrisAsString()).append('\n');
        sb.append("ocspUris: ").append(getOcspUrisAsString()).append('\n');
        sb.append("cert: ").append("\n");
        if(cert == null)
        {
            sb.append("\tnull").append("\n");
        }
        else
        {
            sb.append("\tissuer: ").append(
                    SecurityUtil.getRFC4519Name(cert.getIssuerX500Principal())).append("\n");
            sb.append("\tserialNumber: ").append(cert.getSerialNumber()).append("\n");
            sb.append("\tsubject: ").append(subject).append("\n");
            sb.append("\tnotBefore: ").append(cert.getNotBefore()).append("\n");
            sb.append("\tnotAfter: ").append(cert.getNotAfter()).append("\n");
            if(verbose)
            {
                String b64EncodedCert = null;
                try
                {
                    b64EncodedCert = Base64.toBase64String(cert.getEncoded());
                } catch (CertificateEncodingException e)
                {
                    b64EncodedCert = "ERROR, could not encode the certificate";
                }
                sb.append("\tEncoded: ").append(b64EncodedCert).append("\n");
            }
        }

        sb.append("crlsignerName: ").append(crlSignerName).append('\n');
        sb.append("revocation: ").append(revocationInfo == null ? "not revoked" : "revoked").append("\n");
        if(revocationInfo != null)
        {
            sb.append("\treason: ").append(revocationInfo.getReason().getDescription()).append("\n");
            sb.append("\trevoked at ").append(revocationInfo.getRevocationTime()).append("\n");
        }

        return sb.toString();
    }

    public CertRevocationInfo getRevocationInfo()
    {
        return revocationInfo;
    }

    public void setRevocationInfo(
            final CertRevocationInfo revocationInfo)
    {
        this.revocationInfo = revocationInfo;
    }

    public Date getCrlBaseTime()
    {
        return cert == null ? null : cert.getNotBefore();
    }

    public String getSubject()
    {
        return subject;
    }

    public String getSerialSeqName()
    {
        return serialSeqName;
    }

}
