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
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.ca.api.CAMgmtException;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.IoUtil;
import org.xipki.common.KeyUsage;
import org.xipki.common.ParamChecker;
import org.xipki.common.SecurityUtil;

/**
 * @author Lijun Liao
 */

public class X509CAEntry implements Serializable
{
    private static final long serialVersionUID = 1L;
    private String name;
    private CAStatus status;
    private List<String> crlUris;
    private List<String> deltaCrlUris;
    private List<String> ocspUris;
    private List<String> issuerLocations;
    private CertValidity maxValidity;
    private X509Certificate cert;
    private String signerType;
    private String signerConf;
    private String crlSignerName;
    private long nextSerial;
    private DuplicationMode duplicateKeyMode;
    private DuplicationMode duplicateSubjectMode;
    private ValidityMode validityMode = ValidityMode.STRICT;
    private Set<Permission> permissions;
    private int numCrls;
    private int expirationPeriod;
    private CertRevocationInfo revocationInfo;
    private int lastCRLInterval;
    private long lastCRLIntervalDate;
    private String subject;
    private String serialSeqName;

    public X509CAEntry(String name, long initialSerial,
            String signerType, String signerConf, X509Certificate cert,
            List<String> ocspUris, List<String> crlUris, List<String> deltaCrlUris,
            List<String> issuerLocations, int numCrls,
            int expirationPeriod)
    throws CAMgmtException
    {
        init(name, initialSerial, signerType, signerConf, cert, ocspUris,
                crlUris, deltaCrlUris, issuerLocations, numCrls, expirationPeriod);
    }

    private void init(String name, long initialSerial,
            String signerType, String signerConf, X509Certificate cert,
            List<String> ocspUris, List<String> crlUris, List<String> deltaCrlUris,
            List<String> issuerLocations, int numCrls,
            int expirationPeriod)
    throws CAMgmtException
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotEmpty("signerType", signerType);
        ParamChecker.assertNotNull("cert", cert);

        if(SecurityUtil.hasKeyusage(cert, KeyUsage.keyCertSign) == false)
        {
            throw new CAMgmtException("CA certificate does not have keyusage keyCertSign");
        }

        if(initialSerial < 0)
        {
            throw new IllegalArgumentException("initialSerial is negative (" + initialSerial + " < 0)");
        }

        if(expirationPeriod < 0)
        {
            throw new IllegalArgumentException("expirationPeriod is negative (" + expirationPeriod + " < 0)");
        }
        this.expirationPeriod = expirationPeriod;

        if(numCrls < 0)
        {
            throw new IllegalArgumentException("numCrls could not be negative");
        }
        this.numCrls = numCrls;

        this.name = name.toUpperCase();
        this.serialSeqName = IoUtil.convertSequenceName("SERIAL_" + this.name);
        this.nextSerial = initialSerial;
        this.cert = cert;
        this.subject = SecurityUtil.getRFC4519Name(cert.getSubjectX500Principal());

        this.signerType = signerType;
        this.signerConf = signerConf;

        this.ocspUris = (ocspUris == null) ?
                null : Collections.unmodifiableList(new ArrayList<>(ocspUris));
        this.crlUris = (crlUris == null) ?
                null : Collections.unmodifiableList(new ArrayList<>(crlUris));
        this.deltaCrlUris = (deltaCrlUris == null) ?
                null : Collections.unmodifiableList(new ArrayList<>(deltaCrlUris));
        this.issuerLocations = (issuerLocations == null) ?
                null : Collections.unmodifiableList(new ArrayList<>(issuerLocations));
    }

    public String getName()
    {
        return name;
    }

    public long getNextSerial()
    {
        return nextSerial;
    }

    public void setNextSerial(long nextSerial)
    {
        this.nextSerial = nextSerial;
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

    public CertValidity getMaxValidity()
    {
        return maxValidity;
    }

    public void setMaxValidity(CertValidity maxValidity)
    {
        this.maxValidity = maxValidity;
    }

    public X509Certificate getCertificate()
    {
        return cert;
    }

    public String getSignerConf()
    {
        return signerConf;
    }

    public String getCrlSignerName()
    {
        return crlSignerName;
    }

    public int getNumCrls()
    {
        return numCrls;
    }

    public void setCrlSignerName(String crlSignerName)
    {
        this.crlSignerName = crlSignerName;
    }

    public CAStatus getStatus()
    {
        return status;
    }
    public void setStatus(CAStatus status)
    {
        this.status = status;
    }

    public String getSignerType()
    {
        return signerType;
    }

    public List<String> getCaIssuerLocations()
    {
        return issuerLocations;
    }

    @Override
    public String toString()
    {
        return toString(false);
    }

    public String toString(boolean verbose)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("name: ").append(name).append('\n');
        sb.append("next_serial: ").append(nextSerial).append('\n');
        sb.append("status: ").append(status.getStatus()).append('\n');
        sb.append("deltaCrl_uris: ").append(getDeltaCrlUrisAsString()).append('\n');
        sb.append("crl_uris: ").append(getCrlUrisAsString()).append('\n');
        sb.append("ocsp_uris: ").append(getOcspUrisAsString()).append('\n');
        sb.append("max_validity: ").append(maxValidity).append(" days\n");
        sb.append("expirationPeriod: ").append(expirationPeriod).append(" days\n");
        sb.append("signer_type: ").append(signerType).append('\n');
        sb.append("signer_conf: ");
        if(signerConf == null)
        {
            sb.append("null");
        }
        else if(verbose || signerConf.length() < 101)
        {
            sb.append(signerConf);
        }
        else
        {
            sb.append(signerConf.substring(0, 97)).append("...");
        }
        sb.append('\n');
        sb.append("cert: ").append("\n");
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

        sb.append("crlsigner_name: ").append(crlSignerName).append('\n');
        sb.append("duplicateKey: ").append(duplicateKeyMode.getDescription()).append('\n');
        sb.append("duplicateSubject: ").append(duplicateSubjectMode.getDescription()).append('\n');
        sb.append("validityMode: ").append(validityMode).append('\n');
        sb.append("permissions: ").append(Permission.toString(permissions)).append('\n');
        sb.append("lastCRLInterval: ").append(lastCRLInterval).append('\n');
        sb.append("lastCRLIntervalDate: ").append(lastCRLIntervalDate).append('\n');

        return sb.toString();
    }

    private static String toString(Collection<String> tokens)
    {
        if(tokens == null || tokens.isEmpty())
        {
            return null;
        }

        StringBuilder sb = new StringBuilder();

        int size = tokens.size();
        int idx = 0;
        for(String token : tokens)
        {
            sb.append(token);
            if(idx++ < size - 1)
            {
                sb.append("\t");
            }
        }
        return sb.toString();
    }

    public DuplicationMode getDuplicateKeyMode()
    {
        return duplicateKeyMode;
    }

    public void setDuplicateKeyMode(DuplicationMode mode)
    {
        ParamChecker.assertNotNull("mode", mode);
        this.duplicateKeyMode = mode;
    }

    public DuplicationMode getDuplicateSubjectMode()
    {
        return duplicateSubjectMode;
    }

    public void setDuplicateSubjectMode(DuplicationMode mode)
    {
        ParamChecker.assertNotNull("mode", mode);
        this.duplicateSubjectMode = mode;
    }

    public ValidityMode getValidityMode()
    {
        return validityMode;
    }

    public void setValidityMode(ValidityMode mode)
    {
        ParamChecker.assertNotNull("mode", mode);
        this.validityMode = mode;
    }

    public Set<Permission> getPermissions()
    {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions)
    {
        this.permissions = (permissions == null) ? null : Collections.unmodifiableSet(permissions);
    }

    public CertRevocationInfo getRevocationInfo()
    {
        return revocationInfo;
    }

    public void setRevocationInfo(CertRevocationInfo revocationInfo)
    {
        this.revocationInfo = revocationInfo;
    }

    public int getExpirationPeriod()
    {
        return expirationPeriod;
    }

    public int getLastCRLInterval()
    {
        return lastCRLInterval;
    }

    public void setLastCRLInterval(int lastInterval)
    {
        this.lastCRLInterval = lastInterval;
    }

    public long getLastCRLIntervalDate()
    {
        return lastCRLIntervalDate;
    }

    public void setLastCRLIntervalDate(long lastIntervalDate)
    {
        this.lastCRLIntervalDate = lastIntervalDate;
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
