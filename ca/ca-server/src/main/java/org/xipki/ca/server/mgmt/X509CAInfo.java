/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 Lijun Liao
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

package org.xipki.ca.server.mgmt;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.api.CertValidity;
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.X509CertificateWithMetaInfo;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.server.PublicCAInfo;
import org.xipki.ca.server.RandomSerialNumberGenerator;
import org.xipki.ca.server.mgmt.api.X509CAEntry;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.store.CertificateStore;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class X509CAInfo
{
    private final static Logger LOG = LoggerFactory.getLogger(X509CAInfo.class);

    private static long MS_PER_DAY = 24L * 60 * 60 * 1000;

    private final X509CAEntry caEntry;

    private long noNewCertificateAfter;
    private BigInteger serialNumber;
    private Date notBefore;
    private Date notAfter;
    private boolean selfSigned;
    private CMPCertificate certInCMPFormat;
    private PublicCAInfo publicCAInfo;
    private X509CertificateWithMetaInfo cert;

    private CertificateStore certStore;
    private boolean useRandomSerialNumber;
    private RandomSerialNumberGenerator randomSNGenerator;

    public X509CAInfo(X509CAEntry caEntry, CertificateStore certStore)
    throws OperationException
    {
        ParamChecker.assertNotNull("caEntry", caEntry);
        ParamChecker.assertNotNull("certStore", certStore);
        this.caEntry = caEntry;
        this.certStore = certStore;

        X509Certificate cert = caEntry.getCertificate();
        this.notBefore = cert.getNotBefore();
        this.notAfter = cert.getNotAfter();
        this.serialNumber = cert.getSerialNumber();
        this.selfSigned = cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());

        Certificate bcCert;
        try
        {
            byte[] encodedCert = cert.getEncoded();
            this.cert = new X509CertificateWithMetaInfo(cert, encodedCert);
            bcCert = Certificate.getInstance(encodedCert);
        } catch (CertificateEncodingException e)
        {
            throw new OperationException(ErrorCode.System_Failure, "could not encode the CA certificate");
        }
        this.certInCMPFormat = new CMPCertificate(bcCert);

        this.publicCAInfo = new PublicCAInfo(cert,
                caEntry.getOcspUris(), caEntry.getCrlUris(), caEntry.getCaIssuerLocations(), caEntry.getDeltaCrlUris());

        this.noNewCertificateAfter = this.notAfter.getTime() - MS_PER_DAY * caEntry.getExpirationPeriod();

        this.useRandomSerialNumber = caEntry.getNextSerial() < 1;
        if(this.useRandomSerialNumber)
        {
            randomSNGenerator = RandomSerialNumberGenerator.getInstance();
            return;
        }

        Long greatestSerialNumber = certStore.getGreatestSerialNumber(this.cert);

        if(greatestSerialNumber == null)
        {
            throw new OperationException(ErrorCode.System_Failure,
                    "Could not retrieve the greatest serial number for ca " + caEntry.getName());
        }

        long nextSerial = greatestSerialNumber + 1;
        if(nextSerial < 2)
        {
            nextSerial = 2;
        }

        if(caEntry.getNextSerial() < nextSerial)
        {
            LOG.info("Corrected the next_serial of {} from {} to {}",
                    new Object[]{caEntry.getName(), caEntry.getNextSerial(), nextSerial});
            caEntry.setNextSerial(nextSerial);
            certStore.commitNextSerialIfLess(getName(), nextSerial);
        }
        else
        {
            nextSerial = caEntry.getNextSerial();
        }
    }

    public void commitNextSerial()
    throws OperationException
    {
        if(useRandomSerialNumber)
        {
            return;
        }
        long nextSerial = caEntry.getNextSerial();
        certStore.commitNextSerialIfLess(caEntry.getName(), nextSerial);
    }

    public PublicCAInfo getPublicCAInfo()
    {
        return publicCAInfo;
    }

    public String getSubject()
    {
        return caEntry.getSubject();
    }

    public Date getNotBefore()
    {
        return notBefore;
    }

    public Date getNotAfter()
    {
        return notAfter;
    }

    public BigInteger getSerialNumber()
    {
        return serialNumber;
    }

    public boolean isSelfSigned()
    {
        return selfSigned;
    }

    public CMPCertificate getCertInCMPFormat()
    {
        return certInCMPFormat;
    }

    public long getNoNewCertificateAfter()
    {
        return noNewCertificateAfter;
    }

    public X509CAEntry getCaEntry()
    {
        return caEntry;
    }

    public String getName()
    {
        return caEntry.getName();
    }

    public List<String> getCrlUris()
    {
        return caEntry.getCrlUris();
    }

    public String getCrlUrisAsString()
    {
        return caEntry.getCrlUrisAsString();
    }

    public List<String> getDeltaCrlUris()
    {
        return caEntry.getDeltaCrlUris();
    }

    public String getDeltaCrlUrisAsString()
    {
        return caEntry.getDeltaCrlUrisAsString();
    }

    public List<String> getOcspUris()
    {
        return caEntry.getOcspUris();
    }

    public String getOcspUrisAsString()
    {
        return caEntry.getOcspUrisAsString();
    }

    public CertValidity getMaxValidity()
    {
        return caEntry.getMaxValidity();
    }

    public void setMaxValidity(CertValidity maxValidity)
    {
        caEntry.setMaxValidity(maxValidity);
    }

    public X509CertificateWithMetaInfo getCertificate()
    {
        return cert;
    }

    public String getSignerConf()
    {
        return caEntry.getSignerConf();
    }

    public String getCrlSignerName()
    {
        return caEntry.getCrlSignerName();
    }

    public int getNumCrls()
    {
        return caEntry.getNumCrls();
    }

    public void setCrlSignerName(String crlSignerName)
    {
        caEntry.setCrlSignerName(crlSignerName);
    }

    public CAStatus getStatus()
    {
        return caEntry.getStatus();
    }

    public void setStatus(CAStatus status)
    {
        caEntry.setStatus(status);
    }

    public String getSignerType()
    {
        return caEntry.getSignerType();
    }

    public List<String> getCaIssuerLocations()
    {
        return caEntry.getCaIssuerLocations();
    }

    @Override
    public String toString()
    {
        return caEntry.toString(false);
    }

    public String toString(boolean verbose)
    {
        return caEntry.toString(verbose);
    }

    public DuplicationMode getDuplicateKeyMode()
    {
        return caEntry.getDuplicateKeyMode();
    }

    public void setDuplicateKeyMode(DuplicationMode mode)
    {
        caEntry.setDuplicateKeyMode(mode);
    }

    public DuplicationMode getDuplicateSubjectMode()
    {
        return caEntry.getDuplicateSubjectMode();
    }

    public void setDuplicateSubjectMode(DuplicationMode mode)
    {
        caEntry.setDuplicateSubjectMode(mode);
    }

    public ValidityMode getValidityMode()
    {
        return caEntry.getValidityMode();
    }

    public void setValidityMode(ValidityMode mode)
    {
        caEntry.setValidityMode(mode);
    }

    public Set<Permission> getPermissions()
    {
        return caEntry.getPermissions();
    }

    public void setPermissions(Set<Permission> permissions)
    {
        caEntry.setPermissions(permissions);
    }

    public CertRevocationInfo getRevocationInfo()
    {
        return caEntry.getRevocationInfo();
    }

    public void setRevocationInfo(CertRevocationInfo revocationInfo)
    {
        caEntry.setRevocationInfo(revocationInfo);
    }

    public int getExpirationPeriod()
    {
        return caEntry.getExpirationPeriod();
    }

    public int getLastCRLInterval()
    {
        return caEntry.getLastCRLInterval();
    }

    public void setLastCRLInterval(int lastInterval)
    {
        caEntry.setLastCRLInterval(lastInterval);
    }

    public long getLastCRLIntervalDate()
    {
        return caEntry.getLastCRLIntervalDate();
    }

    public void setLastCRLIntervalDate(long lastIntervalDate)
    {
        caEntry.setLastCRLIntervalDate(lastIntervalDate);
    }

    public BigInteger nextSerial()
    throws OperationException
    {
        if(useRandomSerialNumber)
        {
            return randomSNGenerator.getSerialNumber();
        }

        long serial = certStore.nextSerial(caEntry.getSerialSeqName());
        caEntry.setNextSerial(serial + 1);
        return BigInteger.valueOf(serial);
    }

    public boolean useRandomSerialNumber()
    {
        return useRandomSerialNumber;
    }
}
