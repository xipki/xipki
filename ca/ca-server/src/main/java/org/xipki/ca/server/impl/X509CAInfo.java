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

package org.xipki.ca.server.impl;

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
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.api.X509CertWithDBCertId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.impl.store.CertificateStore;
import org.xipki.ca.server.mgmt.api.CAStatus;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.api.X509CAEntry;
import org.xipki.common.CertRevocationInfo;
import org.xipki.common.ParamChecker;
import org.xipki.security.api.ConcurrentContentSigner;
import org.xipki.security.api.SecurityFactory;
import org.xipki.security.api.SignerException;

/**
 * @author Lijun Liao
 */

class X509CAInfo
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

    private CertificateStore certStore;
    private boolean useRandomSerialNumber;
    private RandomSerialNumberGenerator randomSNGenerator;
    private ConcurrentContentSigner signer;

    public X509CAInfo(
            final X509CAEntry caEntry,
            final CertificateStore certStore)
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
            bcCert = Certificate.getInstance(encodedCert);
        } catch (CertificateEncodingException e)
        {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE, "could not encode the CA certificate");
        }
        this.certInCMPFormat = new CMPCertificate(bcCert);

        this.publicCAInfo = new PublicCAInfo(cert,
                caEntry.getCacertUris(),
                caEntry.getOcspUris(),
                caEntry.getCrlUris(),
                caEntry.getDeltaCrlUris());

        this.noNewCertificateAfter = this.notAfter.getTime() - MS_PER_DAY * caEntry.getExpirationPeriod();

        this.useRandomSerialNumber = caEntry.getNextSerial() < 1;
        if(this.useRandomSerialNumber)
        {
            randomSNGenerator = RandomSerialNumberGenerator.getInstance();
            return;
        }

        Long greatestSerialNumber = certStore.getGreatestSerialNumber(this.publicCAInfo.getCaCertificate());

        if(greatestSerialNumber == null)
        {
            throw new OperationException(ErrorCode.SYSTEM_FAILURE,
                    "could not retrieve the greatest serial number for ca " + caEntry.getName());
        }

        long nextSerial = greatestSerialNumber + 1;
        if(nextSerial < 2)
        {
            nextSerial = 2;
        }

        if(caEntry.getNextSerial() < nextSerial)
        {
            LOG.info("corrected the next_serial of {} from {} to {}",
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
        if(useRandomSerialNumber == false)
        {
            certStore.commitNextSerialIfLess(caEntry.getName(), caEntry.getNextSerial());
        }
    }

    public void commitNextCrlNo()
    throws OperationException
    {
        certStore.commitNextCrlNo(caEntry.getName(), caEntry.getNextCRLNumber());
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

    public void setMaxValidity(
            final CertValidity maxValidity)
    {
        caEntry.setMaxValidity(maxValidity);
    }

    public X509CertWithDBCertId getCertificate()
    {
        return publicCAInfo.getCaCertificate();
    }

    public String getSignerConf()
    {
        return caEntry.getSignerConf();
    }

    public String getCrlSignerName()
    {
        return caEntry.getCrlSignerName();
    }

    public void setCrlSignerName(
            final String crlSignerName)
    {
        caEntry.setCrlSignerName(crlSignerName);
    }

    public String getCmpControlName()
    {
        return caEntry.getCmpControlName();
    }

    public void setCmpControlName(
            final String name)
    {
        caEntry.setCmpControlName(name);
    }

    public int getNumCrls()
    {
        return caEntry.getNumCrls();
    }

    public CAStatus getStatus()
    {
        return caEntry.getStatus();
    }

    public void setStatus(
            final CAStatus status)
    {
        caEntry.setStatus(status);
    }

    public String getSignerType()
    {
        return caEntry.getSignerType();
    }

    @Override
    public String toString()
    {
        return caEntry.toString(false);
    }

    public String toString(
            final boolean verbose)
    {
        return caEntry.toString(verbose);
    }

    public DuplicationMode getDuplicateKeyMode()
    {
        return caEntry.getDuplicateKeyMode();
    }

    public void setDuplicateKeyMode(
            final DuplicationMode mode)
    {
        caEntry.setDuplicateKeyMode(mode);
    }

    public DuplicationMode getDuplicateSubjectMode()
    {
        return caEntry.getDuplicateSubjectMode();
    }

    public void setDuplicateSubjectMode(
            final DuplicationMode mode)
    {
        caEntry.setDuplicateSubjectMode(mode);
    }

    public ValidityMode getValidityMode()
    {
        return caEntry.getValidityMode();
    }

    public void setValidityMode(
            final ValidityMode mode)
    {
        caEntry.setValidityMode(mode);
    }

    public Set<Permission> getPermissions()
    {
        return caEntry.getPermissions();
    }

    public void setPermissions(
            final Set<Permission> permissions)
    {
        caEntry.setPermissions(permissions);
    }

    public CertRevocationInfo getRevocationInfo()
    {
        return caEntry.getRevocationInfo();
    }

    public void setRevocationInfo(
            final CertRevocationInfo revocationInfo)
    {
        caEntry.setRevocationInfo(revocationInfo);
    }

    public int getExpirationPeriod()
    {
        return caEntry.getExpirationPeriod();
    }

    public Date getCrlBaseTime()
    {
        return caEntry.getCrlBaseTime();
    }

    public BigInteger nextSerial()
    throws OperationException
    {
        if(useRandomSerialNumber)
        {
            return randomSNGenerator.getSerialNumber();
        }

        long serial = certStore.nextSerial(getCertificate(), caEntry.getSerialSeqName());
        caEntry.setNextSerial(serial + 1);
        return BigInteger.valueOf(serial);
    }

    public void markMaxSerial()
    throws OperationException
    {
        if(useRandomSerialNumber == false)
        {
            certStore.markMaxSerial(getCertificate(), caEntry.getSerialSeqName());
        }
    }

    public BigInteger nextCRLNumber()
    throws OperationException
    {
        int crlNo = caEntry.getNextCRLNumber();
        int currentMaxNo = certStore.getMaxCRLNumber(getCertificate());
        if(crlNo <= currentMaxNo)
        {
            crlNo = currentMaxNo + 1;
        }
        caEntry.setNextCRLNumber(crlNo + 1);
        return BigInteger.valueOf(crlNo);
    }

    public boolean useRandomSerialNumber()
    {
        return useRandomSerialNumber;
    }

    public ConcurrentContentSigner getSigner()
    {
        return signer;
    }

    public boolean initSigner(
            final SecurityFactory securityFactory)
    throws SignerException
    {
        if(signer != null)
        {
            return true;
        }

        this.signer = securityFactory.createSigner(caEntry.getSignerType(), caEntry.getSignerConf(),
                caEntry.getCertificate());
        return true;
    }

    public boolean isSignerRequired()
    {
        Set<Permission> permissions = caEntry.getPermissions();
        if(permissions == null)
        {
            return true;
        }

        boolean signerRequired = false;
        for(Permission permission : permissions)
        {
            switch(permission)
            {
            case REMOVE_CERT:
            case UNREVOKE_CERT:
            case REVOKE_CERT:
                break;
            default:
                signerRequired = true;
                break;
            } // end switch(permission)

            if(signerRequired)
            {
                break;
            }
        }

        return signerRequired;
    }

}
