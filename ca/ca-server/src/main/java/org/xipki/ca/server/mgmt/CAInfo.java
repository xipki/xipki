/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
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
import org.xipki.ca.api.OperationException;
import org.xipki.ca.api.OperationException.ErrorCode;
import org.xipki.ca.common.CAStatus;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.PublicCAInfo;
import org.xipki.ca.server.mgmt.api.CAEntry;
import org.xipki.ca.server.mgmt.api.DuplicationMode;
import org.xipki.ca.server.mgmt.api.Permission;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CAInfo
{
    private static long MS_PER_DAY = 24L * 60 * 60 * 1000;

    private final CAEntry caEntry;

    private long noNewCertificateAfter;
    private BigInteger serialNumber;
    private Date notBefore;
    private Date notAfter;
    private boolean selfSigned;
    private CMPCertificate certInCMPFormat;
    private PublicCAInfo publicCAInfo;
    private long lastCommittedNextSerial;
    private X509CertificateWithMetaInfo cert;

    public CAInfo(CAEntry caEntry)
    throws OperationException
    {
        ParamChecker.assertNotNull("caEntry", caEntry);
        this.caEntry = caEntry;

        X509Certificate cert = caEntry.getCertificate();
        this.notBefore = cert.getNotBefore();
        this.notAfter = cert.getNotAfter();
        this.serialNumber = cert.getSerialNumber();
        this.selfSigned = cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
        this.lastCommittedNextSerial = caEntry.getNextSerial();

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
    }

    public long getLastCommittedNextSerial()
    {
        return lastCommittedNextSerial;
    }

    public void setLastCommittedNextSerial(long lastCommittedNextSerial)
    {
        this.lastCommittedNextSerial = lastCommittedNextSerial;
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

    public CAEntry getCaEntry()
    {
        return caEntry;
    }

    public String getName()
    {
        return caEntry.getName();
    }

    public long getNextSerial()
    {
        return caEntry.getNextSerial();
    }

    public void setNextSerial(long nextSerial)
    {
        caEntry.setNextSerial(nextSerial);
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

    public int getMaxValidity()
    {
        return caEntry.getMaxValidity();
    }

    public void setMaxValidity(int maxValidity)
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
}
