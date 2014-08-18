/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.api;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.xipki.ca.api.CAMgmtException;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CAEntry
{
    private static long DAY = 24L * 60 * 60 * 1000;

    private final String name;
    private final boolean selfSigned;
    private final BigInteger serialNumber;
    private final String subject;
    private final Date notBefore;
    private final Date notAfter;
    private CAStatus status;
    private final List<String> crlUris;
    private final List<String> deltaCrlUris;
    private final List<String> ocspUris;
    private final List<String> issuerLocations;
    private int maxValidity;
    private final X509CertificateWithMetaInfo cert;
    private final CMPCertificate certInCMPFormat;
    private String signerType;
    private String signerConf;
    private String crlSignerName;
    private long lastCommittedNextSerial;
    private long nextSerial;
    private DuplicationMode duplicateKeyMode;
    private DuplicationMode duplicateSubjectMode;
    private ValidityMode validityMode = ValidityMode.STRICT;
    private Set<Permission> permissions;
    private int numCrls;
    private final int expirationPeriod;
    private final long noNewCertificateAfter;
    private CertRevocationInfo revocationInfo;

    private PublicCAInfo publicCAInfo;

    public CAEntry(String name, long initialSerial,
            String signerType, String signerConf, X509Certificate cert,
            List<String> ocspUris, List<String> crlUris, List<String> deltaCrlUris,
            List<String> issuerLocations, int numCrls,
            int expirationPeriod)
    throws CAMgmtException
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotEmpty("signerType", signerType);
        ParamChecker.assertNotNull("cert", cert);

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

        this.name = name;
        this.nextSerial = initialSerial;

        Certificate bcCert;
        try
        {
            bcCert = Certificate.getInstance(cert.getEncoded());
            this.cert = new X509CertificateWithMetaInfo(cert, cert.getEncoded());
        } catch (CertificateEncodingException e)
        {
            throw new CAMgmtException("could not encode the CA certificate");
        }

        this.subject = IoCertUtil.canonicalizeName(cert.getSubjectX500Principal());
        this.notBefore = cert.getNotBefore();
        this.notAfter = cert.getNotAfter();
        this.serialNumber = cert.getSerialNumber();
        this.selfSigned = cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
        this.certInCMPFormat = new CMPCertificate(bcCert);

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

        this.publicCAInfo = new PublicCAInfo(this.cert.getCert(),
                this.ocspUris, this.crlUris, this.issuerLocations, this.deltaCrlUris);

        this.noNewCertificateAfter = this.cert.getCert().getNotAfter().getTime() - DAY * expirationPeriod;
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

    public PublicCAInfo getPublicCAInfo()
    {
        return publicCAInfo;
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

    public int getMaxValidity()
    {
        return maxValidity;
    }

    public void setMaxValidity(int maxValidity)
    {
        this.maxValidity = maxValidity;
    }

    public X509CertificateWithMetaInfo getCertificate()
    {
        return cert;
    }

    public String getSubject()
    {
        return subject;
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
        sb.append("signer_conf: ").append(signerConf).append('\n');
        sb.append("cert: ").append("\n");
        sb.append("\tissuer: ").append(
                IoCertUtil.canonicalizeName(cert.getCert().getIssuerX500Principal())).append("\n");
        sb.append("\tserialNumber: ").append(cert.getCert().getSerialNumber()).append("\n");
        sb.append("\tsubject: ").append(subject).append("\n");
        sb.append("\tnotBefore: ").append(notBefore).append("\n");
        sb.append("\tnotAfter: ").append(notAfter).append("\n");
        if(verbose)
        {
            sb.append("\tEncoded: ").append(Base64.toBase64String(cert.getEncodedCert())).append("\n");
        }
        sb.append("crlsigner_name: ").append(crlSignerName).append('\n');
        sb.append("duplicateKey: ").append(duplicateKeyMode.getDescription()).append('\n');
        sb.append("duplicateSubject: ").append(duplicateSubjectMode.getDescription()).append('\n');
        sb.append("validityMode: ").append(validityMode).append('\n');
        sb.append("permissions: ").append(Permission.toString(permissions));

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

    public long getLastCommittedNextSerial()
    {
        return lastCommittedNextSerial;
    }

    public void setLastCommittedNextSerial(long lastCommittedNextSerial)
    {
        this.lastCommittedNextSerial = lastCommittedNextSerial;
    }

    public CMPCertificate getCertInCMPFormat()
    {
        return certInCMPFormat;
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

    public long getNoNewCertificateAfter()
    {
        return noNewCertificateAfter;
    }

}
