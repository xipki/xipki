/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.mgmt;

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.ca.api.CAMgmtException;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.ca.server.PublicCAInfo;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

public class CAEntry
{
    private final String name;
    private final boolean selfSigned;
    private final BigInteger serialNumber;
    private final String subject;
    private CAStatus status;
    private final List<String> crlUris;
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
    private boolean allowDuplicateKey;
    private boolean allowDuplicateSubject;
    private Set<Permission> permissions;
    private int numCrls;
    private CertRevocationInfo revocationInfo;

    private PublicCAInfo publicCAInfo;

    public CAEntry(String name, long initialSerial,
            String signerType, String signerConf, X509Certificate cert,
            List<String> ocspUris, List<String> crlUris,
            List<String> issuerLocations, Integer numCrls)
    throws CAMgmtException
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotEmpty("signerType", signerType);
        ParamChecker.assertNotNull("cert", cert);

        if(initialSerial < 0)
        {
            throw new IllegalArgumentException("initialSerial is negative (" + initialSerial + " < 0)");
        }

        if(numCrls == null)
        {
            this.numCrls = 30;
        }
        else if(numCrls >= 0)
        {
            this.numCrls = numCrls;
        }
        else
        {
            throw new IllegalArgumentException("numCrls could not be negative");
        }

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
        this.serialNumber = cert.getSerialNumber();
        this.selfSigned = cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal());
        this.certInCMPFormat = new CMPCertificate(bcCert);

        this.signerType = signerType;
        this.signerConf = signerConf;

        this.ocspUris = (ocspUris == null) ?
                null : Collections.unmodifiableList(new ArrayList<String>(ocspUris));
        this.crlUris = (crlUris == null) ?
                null : Collections.unmodifiableList(new ArrayList<String>(crlUris));
        this.issuerLocations = (issuerLocations == null) ?
                null : Collections.unmodifiableList(new ArrayList<String>(issuerLocations));

        this.publicCAInfo = new PublicCAInfo(this.cert.getCert(),
                this.ocspUris, this.crlUris, this.issuerLocations);
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
        StringBuilder sb = new StringBuilder();
        sb.append("name: ").append(name).append('\n');
        sb.append("next_serial: ").append(nextSerial).append('\n');
        sb.append("status: ").append(status.getStatus()).append('\n');
        sb.append("crl_uris: ").append(getCrlUrisAsString()).append('\n');
        sb.append("ocsp_uris: ").append(getOcspUrisAsString()).append('\n');
        sb.append("max_validity: ").append(maxValidity).append('\n');
        sb.append("signer_type: ").append(signerType).append('\n');
        sb.append("signer_conf: ").append(signerConf).append('\n');
        sb.append("cert: ").append("\n");
        sb.append("\tissuer: ").append(
                IoCertUtil.canonicalizeName(cert.getCert().getIssuerX500Principal())).append("\n");
        sb.append("\tserialNumber: ").append(cert.getCert().getSerialNumber()).append("\n");
        sb.append("\tsubject: ").append(subject).append("\n");
        sb.append("crlsigner_name: ").append(crlSignerName).append('\n');
        sb.append("allowDuplicateKey: ").append(allowDuplicateKey).append('\n');
        sb.append("allowDuplicateSubject: ").append(allowDuplicateSubject);
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

    public boolean isAllowDuplicateKey()
    {
        return allowDuplicateKey;
    }

    public void setAllowDuplicateKey(boolean allowDuplicateKey)
    {
        this.allowDuplicateKey = allowDuplicateKey;
    }

    public boolean isAllowDuplicateSubject()
    {
        return allowDuplicateSubject;
    }

    public void setAllowDuplicateSubject(boolean allowDuplicateSubject)
    {
        this.allowDuplicateSubject = allowDuplicateSubject;
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

}
