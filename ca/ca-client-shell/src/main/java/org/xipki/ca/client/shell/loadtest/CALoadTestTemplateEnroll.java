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

package org.xipki.ca.client.shell.loadtest;

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.SchemaFactory;

import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.client.api.CertOrError;
import org.xipki.ca.client.api.EnrollCertResult;
import org.xipki.ca.client.api.PKIErrorException;
import org.xipki.ca.client.api.RAWorker;
import org.xipki.ca.client.api.RAWorkerException;
import org.xipki.ca.client.api.dto.EnrollCertRequestEntryType;
import org.xipki.ca.client.api.dto.EnrollCertRequestType;
import org.xipki.ca.client.api.dto.EnrollCertRequestType.Type;
import org.xipki.ca.client.shell.internal.loadtest.jaxb.EnrollCertType;
import org.xipki.ca.client.shell.internal.loadtest.jaxb.EnrollTemplateType;
import org.xipki.ca.client.shell.internal.loadtest.jaxb.ObjectFactory;
import org.xipki.ca.client.shell.loadtest.KeyEntry.DSAKeyEntry;
import org.xipki.ca.client.shell.loadtest.KeyEntry.ECKeyEntry;
import org.xipki.ca.client.shell.loadtest.KeyEntry.RSAKeyEntry;
import org.xipki.ca.client.shell.loadtest.LoadTestEntry.RandomDN;
import org.xipki.common.AbstractLoadTest;
import org.xipki.common.ConfigurationException;
import org.xipki.common.ParamChecker;
import org.xipki.common.util.XMLUtil;
import org.xml.sax.SAXException;

/**
 * @author Lijun Liao
 */

public class CALoadTestTemplateEnroll extends AbstractLoadTest
{
    private final static class CertRequestWithProfile
    {
        private final String certprofile;
        private final CertRequest certRequest;

        public CertRequestWithProfile(
                final String certprofile,
                final CertRequest certRequest)
        {
            this.certprofile = certprofile;
            this.certRequest = certRequest;
        }
    }

    class Testor implements Runnable
    {

        @Override
        public void run()
        {
            while(stop() == false && getErrorAccout() < 1)
            {
                Map<Integer, CertRequestWithProfile> certReqs = nextCertRequests();
                if(certReqs != null)
                {
                    boolean successful = testNext(certReqs);
                    account(1, successful ? 0 : 1);
                }
                else
                {
                    account(1, 1);
                }
            }
        }

        private boolean testNext(
                final Map<Integer, CertRequestWithProfile> certRequests)
        {
            EnrollCertResult result;
            try
            {
                EnrollCertRequestType request = new EnrollCertRequestType(Type.CERT_REQ);
                for(Integer certId : certRequests.keySet())
                {
                    CertRequestWithProfile certRequest = certRequests.get(certId);
                    EnrollCertRequestEntryType requestEntry = new EnrollCertRequestEntryType
                            ("id-" + certId, certRequest.certprofile, certRequest.certRequest, RA_VERIFIED);

                    request.addRequestEntry(requestEntry);
                }

                result = raWorker.requestCerts(request, null, userPrefix + System.currentTimeMillis(), null);
            } catch (RAWorkerException | PKIErrorException e)
            {
                LOG.warn("{}: {}", e.getClass().getName(), e.getMessage());
                return false;
            } catch (Throwable t)
            {
                LOG.warn("{}: {}", t.getClass().getName(), t.getMessage());
                return false;
            }

            if(result == null)
            {
                return false;
            }

            Set<String> ids = result.getAllIds();
            if(ids.size() < certRequests.size())
            {
                return false;
            }

            for(String id : ids)
            {
                CertOrError certOrError = result.getCertificateOrError(id);
                X509Certificate cert = (X509Certificate) certOrError.getCertificate();

                if(cert == null)
                {
                    return false;
                }
            }

            return true;
        }

    }

    private static final Logger LOG = LoggerFactory.getLogger(CALoadTestTemplateEnroll.class);
    private static final ProofOfPossession RA_VERIFIED = new ProofOfPossession();

    private static Object jaxbUnmarshallerLock = new Object();
    private static Unmarshaller jaxbUnmarshaller;

    private final RAWorker raWorker;
    private final String userPrefix = "LOADTEST-";
    private final List<LoadTestEntry> loadtestEntries;

    private final AtomicLong index;

    public CALoadTestTemplateEnroll(
            final RAWorker raWorker,
            final String templateFile)
    throws Exception
    {
        ParamChecker.assertNotNull("raWorker", raWorker);
        ParamChecker.assertNotEmpty("templateFile", templateFile);

        this.raWorker = raWorker;

        Calendar baseTime = Calendar.getInstance(Locale.UK);
        baseTime.set(Calendar.YEAR, 2014);
        baseTime.set(Calendar.MONTH, 0);
        baseTime.set(Calendar.DAY_OF_MONTH, 1);

        this.index = new AtomicLong(getSecureIndex());

        EnrollTemplateType template = parse(new FileInputStream(templateFile));

        List<EnrollCertType> list = template.getEnrollCert();
        loadtestEntries = new ArrayList<>(list.size());

        for(EnrollCertType entry : list)
        {
            KeyEntry keyEntry;
            if(entry.getEcKey() != null)
            {
                keyEntry = new ECKeyEntry(entry.getEcKey().getCurve());
            }
            else if(entry.getRsaKey() != null)
            {
                keyEntry = new RSAKeyEntry(entry.getRsaKey().getModulusLength());
            }
            else if(entry.getDsaKey() != null)
            {
                keyEntry = new DSAKeyEntry(entry.getDsaKey().getPLength());
            }
            else
            {
                throw new RuntimeException("should not reach here, unknown child of KeyEntry");
            }

            String randomDNStr = entry.getRandomDN();
            RandomDN randomDN = RandomDN.getInstance(randomDNStr);
            if(randomDN == null)
            {
                throw new ConfigurationException("invalid randomDN " + randomDNStr);
            }

            LoadTestEntry loadtestEntry = new LoadTestEntry(entry.getCertprofile(),
                    keyEntry, entry.getSubject(), randomDN);
            loadtestEntries.add(loadtestEntry);
        }
    }

    @Override
    protected Runnable getTestor()
    throws Exception
    {
        return new Testor();
    }

    public int getNumberOfCertsInOneRequest()
    {
        return loadtestEntries.size();
    }

    private Map<Integer, CertRequestWithProfile> nextCertRequests()
    {
        Map<Integer, CertRequestWithProfile> certRequests = new HashMap<>();
        final int n = loadtestEntries.size();
        for(int i = 0; i < n; i++)
        {
            LoadTestEntry loadtestEntry = loadtestEntries.get(i);
            final int certId = i + 1;
            CertTemplateBuilder certTempBuilder = new CertTemplateBuilder();

            long thisIndex = index.getAndIncrement();
            certTempBuilder.setSubject(loadtestEntry.getX500Name(thisIndex));

            SubjectPublicKeyInfo spki = loadtestEntry.getSubjectPublicKeyInfo(thisIndex);
            if(spki == null)
            {
                return null;
            }

            certTempBuilder.setPublicKey(spki);

            CertTemplate certTemplate = certTempBuilder.build();
            CertRequest certRequest = new CertRequest(certId, certTemplate, null);
            CertRequestWithProfile requestWithCertprofile = new CertRequestWithProfile(
                    loadtestEntry.getCertprofile(), certRequest);
            certRequests.put(certId, requestWithCertprofile);
        }
        return certRequests;
    }

    private static EnrollTemplateType parse(
            InputStream configStream)
    throws ConfigurationException
    {
        synchronized (jaxbUnmarshallerLock)
        {
            Object root;
            try
            {
                if(jaxbUnmarshaller == null)
                {
                    JAXBContext context = JAXBContext.newInstance(ObjectFactory.class);
                    jaxbUnmarshaller = context.createUnmarshaller();

                    final SchemaFactory schemaFact = SchemaFactory.newInstance(
                            javax.xml.XMLConstants.W3C_XML_SCHEMA_NS_URI);
                    URL url = ObjectFactory.class.getResource("/xsd/loadtest.xsd");
                    jaxbUnmarshaller.setSchema(schemaFact.newSchema(url));
                }

                root = jaxbUnmarshaller.unmarshal(configStream);
            }
            catch(SAXException e)
            {
                throw new ConfigurationException("parse profile failed, message: " + e.getMessage(), e);
            } catch(JAXBException e)
            {
                throw new ConfigurationException("parse profile failed, message: " + XMLUtil.getMessage((JAXBException) e), e);
            }

            if(root instanceof JAXBElement)
            {
                return (EnrollTemplateType) ((JAXBElement<?>)root).getValue();
            }
            else
            {
                throw new ConfigurationException("invalid root element type");
            }
        }
    }

}
