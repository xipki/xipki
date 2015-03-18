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

package org.xipki.security.p11.sun.nss;

import java.io.ByteArrayInputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * @author Lijun Liao
 */

@SuppressWarnings("restriction")
public class XipkiNSSProvider
extends Provider
{
    // Signature
    public static final String OID_SHA1withRSA = "1.2.840.113549.1.1.5";
    public static final String OID_SHA224withRSA = "1.2.840.113549.1.1.14";
    public static final String OID_SHA256withRSA = "1.2.840.113549.1.1.11";
    public static final String OID_SHA384withRSA = "1.2.840.113549.1.1.12";
    public static final String OID_SHA512withRSA = "1.2.840.113549.1.1.13";
    public static final String OID_SHA1withDSA = "1.2.840.10040.4.3";
    public static final String OID_SHA1withECDSA   = "1.2.840.10045.4.1";
    public static final String OID_SHA224withECDSA = "1.2.840.10045.4.3.1";
    public static final String OID_SHA256withECDSA = "1.2.840.10045.4.3.2";
    public static final String OID_SHA384withECDSA = "1.2.840.10045.4.3.3";
    public static final String OID_SHA512withECDSA = "1.2.840.10045.4.3.4";
    // Asymmetric Encryption
    public static final String OID_RSAENC = "1.2.840.113549.1.1.1";
    public static final String OID_DSAENC = "1.2.840.10040.4.1";

    private static final long serialVersionUID = 1L;
    public static final String PROVIDER_NAME = "XipkiNSS";
    public static final double PROVIDER_VERSION = 1.0;

    static Provider nssProvider;

    public XipkiNSSProvider()
    {
        super(PROVIDER_NAME, PROVIDER_VERSION, PROVIDER_NAME + " v" + PROVIDER_VERSION);

        init();

        AccessController.doPrivileged(
        new PrivilegedAction<Object>()
        {
            public Object run()
            {
                Iterator<Descriptor> it = descriptors.values().iterator();
                while(it.hasNext())
                {
                    Descriptor d = it.next();
                    put(d.service.type + "." + d.algorithm, d.getClassName());
                    if(d.aliases != null)
                    {
                        List<String> aliases = d.getAliases();
                        for (String alias : aliases)
                        {
                            put("Alg.Alias." + d.service.type + "." + alias, d.algorithm);
                        }
                    }
                }
                return null;
            }
        });
    }

    private static boolean support(Descriptor d)
    {
        try
        {
            Object o = Class.forName(d.getClassName()).newInstance();
            return (o != null);
        }catch(Throwable t)
        {
            return false;
        }
    }

    // Map from mechanism to List of Descriptors that should be registered if the mechanism is supported
    private final static Map<String, Descriptor> descriptors = new HashMap<>();

    private synchronized static void init()
    {
        if(nssProvider != null)
        {
            return;
        }

        try
        {
            // check whether there exists an NSS provider registered by OpenJDK
            nssProvider = Security.getProvider("SunPKCS11-NSS");
            if(nssProvider == null)
            {
                StringBuilder sb = new StringBuilder();
                sb.append("name=").append(PROVIDER_NAME).append("\n");
                sb.append("nssDbMode=noDb\n");
                sb.append("attributes=compatibility\n");
                String NSSLIB = System.getProperty("NSSLIB");
                if(NSSLIB != null)
                {
                    sb.append("\nnssLibraryDirectory=").append(NSSLIB);
                }

                nssProvider = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(sb.toString().getBytes()));
                Security.addProvider(nssProvider);
            }
        }catch(Throwable t)
        {
            throw new ProviderException("could not initialize SunPKCS11 NSS provider", t);
        }

        // Signature RSA
        regist(Service.Signature, "SHA1withRSA",   "SHA1withRSA",   OID_SHA1withRSA);
        regist(Service.Signature, "SHA224withRSA", "SHA224withRSA", OID_SHA224withRSA);
        regist(Service.Signature, "SHA256withRSA", "SHA256withRSA", OID_SHA256withRSA);
        regist(Service.Signature, "SHA384withRSA", "SHA384withRSA", OID_SHA384withRSA);
        regist(Service.Signature, "SHA512withRSA", "SHA512withRSA", OID_SHA512withRSA);

        // Signature ECDSA
        regist(Service.Signature, "SHA1withECDSA",   "SHA1withECDSA",   OID_SHA1withECDSA);
        regist(Service.Signature, "SHA224withECDSA", "SHA224withECDSA", OID_SHA224withECDSA);
        regist(Service.Signature, "SHA256withECDSA", "SHA256withECDSA", OID_SHA256withECDSA);
        regist(Service.Signature, "SHA384withECDSA", "SHA384withECDSA", OID_SHA384withECDSA);
        regist(Service.Signature, "SHA512withECDSA", "SHA512withECDSA", OID_SHA512withECDSA);
        regist(Service.Signature, "RawECDSA", "RawECDSA", OID_DSAENC, "NONEWithECDSA");
    }

    private static void regist(Service service, String algorithm, String className, String oid, String... aliases)
    {
        Descriptor d = new Descriptor(service, algorithm, className, oid, aliases);
        if(support(d))
        {
            descriptors.put(d.toString(), d);
        }
    }

    public static final class Descriptor
    {
        private final Service service;
        private final String algorithm;
        private final String className;
        private final String oid;
        private final String[] aliases;

        private Descriptor(Service service, String algorithm,
            String classNameWithoutPackage, String oid,
            String... aliases)
        {
            this.service = service;
            this.algorithm = algorithm;
            this.className = classNameWithoutPackage;
            this.oid = oid;
            this.aliases = aliases;
        }

        private List<String> aliasesWithOid;
        List<String> getAliases()
        {
            if(aliasesWithOid == null)
            {
                aliasesWithOid = new ArrayList<>();
                if(aliases != null)
                {
                    for (String alias : aliases)
                    {
                        aliasesWithOid.add(alias);
                    }
                }
                if(oid != null)
                {
                    aliasesWithOid.add(oid);
                    aliasesWithOid.add("OID." + oid);
                }
            }

            return aliasesWithOid;
        }

        public String getClassName()
        {
            return service.classPrefix + className;
        }

        @Override
        public String toString()
        {
            return service.type + "." + algorithm;
        }

        @Override
        public int hashCode()
        {
            return toString().hashCode();
        }
    }

    private static enum Service
    {
        Signature("Signature", NSSSignatureSpi.class.getName() + "$");

        private String type;
        private String classPrefix;
        private Service(String type, String classPrefix)
        {
            this.type = type;
            this.classPrefix = classPrefix;
        }
    }

}
