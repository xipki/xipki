/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.qa.shell;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.qa.ca.CaQaSystemManager;
import org.xipki.qa.ocsp.OcspCertStatus;
import org.xipki.qa.ocsp.OcspError;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.shell.DynamicEnumCompleter;
import org.xipki.shell.EnumCompleter;
import org.xipki.util.CollectionUtil;
import org.xipki.util.TripleState;

/**
 * TODO.
 * @author Lijun Liao
 */

public class QaCompleters {

  @Service
  public static class CertprofileNameCompleter extends DynamicEnumCompleter {

    @Reference
    private CaQaSystemManager qaSystemManager;

    @Override
    protected Set<String> getEnums() {
      return qaSystemManager.getCertprofileNames();
    }

  }

  public static class CertStatusCompleter extends EnumCompleter {

    public CertStatusCompleter() {
      List<String> enums = new LinkedList<>();
      for (OcspCertStatus entry : OcspCertStatus.values()) {
        enums.add(entry.name());
      }
      setTokens(enums);
    }

  }

  @Service
  //CHECKSTYLE:SKIP
  public static class DSASigAlgCompleter extends EnumCompleter {

    public DSASigAlgCompleter() {
      String[] hashAlgs = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
        "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};
      List<String> enums = new LinkedList<>();
      for (String hashAlg : hashAlgs) {
        enums.add(hashAlg + "withDSA");
      }
      setTokens(enums);
    }

  }

  @Service
  //CHECKSTYLE:SKIP
  public static class ECDSASigAlgCompleter extends EnumCompleter {

    public ECDSASigAlgCompleter() {
      String[] hashAlgs = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
        "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};
      List<String> enums = new LinkedList<>();
      for (String hashAlg : hashAlgs) {
        enums.add(hashAlg + "withECDSA");
      }
      hashAlgs = new String[]{"SHA1", "SHA224", "SHA256", "SHA384", "SHA512"};
      for (String hashAlg : hashAlgs) {
        enums.add(hashAlg + "withPlainECDSA");
      }
      setTokens(enums);
    }

  }

  @Service
  //CHECKSTYLE:SKIP
  public static class GMACSigAlgCompleter extends EnumCompleter {

    public GMACSigAlgCompleter() {
      setTokens("AES128-GMAC", "AES192-GMAC", "AES256-GMAC");
    }

  }

  @Service
  public static class IssuerNameCompleter extends DynamicEnumCompleter {

    @Reference
    private CaQaSystemManager qaSystemManager;

    @Override
    protected Set<String> getEnums() {
      return qaSystemManager.getIssuerNames();
    }

  }

  @Service
  //CHECKSTYLE:SKIP
  public static class HMACSigAlgCompleter extends EnumCompleter {

    public HMACSigAlgCompleter() {
      setTokens("HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512",
          "HMACSHA3-224", "HMACSHA3-256", "HMACSHA3-384", "HMACSHA3-512");
    }

  }

  @Service
  public static class OccurrenceCompleter extends EnumCompleter {

    public OccurrenceCompleter() {
      List<String> enums = new LinkedList<>();
      for (TripleState entry : TripleState.values()) {
        enums.add(entry.name());
      }
      setTokens(enums);
    }

  }

  @Service
  public static class OcspErrorCompleter extends EnumCompleter {

    public OcspErrorCompleter() {
      List<String> enums = new LinkedList<>();
      for (OcspError entry : OcspError.values()) {
        enums.add(entry.name());
      }
      setTokens(enums);
    }

  }

  @Service
  public static class P11ModuleNameCompleter extends DynamicEnumCompleter {

    @Reference (optional = true)
    private P11CryptServiceFactory p11CryptServiceFactory;

    @Override
    protected Set<String> getEnums() {
      Set<String> names = p11CryptServiceFactory.getModuleNames();
      if (CollectionUtil.isEmpty(names)) {
        return Collections.emptySet();
      }
      return names;
    }

  }

  @Service
  //CHECKSTYLE:SKIP
  public static class RSASigAlgCompleter extends EnumCompleter {

    public RSASigAlgCompleter() {
      String[] hashAlgs = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
        "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};
      List<String> enums = new LinkedList<>();
      for (String hashAlg : hashAlgs) {
        enums.add(hashAlg + "withRSA");
        enums.add(hashAlg + "RSAandMGF1");
      }
      setTokens(enums);
    }

  }
}
