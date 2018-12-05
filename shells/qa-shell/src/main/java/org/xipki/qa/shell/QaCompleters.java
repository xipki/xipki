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

import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.qa.ca.CaQaSystemManager;
import org.xipki.qa.ocsp.OcspCertStatus;
import org.xipki.qa.ocsp.OcspError;
import org.xipki.shell.AbstractDynamicEnumCompleter;
import org.xipki.shell.AbstractEnumCompleter;
import org.xipki.util.TripleState;

/**
 * TODO.
 * @author Lijun Liao
 */

public class QaCompleters {

  @Service
  public static class CertprofileNameCompleter extends AbstractDynamicEnumCompleter {

    @Reference
    private CaQaSystemManager qaSystemManager;

    @Override
    protected Set<String> getEnums() {
      return qaSystemManager.getCertprofileNames();
    }

  }

  public static class CertStatusCompleter extends AbstractEnumCompleter {

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
  public static class DSASigAlgCompleter extends AbstractEnumCompleter {

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
  public static class ECDSASigAlgCompleter extends AbstractEnumCompleter {

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
  public static class GMACSigAlgCompleter extends AbstractEnumCompleter {

    public GMACSigAlgCompleter() {
      setTokens("AES128-GMAC", "AES192-GMAC", "AES256-GMAC");
    }

  }

  @Service
  public static class IssuerNameCompleter extends AbstractDynamicEnumCompleter {

    @Reference
    private CaQaSystemManager qaSystemManager;

    @Override
    protected Set<String> getEnums() {
      return qaSystemManager.getIssuerNames();
    }

  }

  @Service
  //CHECKSTYLE:SKIP
  public static class HMACSigAlgCompleter extends AbstractEnumCompleter {

    public HMACSigAlgCompleter() {
      setTokens("HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512",
          "HMACSHA3-224", "HMACSHA3-256", "HMACSHA3-384", "HMACSHA3-512");
    }

  }

  @Service
  public static class OccurrenceCompleter extends AbstractEnumCompleter {

    public OccurrenceCompleter() {
      List<String> enums = new LinkedList<>();
      for (TripleState entry : TripleState.values()) {
        enums.add(entry.name());
      }
      setTokens(enums);
    }

  }

  @Service
  public static class OcspErrorCompleter extends AbstractEnumCompleter {

    public OcspErrorCompleter() {
      List<String> enums = new LinkedList<>();
      for (OcspError entry : OcspError.values()) {
        enums.add(entry.name());
      }
      setTokens(enums);
    }

  }

  @Service
  //CHECKSTYLE:SKIP
  public static class RSASigAlgCompleter extends AbstractEnumCompleter {

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
