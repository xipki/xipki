/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security.shell;

import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.security.EdECConstants;
import org.xipki.shell.EnumCompleter;

import java.util.LinkedList;
import java.util.List;

/**
 * Completers for QA shells.
 *
 * @author Lijun Liao
 */

public class QaCompleters {

  @Service
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

  } // class DSASigAlgCompleter

  @Service
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

  } // class ECDSASigAlgCompleter

  @Service
  public static class EDDSASigAlgCompleter extends EnumCompleter {

    public EDDSASigAlgCompleter() {
      setTokens(EdECConstants.ED25519, EdECConstants.ED448);
    }

  } // class EDDSASigAlgCompleter

  @Service
  public static class GMACSigAlgCompleter extends EnumCompleter {

    public GMACSigAlgCompleter() {
      setTokens("AES128-GMAC", "AES192-GMAC", "AES256-GMAC");
    }

  } // class GMACSigAlgCompleter

  @Service
  public static class HMACSigAlgCompleter extends EnumCompleter {

    public HMACSigAlgCompleter() {
      setTokens("HMACSHA1", "HMACSHA224", "HMACSHA256", "HMACSHA384", "HMACSHA512",
          "HMACSHA3-224", "HMACSHA3-256", "HMACSHA3-384", "HMACSHA3-512");
    }

  } // class HMACSigAlgCompleter

  @Service
  public static class RSASigAlgCompleter extends EnumCompleter {

    public RSASigAlgCompleter() {
      String[] hashAlgs = {"SHA1", "SHA224", "SHA256", "SHA384", "SHA512",
          "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};
      List<String> enums = new LinkedList<>();
      for (String hashAlg : hashAlgs) {
        enums.add(hashAlg + "withRSA");
        enums.add(hashAlg + "withRSAandMGF1");
      }
      setTokens(enums);
    }

  } // class RSASigAlgCompleter

}
