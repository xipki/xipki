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

package org.xipki.ca.mgmt.shell;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.api.mgmt.*;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.security.CrlReason;
import org.xipki.security.X509Cert;
import org.xipki.shell.DynamicEnumCompleter;
import org.xipki.shell.EnumCompleter;

import java.util.*;

/**
 * Completers for the CA actions.
 *
 * @author Lijun Liao
 */
public class CaCompleters {

  public abstract static class CaMgmtCompleter extends DynamicEnumCompleter {

    @Reference
    protected CaManager caManager;

  } // class CaMgmtCompleter

  @Service
  public static class CaAliasCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      try {
        return caManager.getCaAliasNames();
      } catch (CaMgmtException ex) {
        return Collections.emptySet();
      }
    }

  } // class CaAliasCompleter

  @Service
  public static class CaCrlReasonCompleter extends EnumCompleter {

    public CaCrlReasonCompleter() {
      List<String> enums = new LinkedList<>();
      for (CrlReason reason : CaActions.CaRevoke.PERMITTED_REASONS) {
        enums.add(reason.getDescription());
      }
      setTokens(enums);
    }

  } // class CaCrlReasonCompleter

  @Service
  public static class CaNameCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      try {
        return caManager.getCaNames();
      } catch (CaMgmtException ex) {
        return Collections.emptySet();
      }
    }

  } // class CaNameCompleter

  @Service
  public static class CaNamePlusAllCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      Set<String> ret;
      try {
        ret = new HashSet<>(caManager.getCaNames());
      } catch (CaMgmtException ex) {
        ret = new HashSet<>();
      }
      ret.add("all");
      return ret;
    }

  } // class CaNamePlusAllCompleter

  @Service
  public static class CaStatusCompleter extends EnumCompleter {

    public CaStatusCompleter() {
      setTokens("active", "inactive");
    }

  } // class CaStatusCompleter

  @Service
  public static class CertListSortByCompleter extends EnumCompleter {

    public CertListSortByCompleter() {
      List<String> enums = new LinkedList<>();
      for (CertListOrderBy sort : CertListOrderBy.values()) {
        enums.add(sort.getText());
      }
      setTokens(enums);
    }

  } // class

  @Service
  public static class KeypairGenNameCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      try {
        return caManager.getKeypairGenNames();
      } catch (CaMgmtException ex) {
        return Collections.emptySet();
      }
    }

  } // class ProfileNameCompleter

  @Service
  public static class KeypairGenTypeCompleter extends EnumCompleter {

    public KeypairGenTypeCompleter() {
      setTokens("PKCS11", "DATABASE");
    }
  } // class KeypairGenTypeCompleter

  @Service
  public static class PermissionCompleter extends EnumCompleter {

    public PermissionCompleter() {
      setTokens("enroll_cert", "revoke_cert", "unrevoke_cert", "remove_cert",
          "key_update", "gen_crl", "get_crl", "enroll_cross", "all");
    }
  } // class PermissionCompleter

  @Service
  public static class ProfileNameAndAllCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      Set<String> ret;
      try {
        ret = new HashSet<>(caManager.getCertprofileNames());
      } catch (CaMgmtException ex) {
        ret = new HashSet<>();
      }
      ret.add("all");
      return ret;
    }

  } // class ProfileNameAndAllCompleter

  @Service
  public static class ProfileNameCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      try {
        return caManager.getCertprofileNames();
      } catch (CaMgmtException ex) {
        return Collections.emptySet();
      }
    }

  } // class ProfileNameCompleter

  @Service
  public static class ProfileTypeCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      try {
        return caManager.getSupportedCertprofileTypes();
      } catch (CaMgmtException ex) {
        return Collections.emptySet();
      }
    }

  } // class ProfileTypeCompleter

  @Service
  public static class PublisherNameCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      try {
        return caManager.getPublisherNames();
      } catch (CaMgmtException ex) {
        return Collections.emptySet();
      }
    }

  } // class PublisherNameCompleter

  @Service
  public static class PublisherNamePlusAllCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      Set<String> ret;
      try {
        ret = new HashSet<>(caManager.getPublisherNames());
      } catch (CaMgmtException ex) {
        ret = new HashSet<>();
      }
      ret.add("all");
      return ret;
    }

  } // class PublisherNamePlusAllCompleter

  @Service
  public static class PublisherTypeCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      try {
        return caManager.getSupportedPublisherTypes();
      } catch (CaMgmtException ex) {
        return Collections.emptySet();
      }
    }

  } // class PublisherTypeCompleter

  @Service
  public static class RcaNameCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      Set<String> caNames;
      try {
        caNames = caManager.getCaNames();
      } catch (CaMgmtException ex) {
        return Collections.emptySet();
      }

      Set<String> ret = new HashSet<>();

      for (String name : caNames) {
        CaEntry caEntry;
        try {
          caEntry = caManager.getCa(name);
        } catch (CaMgmtException ex) {
          continue;
        }

        X509Cert cert = caEntry.getCert();
        if (cert.isSelfSigned()) {
          ret.add(name);
        }
      }
      return ret;
    }

  } // class RcaNameCompleter

  @Service
  public static class RequestorNameCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      Set<String> names = new HashSet<>();
      try {
        names.addAll(caManager.getRequestorNames());
      } catch (CaMgmtException ex) {
        // CHECKSTYLE:SKIP
      }
      names.remove(RequestorInfo.NAME_BY_CA);
      names.remove(RequestorInfo.NAME_BY_USER);
      names.remove(RequestorInfo.NAME_BY_CA.toUpperCase());
      names.remove(RequestorInfo.NAME_BY_USER.toUpperCase());
      return names;
    }

  } // class RequestorNameCompleter

  @Service
  public static class SignerNameCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      try {
        return caManager.getSignerNames();
      } catch (CaMgmtException ex) {
        return Collections.emptySet();
      }
    }
  } // class SignerNameCompleter

  @Service
  public static class SignerNamePlusNullCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      Set<String> ret = new HashSet<>();
      try {
        ret.addAll(caManager.getSignerNames());
      } catch (CaMgmtException ex) {
        // CHECKSTYLE:SKIP
      }
      ret.add(CaManager.NULL);
      return ret;
    }

  } // class SignerNamePlusNullCompleter

  @Service
  public static class SignerTypeCompleter extends CaMgmtCompleter {

    @Override
    protected Set<String> getEnums() {
      try {
        return caManager.getSupportedSignerTypes();
      } catch (CaMgmtException ex) {
        return Collections.emptySet();
      }
    }

  } // class SignerTypeCompleter

  @Service
  public static class ValidityModeCompleter extends EnumCompleter {

    public ValidityModeCompleter() {
      List<String> enums = new LinkedList<>();
      for (ValidityMode mode : ValidityMode.values()) {
        enums.add(mode.name());
      }
      setTokens(enums);
    }

  } // class ValidityModeCompleter

}
