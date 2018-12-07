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

package org.xipki.ca.mgmt.shell;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.ca.mgmt.api.CaManager;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.ca.mgmt.api.CertListOrderBy;
import org.xipki.ca.mgmt.api.MgmtEntry;
import org.xipki.ca.mgmt.api.RequestorInfo;
import org.xipki.ca.mgmt.api.ValidityMode;
import org.xipki.security.CrlReason;
import org.xipki.shell.DynamicEnumCompleter;
import org.xipki.shell.EnumCompleter;

/**
 * TODO.
 * @author Lijun Liao
 */
public class CaCompleters {

  public abstract static class CaMgmtCompleter extends DynamicEnumCompleter {

    @Reference
    protected CaManager caManager;

  }

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

  }

  @Service
  public static class CaCrlReasonCompleter extends EnumCompleter {

    public CaCrlReasonCompleter() {
      List<String> enums = new LinkedList<>();
      for (CrlReason reason : CaActions.CaRevoke.PERMITTED_REASONS) {
        enums.add(reason.getDescription());
      }
      setTokens(enums);
    }

  }

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

  }

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

  }

  @Service
  public static class CaStatusCompleter extends EnumCompleter {

    public CaStatusCompleter() {
      setTokens("active", "inactive");
    }

  }

  @Service
  public static class CertListSortByCompleter extends EnumCompleter {

    public CertListSortByCompleter() {
      List<String> enums = new LinkedList<>();
      for (CertListOrderBy sort : CertListOrderBy.values()) {
        enums.add(sort.getText());
      }
      setTokens(enums);
    }

  }

  @Service
  public static class PermissionCompleter extends EnumCompleter {

    public PermissionCompleter() {
      setTokens("enroll_cert", "revoke_cert", "unrevoke_cert", "remove_cert",
          "key_update", "gen_crl", "get_crl", "enroll_cross", "all");
    }
  }

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

  }

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

  }

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

  }

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

  }

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

  }

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

  }

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
        MgmtEntry.Ca caEntry;
        try {
          caEntry = caManager.getCa(name);
        } catch (CaMgmtException ex) {
          continue;
        }

        X509Certificate cert = caEntry.getCert();
        if (cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
          ret.add(name);
        }
      }
      return ret;
    }

  }

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
      return names;
    }

  }

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
  }

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

  }

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

  }

  @Service
  public static class ValidityModeCompleter extends EnumCompleter {

    public ValidityModeCompleter() {
      List<String> enums = new LinkedList<>();
      for (ValidityMode mode : ValidityMode.values()) {
        enums.add(mode.name());
      }
      setTokens(enums);
    }

  }

}
