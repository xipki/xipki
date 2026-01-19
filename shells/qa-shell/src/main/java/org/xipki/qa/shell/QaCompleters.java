// Copyright (c) 2013-2025 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.qa.shell;

import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.xipki.qa.ca.CaQaSystemManager;
import org.xipki.qa.ocsp.OcspCertStatus;
import org.xipki.qa.ocsp.OcspError;
import org.xipki.security.pkcs11.P11CryptServiceFactory;
import org.xipki.shell.DynamicEnumCompleter;
import org.xipki.shell.EnumCompleter;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.type.TripleState;

import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * Completers for QA shells.
 *
 * @author Lijun Liao (xipki)
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

  } // class CertprofileNameCompleter

  @Service
  public static class CertStatusCompleter extends EnumCompleter {

    public CertStatusCompleter() {
      List<String> enums = new LinkedList<>();
      for (OcspCertStatus entry : OcspCertStatus.values()) {
        enums.add(entry.name());
      }
      setTokens(enums);
    }

  } // class CertStatusCompleter

  @Service
  public static class IssuerNameCompleter extends DynamicEnumCompleter {

    @Reference
    private CaQaSystemManager qaSystemManager;

    @Override
    protected Set<String> getEnums() {
      return qaSystemManager.getIssuerNames();
    }

  } // class IssuerNameCompleter

  @Service
  public static class OccurrenceCompleter extends EnumCompleter {

    public OccurrenceCompleter() {
      List<String> enums = new LinkedList<>();
      for (TripleState entry : TripleState.values()) {
        enums.add(entry.name());
      }
      setTokens(enums);
    }

  } // class OccurrenceCompleter

  @Service
  public static class OcspErrorCompleter extends EnumCompleter {

    public OcspErrorCompleter() {
      List<String> enums = new LinkedList<>();
      for (OcspError entry : OcspError.values()) {
        enums.add(entry.name());
      }
      setTokens(enums);
    }

  } // class OcspErrorCompleter

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

  } // class P11ModuleNameCompleter

}
