// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.ca.mgmt;

import org.xipki.ca.api.mgmt.CaManager;
import org.xipki.ca.api.mgmt.CertListOrderBy;
import org.xipki.ca.api.mgmt.RequestorInfo;
import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.profile.ctrl.ValidityMode;
import org.xipki.ca.mgmt.client.CaMgmtClient;
import org.xipki.security.pkix.CrlReason;
import org.xipki.security.pkix.X509Cert;
import org.xipki.shell.CompletionProvider;
import org.xipki.shell.completer.AbstractSetCompleter;
import picocli.CommandLine;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Completers for the CA commands.
 *
 * @author Lijun Liao (xipki)
 */
public class CaCompleters {

  private static abstract class AbstractCaCompleter implements CompletionProvider {

    @Override
    public Set<String> complete(CommandLine.Model.CommandSpec commandSpec,
                                CommandLine.Model.ArgSpec argSpec,
                                List<String> words, int wordIndex) {
      return complete();
    }

    protected abstract Set<String> complete();

  }

  public static class CaAliasCompleter extends AbstractCaCompleter {

    @Override
    public Set<String> complete() {
      try {
      return CaMgmtRuntime.get().getCaAliasNames();
      } catch (Exception e) {
        return Set.of();
      }
    }
  } // class CaAliasCompleter

  public static class CaCrlReasonCompleter extends AbstractSetCompleter {
    public CaCrlReasonCompleter() {
      setTokens(new Enum<?>[]{
          CrlReason.UNSPECIFIED,      CrlReason.KEY_COMPROMISE,
          CrlReason.CA_COMPROMISE,    CrlReason.AFFILIATION_CHANGED,
          CrlReason.SUPERSEDED,       CrlReason.CESSATION_OF_OPERATION,
          CrlReason.CERTIFICATE_HOLD, CrlReason.PRIVILEGE_WITHDRAWN});
    }
  } // class CaCrlReasonCompleter

  public static class CaNameCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      try {
        return CaMgmtRuntime.get().getCaNames();
      } catch (Exception e) {
        return Collections.emptySet();
      }
    }
  }

  public static class CaNamePlusAllCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      Set<String> ret;
      try {
        ret = CaMgmtRuntime.get().getCaNames();
      } catch (Exception e) {
        ret = new HashSet<>();
      }
      ret.add("all");
      return ret;
    }
  } // class CaNamePlusAllCompleter

  public static class CaStatusCompleter extends AbstractSetCompleter {
    public CaStatusCompleter() {
      setTokens("active", "inactive");
    }
  } // class CaStatusCompleter

  public static class CertListSortByCompleter extends AbstractSetCompleter {
    public CertListSortByCompleter() {
      setTokens(CertListOrderBy.values());
    }
  }

  public static class KeypairGenNameCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      try {
        return CaMgmtRuntime.get().getKeypairGenNames();
      } catch (Exception ex) {
        return Collections.emptySet();
      }
    }
  }

  public static class KeypairGenTypeCompleter extends AbstractSetCompleter {
    public KeypairGenTypeCompleter() {
      setTokens("SOFTWARE", "PKCS11", "KEYPOOL");
    }
  }

  public static class PermissionCompleter extends AbstractSetCompleter {
    public PermissionCompleter() {
      setTokens("enroll_cert", "revoke_cert", "unrevoke_cert", "remove_cert",
          "key_update", "gen_crl", "get_crl", "enroll_cross", "all", "none");
    }
  } // class PermissionCompleter

  public static class ProfileNameAndAllCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      Set<String> ret;
      try {
        ret = new HashSet<>(CaMgmtRuntime.get().getCertprofileNames());
      } catch (Exception ex) {
        ret = new HashSet<>();
      }
      ret.add("all");
      return ret;
    }
  }

  public static class ProfileNameCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      try {
        return CaMgmtRuntime.get().getCertprofileNames();
      } catch (Exception ex) {
        return Collections.emptySet();
      }
    }
  }

  public static class ProfileTypeCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      try {
        return CaMgmtRuntime.get().getSupportedCertprofileTypes();
      } catch (Exception ex) {
        return Collections.emptySet();
      }
    }
  }

  public static class PublisherNameCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      try {
        return CaMgmtRuntime.get().getPublisherNames();
      } catch (Exception ex) {
        return Collections.emptySet();
      }
    }

  } // class PublisherNameCompleter

  public static class PublisherNamePlusAllCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      Set<String> ret;
      try {
        ret = new HashSet<>(CaMgmtRuntime.get().getPublisherNames());
      } catch (Exception ex) {
        ret = new HashSet<>();
      }
      ret.add("all");
      return ret;
    }

  } // class PublisherNamePlusAllCompleter

  public static class PublisherTypeCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      try {
        return CaMgmtRuntime.get().getSupportedPublisherTypes();
      } catch (Exception ex) {
        return Collections.emptySet();
      }
    }

  } // class PublisherTypeCompleter

  public static class RcaNameCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      Set<String> caNames;
      CaMgmtClient caManager;
      try {
        caManager = CaMgmtRuntime.get();
        caNames = caManager.getCaNames();
      } catch (Exception ex) {
        return Collections.emptySet();
      }

      Set<String> ret = new HashSet<>();

      for (String name : caNames) {
        CaEntry caEntry;
        try {
          caEntry = caManager.getCa(name);
        } catch (Exception ex) {
          continue;
        }

        X509Cert cert = caEntry.cert();
        if (cert.isSelfSigned()) {
          ret.add(name);
        }
      }
      return ret;
    }

  } // class RcaNameCompleter

  public static class RequestorNameCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      Set<String> names = new HashSet<>();
      try {
        names.addAll(CaMgmtRuntime.get().getRequestorNames());
      } catch (Exception ex) {
      }
      names.remove(RequestorInfo.NAME_BY_CA);
      names.remove(RequestorInfo.NAME_BY_CA.toUpperCase());
      return names;
    }

  } // class RequestorNameCompleter

  public static class SignerNameCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      try {
        return CaMgmtRuntime.get().getSignerNames();
      } catch (Exception ex) {
        return Collections.emptySet();
      }
    }
  } // class SignerNameCompleter

  public static class SignerNamePlusNullCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      Set<String> ret = new HashSet<>();
      try {
        ret.addAll(CaMgmtRuntime.get().getSignerNames());
      } catch (Exception ex) {
      }
      ret.add(CaManager.NULL);
      return ret;
    }

  } // class SignerNamePlusNullCompleter

  public static class SignerTypeCompleter extends AbstractCaCompleter {
    @Override
    protected Set<String> complete() {
      try {
        return CaMgmtRuntime.get().getSupportedSignerTypes();
      } catch (Exception ex) {
        return Collections.emptySet();
      }
    }

  } // class SignerTypeCompleter

  public static class ValidityModeCompleter extends AbstractSetCompleter {

    public ValidityModeCompleter() {
      Set<String> enums = new HashSet<>();
      for (ValidityMode mode : ValidityMode.values()) {
        enums.add(mode.name());
      }
      setTokens(enums);
    }

  } // class ValidityModeCompleter

}
