// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.qa;

import org.xipki.qa.ocsp.OcspCertStatus;
import org.xipki.qa.ocsp.OcspError;
import org.xipki.shell.CompletionProvider;
import org.xipki.shell.completer.AbstractSetCompleter;
import org.xipki.util.codec.TripleState;
import picocli.CommandLine.Model.ArgSpec;
import picocli.CommandLine.Model.CommandSpec;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Completion providers for QA shell commands.
 *
 * @author Lijun Liao (xipki)
 */
public class QaCompleters {

  private abstract static class QaCompleter implements CompletionProvider {
    @Override
    public Set<String> complete(CommandSpec commandSpec, ArgSpec argSpec,
                                List<String> words, int wordIndex) {
      return complete();
    }

    protected abstract Set<String> complete();
  }

  public static class IssuerNameCompleter extends QaCompleter {
    @Override
    public Set<String> complete() {
      try {
        return QaRuntime.getCaQaManager().getIssuerNames();
      } catch (Exception ex) {
        return Collections.emptySet();
      }
    }
  }

  public static class ProfileNameCompleter extends QaCompleter {
    @Override
    public Set<String> complete() {
      try {
        return QaRuntime.getCaQaManager().getCertprofileNames();
      } catch (Exception ex) {
        return Collections.emptySet();
      }
    }
  }

  public static class CertStatusCompleter extends AbstractSetCompleter {
    public CertStatusCompleter() {
      setTokens(OcspCertStatus.values());
    }
  }

  public static class OccurrenceCompleter extends AbstractSetCompleter {
    public OccurrenceCompleter() {
      setTokens(TripleState.values());
    }
  }

  public static class OcspErrorCompleter extends AbstractSetCompleter {
    public OcspErrorCompleter() {
      setTokens(OcspError.values());
    }
  }

}
