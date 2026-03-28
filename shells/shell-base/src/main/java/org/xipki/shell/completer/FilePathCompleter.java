// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell.completer;

import org.xipki.shell.CompletionProvider;
import picocli.CommandLine.Model.ArgSpec;
import picocli.CommandLine.Model.CommandSpec;

import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Marker CompletionProvider for File Paths.
 * Handled natively by PicocliShell to preserve JLine Candidate trailing spaces.
 * @author Lijun Liao (xipki)
 */
public class FilePathCompleter implements CompletionProvider {
  @Override
  public Set<String> complete(CommandSpec commandSpec, ArgSpec argSpec,
                              List<String> words, int wordIndex) {
    return Collections.emptySet();
  }
}
