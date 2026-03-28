// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import picocli.CommandLine;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * Annotation to specify explicit completion candidates for Picocli options and parameters.
 * Static {@link #values()} are merged with candidates returned by the optional
 * {@link #value()} provider.
 *
 * @author Lijun Liao (xipki)
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.FIELD})
public @interface Completion {

  Class<? extends CompletionProvider> value() default NoopCompletionProvider.class;

  String[] values() default {};

  /**
   * Default no-op provider used when only static completion values are configured.
   */
  class NoopCompletionProvider implements CompletionProvider {

    @Override
    public Set<String> complete(CommandLine.Model.CommandSpec commandSpec,
        CommandLine.Model.ArgSpec argSpec, List<String> words, int wordIndex) {
      return Collections.emptySet();
    }
  }

}
