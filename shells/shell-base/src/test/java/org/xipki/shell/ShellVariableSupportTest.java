// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.shell;

import org.junit.Assert;
import org.junit.Test;

import java.nio.file.Paths;

/**
 * Tests for shell variable interpolation.
 *
 * @author Lijun Liao (xipki)
 */
public class ShellVariableSupportTest {

  @Test
  public void testSetUnsetVariable() {
    ShellScriptContext context = new ShellScriptContext(null, Paths.get("."));
    context.set("A", "va");

    Assert.assertEquals("va", ShellVariableSupport.interpolateVariables("${A}", context));
    Assert.assertEquals("va", ShellVariableSupport.interpolateVariables("$A", context));

    context.unset("A");

    Assert.assertEquals("", ShellVariableSupport.interpolateVariables("${A}", context));
    Assert.assertEquals("", ShellVariableSupport.interpolateVariables("$A", context));
  }

  @Test
  public void testUnresolvedVariableFallsBackToLiteralWhenResolverReturnsNull() {
    Assert.assertEquals("${A}",
        ShellVariableSupport.interpolateVariables("${A}", (braced, simple) -> null));
  }

  @Test
  public void testEscapedVariableIsPreserved() {
    ShellScriptContext context = new ShellScriptContext(null, Paths.get("."));
    context.set("A", "va");

    Assert.assertEquals("${A}", ShellVariableSupport.interpolateVariables("\\${A}", context));
  }

  @Test
  public void testSystemPropertySyntax() {
    String oldValue = System.getProperty("xipki.test.prop");
    System.setProperty("xipki.test.prop", "value1");
    try {
      ShellScriptContext context = new ShellScriptContext(null, Paths.get("."));
      Assert.assertEquals("value1",
          ShellVariableSupport.interpolateVariables("${sys:xipki.test.prop}", context));
    } finally {
      if (oldValue == null) {
        System.clearProperty("xipki.test.prop");
      } else {
        System.setProperty("xipki.test.prop", oldValue);
      }
    }
  }

  @Test
  public void testMissingScriptArgIsEmpty() {
    ShellScriptContext context = new ShellScriptContext(null, Paths.get("."));
    Assert.assertEquals("", ShellVariableSupport.interpolateVariables("$4", context));
  }

}
