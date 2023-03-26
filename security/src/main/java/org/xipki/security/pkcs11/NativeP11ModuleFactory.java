// Copyright (c) 2013-2023 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11;

import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Logger;
import org.xipki.pkcs11.wrapper.StaticLogger;
import org.xipki.pkcs11.wrapper.TokenException;

/**
 * {@link P11ModuleFactory} to create {@link P11Module} of type "native".
 *
 * @author Lijun Liao (xipki)
 *
 */
public class NativeP11ModuleFactory implements P11ModuleFactory {

  private static class P11Logger implements Logger {

    private static final P11Logger INSTANCE = new P11Logger();

    private final org.slf4j.Logger LOG = LoggerFactory.getLogger(org.xipki.pkcs11.wrapper.Logger.class);

    @Override
    public void info(String format, Object... arguments) {
      LOG.info(format, arguments);
    }

    @Override
    public void warn(String format, Object... arguments) {
      LOG.warn(format, arguments);
    }

    @Override
    public void error(String format, Object... arguments) {
      LOG.error(format, arguments);
    }

    @Override
    public void debug(String format, Object... arguments) {
      LOG.debug(format, arguments);
    }

    @Override
    public void trace(String format, Object... arguments) {
      LOG.trace(format, arguments);
    }

    @Override
    public boolean isTraceEnabled() {
      return LOG.isTraceEnabled();
    }

    @Override
    public boolean isDebugEnabled() {
      return LOG.isDebugEnabled();
    }

    @Override
    public boolean isInfoEnabled() {
      return LOG.isInfoEnabled();
    }

    @Override
    public boolean isWarnEnabled() {
      return LOG.isWarnEnabled();
    }
  }

  public NativeP11ModuleFactory() {
  }

  @Override
  public boolean canCreateModule(String type) {
    return NativeP11Module.TYPE.equalsIgnoreCase(type);
  }

  @Override
  public P11Module newModule(P11ModuleConf conf) throws TokenException {
    StaticLogger.setLogger(P11Logger.INSTANCE);
    return NativeP11Module.getInstance(conf);
  }

}
