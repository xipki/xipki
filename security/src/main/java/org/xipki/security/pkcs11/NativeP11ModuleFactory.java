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

package org.xipki.security.pkcs11;

import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Logger;
import org.xipki.pkcs11.wrapper.StaticLogger;
import org.xipki.pkcs11.wrapper.TokenException;

/**
 * {@link P11ModuleFactory} to create {@link P11Module} of type "native".
 *
 * @author Lijun Liao
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
