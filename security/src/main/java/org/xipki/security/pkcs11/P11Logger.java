package org.xipki.security.pkcs11;

import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.Logger;

public class P11Logger implements Logger {

  public static final P11Logger INSTANCE = new P11Logger();

  private final org.slf4j.Logger LOG = LoggerFactory.getLogger(org.xipki.pkcs11.wrapper.Logger.class);

  @Override
  public void info(String msg) {
    LOG.info(msg);
  }

  @Override
  public void warn(String msg) {
    LOG.warn(msg);
  }

  @Override
  public void error(String msg) {
    LOG.error(msg);
  }
}
