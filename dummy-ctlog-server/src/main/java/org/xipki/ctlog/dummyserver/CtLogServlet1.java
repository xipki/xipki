package org.xipki.ctlog.dummyserver;

import java.util.Arrays;
import java.util.Base64;

/**
 * TODO.
 * @author Lijun Liao
 */
@SuppressWarnings("serial")
public class CtLogServlet1 extends CtLogServlet {

  private String id;

  public CtLogServlet1() {
    byte[] tmpId = new byte[32];
    Arrays.fill(tmpId, (byte) 0x11);
    id = Base64.getEncoder().encodeToString(tmpId);
  }

  @Override
  protected String getLogId() {
    return id;
  }

}