// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ocsp.server;

import org.xipki.security.Securities.SecurityConf;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;
import org.xipki.util.codec.json.JsonParser;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.io.IoUtil;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Configuration of the OCSP server.
 *
 * @author Lijun Liao (xipki)
 */
public class OcspConf {

  public static final String DFLT_SERVER_CONF = "ocsp/etc/ocsp-responder.json";

  private final boolean logReqResp;

  private final String serverConf;

  private final SecurityConf security;

  public OcspConf(boolean logReqResp, String serverConf,
                  SecurityConf security) {
    this.logReqResp = logReqResp;
    this.serverConf = serverConf;
    this.security = security;
  }

  public static OcspConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    try {
      Path path = Paths.get(IoUtil.expandFilepath(fileName, true));
      return parse(JsonParser.parseMap(path, true));
    } catch (RuntimeException | CodecException e) {
      throw new InvalidConfException("error parsing " + fileName + ": " +
          e.getMessage(), e);
    }
  }

  public boolean isLogReqResp() {
    return logReqResp;
  }

  public String getServerConf() {
    return serverConf == null ? DFLT_SERVER_CONF : serverConf;
  }

  public SecurityConf getSecurity() {
    return security == null ? SecurityConf.DEFAULT : security;
  }

  public static OcspConf parse(JsonMap json) throws CodecException {
    JsonMap map = json.getMap("security");
    SecurityConf security = (map == null) ? null : SecurityConf.parse(map);

    return new OcspConf(json.getBool("logReqResp", false),
        json.getString("serverConf"), security);
  }

}
