package org.xipki.ca.gateway.rest;

import com.alibaba.fastjson.JSON;
import org.xipki.ca.gateway.conf.ProtocolProxyConf;
import org.xipki.util.Args;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class RestProxyConf extends ProtocolProxyConf {

  public static RestProxyConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    try (InputStream is = Files.newInputStream(Paths.get(fileName))) {
      RestProxyConf conf = JSON.parseObject(is, RestProxyConf.class);
      conf.validate();
      return conf;
    }
  }

}
