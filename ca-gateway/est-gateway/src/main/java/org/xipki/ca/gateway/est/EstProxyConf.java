package org.xipki.ca.gateway.est;

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

public class EstProxyConf extends ProtocolProxyConf {

  public static EstProxyConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    try (InputStream is = Files.newInputStream(Paths.get(fileName))) {
      EstProxyConf conf = JSON.parseObject(is, EstProxyConf.class);
      conf.validate();
      return conf;
    }
  }

}
