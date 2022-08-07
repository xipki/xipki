package org.xipki.ca.protocol.scep;

import com.alibaba.fastjson.JSON;
import org.xipki.ca.protocol.conf.ProtocolProxyConf;
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

public class ScepProxyConf extends ProtocolProxyConf {

  private ScepControl scep;

  public static ScepProxyConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    try (InputStream is = Files.newInputStream(Paths.get(fileName))) {
      ScepProxyConf conf = JSON.parseObject(is, ScepProxyConf.class);
      conf.validate();
      return conf;
    }
  }

  public ScepControl getScep() {
    return scep;
  }

  public void setScep(ScepControl scep) {
    this.scep = scep;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();
    notNull(signer, "signer");
    notNull(scep, "scep");
  }
}
