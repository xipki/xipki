package org.xipki.ca.protocol.scep;

import com.alibaba.fastjson.JSON;
import org.xipki.ca.protocol.conf.ProtocolProxyConf;
import org.xipki.util.Args;
import org.xipki.util.exception.InvalidConfException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ScepProxyConf extends ProtocolProxyConf {

  private ScepControl scepControl;

  public static ScepProxyConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    try (InputStream is = Files.newInputStream(Paths.get(fileName))) {
      ScepProxyConf conf = JSON.parseObject(is, ScepProxyConf.class);
      conf.validate();
      return conf;
    }
  }

  public ScepControl getScepControl() {
    return scepControl;
  }

  public void setScepControl(ScepControl scepControl) {
    this.scepControl = scepControl;
  }

}
