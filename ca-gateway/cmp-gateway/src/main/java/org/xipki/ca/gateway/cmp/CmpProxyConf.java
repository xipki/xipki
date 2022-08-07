package org.xipki.ca.gateway.cmp;

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

public class CmpProxyConf extends ProtocolProxyConf {

  private CmpControlConf cmp;

  public static CmpProxyConf readConfFromFile(String fileName)
      throws IOException, InvalidConfException {
    Args.notBlank(fileName, "fileName");
    try (InputStream is = Files.newInputStream(Paths.get(fileName))) {
      CmpProxyConf conf = JSON.parseObject(is, CmpProxyConf.class);
      conf.validate();
      return conf;
    }
  }

  public CmpControlConf getCmp() {
    return cmp;
  }

  public void setCmp(CmpControlConf cmp) {
    this.cmp = cmp;
  }

  @Override
  public void validate() throws InvalidConfException {
    super.validate();
    notNull(cmp, "cmp");
  }

}
