/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
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

package org.xipki.qa.ca.benchmark;

import java.util.LinkedList;
import java.util.List;

import org.xipki.qa.ca.benchmark.BenchmarkEntry.RandomDn;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.conf.ValidatableConf;

/**
 * TODO.
 * @author Lijun Liao
 */
public class EnrollTemplateType extends ValidatableConf {

  public class EnrollCertType extends ValidatableConf {

    private String certprofile;

    private String subject;

    private RandomDn randomDn;

    private String keyspec;

    public String getCertprofile() {
      return certprofile;
    }

    public void setCertprofile(String value) {
      this.certprofile = value;
    }

    public String getSubject() {
      return subject;
    }

    public void setSubject(String value) {
      this.subject = value;
    }

    public RandomDn getRandomDn() {
      return randomDn;
    }

    public void setRandomDn(RandomDn value) {
      this.randomDn = value;
    }

    public String getKeyspec() {
      return keyspec;
    }

    public void setKeyspec(String keyspec) {
      this.keyspec = keyspec;
    }

    @Override
    public void validate() throws InvalidConfException {
      notEmpty(certprofile, "certprofile");
      notEmpty(subject, "subject");
      notNull(randomDn, "randomDn");
      notEmpty(keyspec, "keyspec");
    }
  }

  private List<EnrollCertType> enrollCerts;

  public List<EnrollCertType> getEnrollCerts() {
    if (enrollCerts == null) {
      enrollCerts = new LinkedList<>();
    }
    return enrollCerts;
  }

  public void setEnrollCerts(List<EnrollCertType> enrollCerts) {
    this.enrollCerts = enrollCerts;
  }

  @Override
  public void validate() throws InvalidConfException {
    notEmpty(enrollCerts, "enrollCerts");
    validate(enrollCerts);
  }

}
