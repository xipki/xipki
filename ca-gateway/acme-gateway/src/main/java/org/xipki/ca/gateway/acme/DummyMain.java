package org.xipki.ca.gateway.acme;

import org.xipki.security.util.JSON;

public class DummyMain {

  public static void main(String[] args) {
    try {
      AcmeAccount.Data data = new AcmeAccount.Data();
      data.setTermsOfServiceAgreed(true);
      String st = JSON.toJson(data);
      System.out.println(st);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

}
