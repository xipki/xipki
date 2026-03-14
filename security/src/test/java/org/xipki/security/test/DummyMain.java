package org.xipki.security.test;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;

import javax.security.auth.x500.X500Principal;

public class DummyMain {

  public static void main(String[] args) {
    try {
    		String dn = "CN=\\=^_^\\=";

    		X500Principal principal = new X500Principal(dn);
    		System.out.println("Using X500Principal: " + principal.getName());

    		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        String cn = "=^_^=";
    		builder.addRDN(BCStyle.CN, cn);
    		X500Name x500Name = builder.build();
    		System.out.println("Using X500NameBuilder: " + x500Name.toString());

    		X500Name x500 = new X500Name(dn);
    		System.out.println("Using X500Name: " + x500.toString());
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

}
