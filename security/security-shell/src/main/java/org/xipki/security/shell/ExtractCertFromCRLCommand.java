/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.security.shell;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.security.cert.X509CRL;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.apache.felix.gogo.commands.Command;
import org.apache.felix.gogo.commands.Option;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.Certificate;
import org.xipki.common.CustomObjectIdentifiers;
import org.xipki.common.IoCertUtil;

/**
 * @author Lijun Liao
 */

@Command(scope = "keytool", name = "extract-cert", description="Extract certificates from CRL")
public class ExtractCertFromCRLCommand extends SecurityCommand
{

    @Option(name = "-crl",
            required = true, description = "Required. CRL file")
    protected String crlFile;

    @Option(name = "-out",
            required = true, description = "Required. Zip file to save the extracted certificates")
    protected String outFile;

    @Override
    protected Object doExecute()
    throws Exception
    {
        X509CRL crl = IoCertUtil.parseCRL(crlFile);
        String oidExtnCerts = CustomObjectIdentifiers.id_crl_certset;
        byte[] extnValue = crl.getExtensionValue(oidExtnCerts);
        if(extnValue == null)
        {
            err("No certificate is contained in " + crlFile);
            return null;
        }

        extnValue = removingTagAndLenFromExtensionValue(extnValue);
        ASN1Set asn1Set = DERSet.getInstance(extnValue);
        int n = asn1Set.size();
        if(n == 0)
        {
            err("No certificate is contained in " + crlFile);
            return null;
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ZipOutputStream zip = new ZipOutputStream(out);

        for(int i = 0; i < n; i++)
        {
            ASN1Encodable asn1 = asn1Set.getObjectAt(i);
            Certificate cert;
            try
            {
                ASN1Sequence seq = ASN1Sequence.getInstance(asn1);
                cert = Certificate.getInstance(seq.getObjectAt(0));
            }catch(IllegalArgumentException e)
            {
                // backwards compatibility
                cert = Certificate.getInstance(asn1);
            }

            byte[] certBytes = cert.getEncoded();
            String sha1_fp_cert = IoCertUtil.sha1sum(certBytes);

            ZipEntry certZipEntry = new ZipEntry(sha1_fp_cert + ".der");
            zip.putNextEntry(certZipEntry);
            try
            {
                zip.write(certBytes);
            }finally
            {
                zip.closeEntry();
            }
        }

        zip.flush();
        zip.close();

        saveVerbose("Extracted " + n + " certificates to", new File(outFile), out.toByteArray());
        return null;
    }

    private static byte[] removingTagAndLenFromExtensionValue(byte[] encodedExtensionValue)
    {
        DEROctetString derOctet = (DEROctetString) DEROctetString.getInstance(encodedExtensionValue);
        return derOctet.getOctets();
    }
}
