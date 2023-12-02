### JAVA_HOME
Set the environment variable `JAVA_HOME` to the root directory of JRE/JDK installation.

## Prepare Keys and certificates for the Communication between XiPKI Components

1. Change the password (`"CHANGEIT"`), and subject in `setup/keycerts.json` and the XiPKI components.
2. Generate keys and certificates:  
   `setup/generate-keycerts.sh`.
3. Copy the keys and certificates to the target components:  
   `setup/provision-keycerts.sh`.

## Install CA Server

1. Unpack tomcat to a new folder
2. Install CA as described in the `xipki-ca/README.md` file.

## Install OCSP Responder

1. Unpack tomcat to a new folder
2. Install CA as described in the `xipki-ocsp/README.md` file.

## Install Protocol Gateway

1. Unpack tomcat to a new folder.
2. Install protocol gateway as described in the `xipki-gateway/README.md` file.

## Install HSM Proxy Server

1. Unpack tomcat to a new folder
2. Install CA as described in the `xipki-hsmproxy/README.md` file.

## Install Management Command Line Interface
void

## Install Command Line Interface
void

## How to Configure Password
In all XiPKI components (including Tomcat's TLS configuration), you may configure the password
using the following methods:  
(In the following examples, assume the password is "CHANGEIT", the master password is "qwert")

- In plaintext, e.g. `password=CHANGEIT`

- In obfuscated format, e.g. `password=OBF:1izy1htq1fnf1ime1im01fnn1hts1j0w`.
  Use karaf commands `xi:obfuscate` / `xi:deobfuscate`to obfuscate / deobfuscate the password.

- Encrypted with master password, e.g. `password=PBE:AQfQcYk2+tR2nDzR0gCaQXMkmRBgqPIomrt5yfTsJPBqb30sCID5OqHFpH/mEKb3OIIw9Q`.
  Use karaf commands `xi:pbe-enc` / `xi:pbe-dec` to encrypt / decrypt the password with master password.

  You need to configure the master password callback and iteration count in the file `xipki/secuity/password.cfg`:
   ```
   pbeCallback = <master password callback>
   pbeIterationCount = <number greater than 999>
   ```
  The following values of pbeCallback are allowed:
    - `FILE file=<path to the masterpassword>`, e.g. `FILE file=masterpassword.secret`,
        - The file content is either the password itself or its obfuscated format (starting with `OBF:`).
        - Either absolute path or relative path to the parent folder of `password.cfg`.
    - `PBE-GUI quorum=<number>,tries=<number>`, e.g. `PBE-GUI quorum=1,tries=3`
    - `GUI quorum=<number>,tries=<number>`, e.g. `GUI quorum=1,tries=3`
    - `OBF OBF:<obfuscated master password>`, e.g. `OBF OBF:1yf01z7o1t331z7e1yf6`.
    - `java:<class name implements org.xipki.password.PasswordCallback> [<corresponding configuration>]`
      e.g. `java:org.xipki.password.demo.PassThroughPasswordCallback qwert`.

- Use you own password resolver, assumed the password protocol is `ABC`, then the password is
  `ABC:<data>`. You need to write a Java class implements `org.xipki.password.PasswordResolver` which
  can resolve password starting with `ABC:`.
  You need to add the password resolvers in the file `xipki/secuity/password.cfg`:
   ```
  passwordResolver.<label> = <class name> [<conf>]
   ```

### Tomcat
To use th password protection mechanism described above, in the file `conf/server.xml`, you need to replace
`org.apache.coyote.http11.Http11NioProtocol` by `org.xipki.tomcat.XiHttp11NioProtocol`,
and `org.apache.coyote.http11.Http11Nio2Protocol` by `org.xipki.tomcat.XiHttp11Nio2Protocol`.

## Configure PKCS#11 device (optional)

This step is only required if the real PKCS#11 device instead of the emulator
is used. **Note that this step should be applied to all components (tomcat, xipki-mgmt-cli, and xipki-cli)**.

* Copy the corresponding configuration file in the folder `xipki/security/example/` to `xipki/security/pkcs11.json`,
  and adapt the PKCS#11 configuration.
    - For HSM device: `pkcs11-hsm.json`
    - For HSM proxy client: `pkcs11-hsmproxy.json`
    - For HSM emulaor: `pkcs11-emulator.json`

## Configure how to handle SSL client certificate behind reverse proxy

### For reverse proxy apache httpd

* Set the `reverseProxyMode` field in the json configuration file to `APACHE`:
    - CA: `xipki/etc/ca/ca.json`
    - HSM Proxy: `xipki/etc/hsmproxy.json`
    - CA Gateway
        - CMP: `xipki/gatway/cmp-gateway.json`
        - EST: `xipki/gatway/est-gateway.json`
        - REST: `xipki/gatway/rest-gateway.json`

* configure the proxy to forward the headers via mod_proxy with the following
  configuration

   ```sh
   # Require SSL Client verification
   SSLVerifyClient		require

   #initialize the special headers to a blank value to avoid http header forgeries 
   RequestHeader set SSL_CLIENT_VERIFY  "" 
   RequestHeader set SSL_CLIENT_CERT  "" 
   
   <Location / >
    RequestHeader set SSL_CLIENT_VERIFY "%{SSL_CLIENT_VERIFY}s"
    RequestHeader set SSL_CLIENT_CERT "%{SSL_CLIENT_CERT}s"
    ...
   </Location>
   ```

  For more details please refer to
    * [Jetty/Howto/Configure mod proxy](https://wiki.eclipse.org/Jetty/Howto/Configure_mod_proxy)
    * [Jetty: Tricks to do client certificate authentications behind a reverse proxy](http://www.zeitoun.net/articles/client-certificate-x509-authentication-behind-reverse-proxy/start)
    * [Apache Module mod_ssl](http://httpd.apache.org/docs/2.2/mod/mod_ssl.html#envvars)

### For reverse proxy apache nginx

* Set the `reverseProxyMode` in the json configuration file (e.g. `ca.json`) to `NGINX`.

* configure the proxy to forward the headers with the following
  configuration

   ```sh
   # Require SSL Client verification
   ssl_verify_client on;

   location / {
     ...
     #initialize the special headers to a blank value to avoid http header forgeries 
     proxy_set_header set SSL_CLIENT_VERIFY  "";
     proxy_set_header set SSL_CLIENT_CERT  "";

     # if the client certificate verified 
     # will have the value of 'SUCCESS' and 'NONE' otherwise
     proxy_set_header SSL_CLIENT_VERIFY $ssl_client_verify;
    
     # client certificate
     proxy_set_header SSL_CLIENT_CERT $ssl_client_escaped_cert;
     ...
   }
   ...
  ```

  For more details please refer to
    * [NGINX Reverse Proxy](https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/)
    * [Module ngx_http_ssl_module](http://nginx.org/en/docs/http/ngx_http_ssl_module.html)

## Setup CA Server

As described in the `xipki-mgmt-cli/README.md` file.

## Enroll/Revoke Certificate

As described in the `xipki-cli/README.md` file.

Management CLI Commands
-----
Please refer to [commands.md](commands.md) for more details.

CLI Commands
-----
Please refer to [commands.md](commands.md) for more details.

