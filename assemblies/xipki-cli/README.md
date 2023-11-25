## Enroll/Revoke Certificate

* Start CLI (not needed for the `*.sh` scripts).

  `bin/karaf`

  You may access the CLI via SSH (details see the last text block in the previous section).

* ACME
  Use any ACME client.

* EST  
  Use any EST client.

  The shell script `xipki/client-script/est-client.sh` demonstrates the use of EST API.

  An example script in available under `xipki/client-script/est-client.script`.
  It can be executed in the CLI as follows:
    - `source xipki/client-script/est-client.script`

* SCEP  
  Use any SCEP client. XiPKI provides also a SCEP client.

  An example script in available under `xipki/client-script/scep-client.script`.
  It can be executed in the CLI as follows:
    - `source xipki/client-script/scep-client.script`

* CMP  
  Use any CMP client. XiPKI provides also a CMP client.

  An example script in available under `xipki/client-script/cmp-client.script`.
  It can be executed in the CLI as follows:
    - `source xipki/client-script/cmp-client.script` (use argument 'help' to print the usage)

* REST API  
  The shell script `xipki/client-script/rest-client.sh` demonstrates the use of REST API.

  An example script in available under `xipki/client-script/rest-client.script`.
  It can be executed in the CLI as follows:
    - `source xipki/client-script/rest-client.script` (use argument 'help' to print the usage)

* Note: You may access the CLI via SSH.
    * Configure karaf to start the SSH server.
        * Add `"ssh,"` to the field `featuresBoot` in the file `etc/org.apache.karaf.features.cfg`.
        * Configure the SSH server. See https://karaf.apache.org/manual/latest/security for details.
    * Start and stop karaf via `bin/start` and `bin/stop`.
    * Use a SSH client (either `bin/client` or any ssh client) to access the SSH service. Supported authentication
      methods are
        * username and password
        * public key (see Section `Managing authentication by key` at https://karaf.apache.org/manual/latest/security).
