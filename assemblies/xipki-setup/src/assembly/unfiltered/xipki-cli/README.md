## How to start XiPKI CLI

`bin/xipki`

Each command in a script file (e.g. my.script) is printed while it executes. To turn this off:

```text
set SCRIPT_TRACE false
source my.script
```

## Available Commands

Call `help` in the xipki shell.

## Enroll/Revoke Certificate

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
