How to deploy
-----
1. Unzip ocsp.war
2. Copy the ocsp-store-example-<version>.jar to the unpacked WEB-INF/lib
3. Zip it back to ocsp.war

How to configure
-----
1. In the file `xipki/etc/ocsp/ocsp-responder.json`

```
	"stores":[{
		"name":"dummystore1",
        ...
		"source":{
			"type":"java:org.xipki.ocsp.server.store.example.DummyStore",
			"conf":{
				"caCert":"keycerts/ca-cert.pem"
			}
		}
	}]
```