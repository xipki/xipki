# XiPKI SDK
XiPKI (e**X**tensible s**I**mple **P**ublic **K**ey **I**nfrastructure) SDK

## License
* The Apache Software License, Version 2.0

## Owner
Lijun Liao (lijun.liao -A-T- gmail -D-O-T- com), [LinkedIn](https://www.linkedin.com/in/lijun-liao-644696b8)

## Support
Just drop me an email.

## Layout
 - lite-caclient-example  
   Example to communicate with the CA via CMP and RESTFUL API. Only dependencies BouncyCastle and
   slf4j-api are required.

## Get Binary Package

Download the binary package `xipki-sdk-<version>.tar.gz` from https://github.com/xipki/xisdk/releases.

Only if you want to use the development version, build it from source code as follows.

  - Get a copy of project code
    ```sh
    git clone https://github.com/xipki/xisdk.git
    ```

  - Build and install maven artifacts
    In folder `xisdk`
    ```sh
    mvn clean install -Pdist
    ```

    Then you will find the `xipki-sdk-*.tar.gz` in the directory `dist/target`.

Karaf Commands
-----
Please refer to [commands.md](commands.md) for more details.

