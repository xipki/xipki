# XiPKI P11Proxy
XiPKI PKCS#11 Proxy

## License
* The Apache Software License, Version 2.0

## Owner
Lijun Liao (lijun.liao -A-T- gmail -D-O-T- com), [LinkedIn](https://www.linkedin.com/in/lijun-liao-644696b8)

## Support
Just drop me an email.

## Build

- Prepare dependency XiTK (optional, required if not done before)

  - Get a copy of XiSCEP code
    ```sh
    git clone https://github.com/xipki/xitk.git
    ```
    The option `--recursive` is required to checkout the submodules.
  - Switch to the tag v2.3.0 (TODO)  
    `git checkout v2.3.0`
  - Build and install maven artifacts
    In the folder xitk, call `mvn install -DskipTests`

- Build the project

  - Get a copy of project code
    ```sh
    git clone https://github.com/xipki/xip11proxy.git
    ```

  - Build and install maven artifacts
    In folder `xip11proxy`
    ```sh
    mvn clean install -Pdist
    ```

