# XiPKI Toolkits
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

## Build

- Prepare dependency XiSCEP (optional, required if not done before)

  - Get a copy of XiSCEP code
    ```sh
    git clone https://github.com/xipki/xiscep.git
    ```
  - Switch to the tag v2.3.0 (TODO)
    `git checkout v2.3.0`
  - Build and install maven artifacts
    In the folder xiscep, call `mvn install -DskipTests`

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
    git clone https://github.com/xipki/xisdk.git
    ```

  - Build and install maven artifacts
    In folder `xisdk`
    ```sh
    mvn clean install
    ```

