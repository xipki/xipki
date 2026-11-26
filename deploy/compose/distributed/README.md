# XiPKI distributed role templates

These files are internal inputs to `../container.sh prepare`; operators should not copy or invoke them
directly. The control-host launcher renders one self-contained archive for each role and includes
the matching Compose template as `compose.yaml` plus the role launcher as `node.sh`.

Each generated node bundle pins one of `ca`, `console`, `gateway`, or `ocsp`, initializes a private
named volume from its role seed, and starts that role from the shared XiPKI application image. No
network or volume is shared across bundles. See the release package's top-level `README.md` for the
supported preparation, transfer, startup, backup, and acceptance procedure.

The Gateway role terminates HTTPS in its own Tomcat process. Its generated server certificate is
separate from the RA SDK client certificate used to call CA `/ca/ra/`; preparation validates their
exclusive EKUs, server SAN, trust chain, and distinct fingerprints. The optional HTTP publication
is fixed to `127.0.0.1` for node-local diagnostics and never follows the node's public bind address.
The Gateway bundle also carries a separate, limited REST verification identity and exposes the
complete issuance, OCSP, and permanent-revocation check as `./node.sh verify`.

Generated XML and JSON carry password markers rather than private-key passwords. Each CA or Gateway
bundle contains only its own file-backed identity Secrets, which the one-shot role initializer
resolves inside the private runtime volume. Optional CA/Gateway server PKCS#12 overrides must be
validated and applied on the control host before these internal templates are packaged.
