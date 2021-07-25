# Tiriryarai
An HTTPS man-in-the-middle proxy framework written in C#.

![logo](Tiriryarai/favicon.ico)

## Table of Contents
 - [1. Features](#1-features)
 - [2. Files](#2-files)
 - [3. Web Interface](#3-web-interface)
 - [4. How To Build](#4-how-to-build)
   - [4.1. Linux](#41-linux)
 - [5. Adding Plugins](#5-adding-plugins)
 - [6. How To Use](#6-how-to-use)
 - [7. License](#7-license)

## 1. Features
- Automated certificate creation for each host.
- Customized plugins for automated HTTP request and response modification and interception.
- OCSP query support (No OCSP stapling).
- Certificate Revocation List (CRL) support.
- Logging of incomming HTTP requests and responses using different verbosity levels.
- Web interfaces with HTTP basic authentication support.
  - Customized web interfaces for remote plugin configuration.
  - Web interface to view and delete logs remotely.

## 2. Files
The program creates the following folders and files:
 - **logs**: Folder that contains one log file for each host, named `<hostname>.log`, containing
             each request sent and response received from that host.
 - **-RootCA-.pfx**: PKCS12 file containing the Root CA certificate that will be used to sign
                     certificates generated by Tiriryarai. The Root CA certificate needs to be
                     installed in your client, refer to [6. How To Use](#6-how-to-use) for details.
                     The password to this file is `secret`.
 - **-OcspCA-.pfx**: PKCS12 file containing the OCSP CA certificate that will be used to sign
                     OCSP responses generated by Tiriryarai. The password to this file is `secret`.
 - **-MitM-.pfx**: PKCS12 file containing the certificate that will be used to authenticate the
                   Man-in-the-middle plugins. The password to this file is `secret`.

By default, they can be found in the application data folder, which is `$HOME/.config/Tiriryarai`
on Unix systems.

## 3. Web Interface
The following Uri enpoints are used by Tiriryarai and will be invoked if it receives an HTTP request
with itself as the destination host.
 - __/__: Contains a welcome page with instructions and links.
 - **/favicon.ico**: Contains the favicon used by the interface.
 - **/cert** and **/Tiriryarai.crt**: Contains the Root CA certificate  used to sign certificates
                                      generated by Tiriryarai.
 - **/ocsp**: Contains an OCSP responder that will send an OCSP response indicating that the certificate in the
              request was valid.
 - **/revoked.crl**: Contains an empty certificate revocation list, meaning tyhat no certificates have been revoked.
 - **/logs\/***: Contains a log management interface that lists links to all logs. This endpoint can only be accessed
               securely using HTTPS. It is disabled by default and can be enabled using the `-l` flag. If Tiriryarai
               was configured to use a username and password, it will be protected using HTTP basic authentication.

Tiriryarai supports custom web interfaces for each plugin using the `HomePage()` method in the `IManInTheMiddle`
interface, see [5. Adding Plugins](#5-adding-plugins) for details about how to add plugins. The custom web page is
invoked when Tiriryarai receives a request to itself that is not destined to any of the Uri endpoints listed above.
It accessed using HTTPS only and can optionally configured to be protected using HTTP basic authentication.

## 4. How To Build
### 4.1 Linux
Install **Mono** from [here](https://www.mono-project.com/download/stable/#download-lin) and run `msbuild Tiriryarai.sln`

## 5. Adding Plugins
 1. Add a new .NET Console application project to the solution. Select .NET Framework 4.8 as the target framework.
 2. Add a reference to the `Tiriryarai` project, `System.Web`, `System.Runtime.Config`, and `Mono.Security`. Also add the
    `Mono.Options` and `BrotliSharpLib` nuget packages.
 3. Create a new class that implements the [`IManInTheMiddle`](Tiriryarai/Server/IManInTheMiddle.cs) interface. See
    the link for documentation of which methods must be implemented.
 4. Build and run the project.

[`TiriryaraiMitm`](Plugins/TiriryaraiMitm) is a dummy example plugin that can be used for reference.
[`TuxEverywhere`](Plugins/TuxEverywhere) is another very serious plugin that illustrates what Tiriryarai
can do if in the wrong (right) hands.

## 6. How To Use
Tiriryarai accepts a number of command line arguments which can configure it. For a list of those arguments, use
the `-h` flag. Also see the [`HttpsMitmProxyParams`](Tiriryarai/Util/HttpsMitmProxyParams.cs) class for further
documentation about the configuration.

The first time Tiriryarai starts up it needs to generate the `.pfx` files, which takes a few seconds. To
use the proxy, you need to install its Root CA certificate. After Tiriryarai has started correctly, open
`http://<your-hostname-or-ip-address>:<your-port>` and click the download link. From there, install it in
your client. You also need to configure your client to use the proxy.

## 7. License
Copyright (C) 2021 William Stackenäs <w.stackenas@gmail.com>

This README file documents the use of Tiriryarai.

Tiriryarai is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Tiriryarai is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
