# Tiriryarai
An HTTPS man-in-the-middle proxy framework written in C#, allowing for custom plugins
that can freely modify incomming HTTP requests and responses automatically.

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
- Customized plugins for automated HTTP request and response modification and interception.
- Automated certificate creation for each host
  - Certificate caching for increased performance.
- OCSP query support (No OCSP stapling).
- Certificate Revocation List (CRL) support.
- Logging of incoming HTTP requests and responses using different verbosity levels.
  - Log encryption with the configured password.
- Optional proxy authentication.
- Web interfaces with HTTP basic authentication support.
  - Web interface to view and delete logs remotely.
  - Web interface to view and update proxy configuration remotely.
  - Customized web interfaces for remote plugin configuration.
- IP bans for clients sending too many incorrect login attempts.

## 2. Files
The program creates the following folders and files:
 - `logs`: Folder that contains one log file for each host, named `<hostname>.tirlog`, containing
           each request sent and response received from that host. These log files will be encrypted
           using AES-256-CBC with the given password in the `-w` flag. If no password is given, the
           logs will be encrypted with a key consisting of only zeros. The `.tirlog` format consists
           on an array of "log entries", where each log entry has a 16 byte initialization vector field,
           a 4 byte "length" field, followed by a "length" byte encrypted HTML representation of
           a HTTP message. Custom objects can also be logged by the custom plugins.
   - `-Debug-.tirlog`: Log file that mainly contains stack traces and other useful information
                       for troubleshooting.
 - `-RootCA-.pfx`: PKCS12 file containing the Root CA certificate that will be used to sign
                   certificates generated by Tiriryarai. The Root CA certificate needs to be
                   installed in your client, refer to [6. How To Use](#6-how-to-use) for details.
 - `-OcspCA-.pfx`: PKCS12 file containing the OCSP CA certificate that will be used to sign
                   OCSP responses generated by Tiriryarai.
 - `tiriryarai.pfx`: PKCS12 file containing the certificate that will be used to authenticate the
                     Tiriryarai host itself.
 - `<plugin-hostname>.pfx`: PKCS12 file containing the certificate that will be used to authenticate the
                            Man-in-the-middle plugin. It will use the hostname that was supplied via the
                            `-d` flag or the local IP address.

In case no password has been configured using the `-w` flag, the password to all `.pfx` files is `secret`.
Otherwise, it is the base64 encoded RFC2898 bytes derived from the password. By default, they can be found
in the application data folder, which is `$HOME/.config/Tiriryarai` on Unix systems.

## 3. Web Interface
The following Uri endpoints are used by Tiriryarai and will be invoked if it receives an HTTP request
to `http[s]://tiriryarai` as the destination host.
 - `/`: Contains a welcome page with instructions and links.
 - `/favicon.ico`: Contains the favicon used by the interface.
 - `/cert` and `/Tiriryarai.crt`: Contains the Root CA certificate  used to sign certificates
                                  generated by Tiriryarai.
 - `/ocsp`: Contains an OCSP responder that will send an OCSP response indicating that the certificate in the
            request was valid. Can be used by clients that require a good OCSP response to validate certificates.
 - `/revoked.crl`: Contains an empty certificate revocation list, meaning that no certificates have been revoked.
                   Can be used by clients that require a CRL to validate certificates.
 - `/config`: Contains a configuration interface for viewing and updating proxy configuration remotely. This endpoint
              can only be accessed securely using HTTPS. It is disabled by default and can be enabled using the `-c`
              flag. If Tiriryarai was configured to use a username and password, it will be protected using HTTP basic
              authentication. If the `-a` flag has been provided, it is possible to update the username and password
              here remotely. This will in turn clear the internal cache and delete the `.pfx` files.
 - `/logs/*`: Contains a log management interface that lists links to all logs. Just like the configuration page,
              this endpoint is only acessed through HTTPS and is disabled by default. It can be enabled using the
              `-l` flag, and If Tiriryarai was configured to use a username and password, it will be protected
              using HTTP basic authentication.

Tiriryarai supports custom web interfaces for each plugin using the `HomePage()` method in the `IManInTheMiddle`
interface, see [5. Adding Plugins](#5-adding-plugins) for details about how to add plugins. The custom web page is
invoked when Tiriryarai receives a request to the hostname given via the `-d` flag or its local IP address.
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
 4. Plugins can obtain a logger to log objects using `Logger.GetSingleton()` and the global proxy configuration
    using `HttpsMitmProxyConfig.GetSingleton()`. The latter has properties such as a directory where files can be
    stored.
 4. Build and run the project.

[`TiriryaraiMitm`](Plugins/TiriryaraiMitm) is a dummy example plugin that can be used for reference.
[`TuxEverywhere`](Plugins/TuxEverywhere) is another very serious plugin that illustrates what Tiriryarai
can do if in the wrong (right) hands.

## 6. How To Use
Tiriryarai accepts a number of command line arguments which can configure it. For a list of those arguments, use
the `-h` flag. Also see the [`HttpsMitmProxyConfig`](Tiriryarai/Util/HttpsMitmProxyConfig.cs) class for further
documentation about the configuration. Most of the same configuration can also be updated through the `/config`
endpoint, see [3. Web Interface](#3-web-interface).

The first time Tiriryarai starts up it needs to generate the `.pfx` files, which takes a few seconds. To
use the proxy, you need to install its Root CA certificate. After Tiriryarai has started correctly, configure
your client to use the proxy at your host and port, go to `http://tiriryarai`, and click the download link.
From there, install it in your client. Now it should be possible to proxy HTTPS requests via Tiriryarai.

## 7. License
Most source files are licensed under the GPLv3, or (at your option)
any later version. Some files in Tiriryarai.Security are licensed
under the MIT license. Please refer to the license notice at the
top of each file for details.

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
