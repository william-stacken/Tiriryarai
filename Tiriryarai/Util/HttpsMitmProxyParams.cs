//
// Copyright (C) 2021 William Stackenäs <w.stackenas@gmail.com>
//
// This file is part of Tiriryarai.
//
// Tiriryarai is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Tiriryarai is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Tiriryarai.Server;

namespace Tiriryarai.Util
{
	class HttpsMitmProxyParams
	{
		public IManInTheMiddle MitM { get; }
		public ushort Port { get; }

		/// <summary>
		/// Gets the username required for HTTP basic authentication.
		/// </summary>
		public string Username { get; private set; }

		/// <summary>
		/// Gets the password required for HTTP basic authentication.
		/// This password is used to access the admin pages and is only sent
		/// over HTTPS.
		/// </summary>
		public string Password { get; private set; }

		private string proxypass;
		/// <summary>
		/// Gets or sets the password required for HTTP basic authentication.
		/// This password is for using the proxy server and is sent over
		/// plain text HTTP. DO NOT USE THE SAME PASSWORD TO ACCESS THE ADMIN PAGES!
		/// </summary>
		public string ProxyPassword
		{
			get
			{
				return proxypass;
			}
			set
			{
				if (Username == null && value != null)
					throw new ArgumentException("Cannot set proxy password, username must be given.");

				proxypass = value;
			}
		}

		/// <summary>
		/// Gets the HTTPS URL of the MitM proxy.
		/// </summary>
		/// <value>The HTTPS URL.</value>
		public string HttpsUrl
		{
			get
			{
				return "https://" + Hostname + ":" + Port;
			}
		}

		private string host;

		/// <summary>
		/// Gets or sets the hostname of the server. If there
		/// is no hostname, it defaults to the IP address.
		/// </summary>
		/// <value>The hostname.</value>
		public string Hostname
		{
			get
			{
				return host ?? IP.ToString();
			}
			set
			{
				host = value;
			}
		}

		private IPAddress ip;

		/// <summary>
		/// Gets or sets the IP address the server is hosted on.
		/// </summary>
		/// <value>The IP address.</value>
		public IPAddress IP
		{
			get
			{
				return ip ?? DefaultIPAddress;
			}
			set 
			{
				ip = value;
			}
		}

		private string configDir;

		/// <summary>
		/// Gets or sets the directory where certificates, server
		/// configuration, and log files will be stored.
		/// </summary>
		/// <value>The config directory.</value>
		public string ConfigDirectory
		{
			get
			{
				return configDir ?? DefaultConfigDir;
			}
			set
			{
				configDir = value;
			}
		}

		private uint? verbosity;

		/// <summary>
		/// Gets or sets the log verbosity. The higher this value is,
		/// the more information will be logged.
		/// </summary>
		/// <value>The log verbosity.</value>
		public uint? LogVerbosity
		{
			get
			{
				return verbosity ?? DefaultVerbosity;
			}
			set
			{
				verbosity = value;
			}
		}

		private uint? maxLogSize;

		/// <summary>
		/// Gets or sets the max log size in MiB. If a log exceeds this
		/// size, it is deleted.
		/// </summary>
		/// <value>The max log size in MiB.</value>
		public uint? MaxLogSize
		{
			get
			{
				return maxLogSize ?? DefaultMaxLogSize;
			}
			set
			{
				maxLogSize = value;
			}
		}

		/// <summary>
		/// Gets or sets a value indicating whether remote log management is enabled.
		/// </summary>
		/// <value><c>true</c> if log management is enabled; otherwise, <c>false</c>.</value>
		public bool LogManagement { get; set; }

		/// <summary>
		/// Gets or sets a value indicating whether invalid certificates should be ignored
		/// by the HttpsClient.
		/// </summary>
		/// <value><c>true</c> if certificates should be ignored; otherwise, <c>false</c>.</value>
		public bool IgnoreCertificates { get; set; }

		/// <summary>
		/// Gets a value indicating whether HTTP basic authentication is required to access
		/// the custom MitM plugin page and other admin pages.
		/// </summary>
		/// <value><c>true</c> if authentication is required; otherwise, <c>false</c>.</value>
		public bool Authenticate { get { return Username != null; } }

		/// <summary>
		/// Gets a value indicating whether HTTP basic authentication is required to use
		/// the proxy.
		/// </summary>
		/// <value><c>true</c> if authentication is required; otherwise, <c>false</c>.</value>
		public bool ProxyAuthenticate { get { return ProxyPassword != null; } }

		/// <summary>
		/// Gets or sets a value indicating how many login attempts is allowed from a client
		/// before an IP ban. If <code>Authenticate</code> is <c>false</c>, this property is
		/// unused.
		/// </summary>
		/// <value>The number of allowed login attempts before an IP ban. Negative values are treated as zero.</value>
		public int AllowedLoginAttempts { get; set; }

		/// <summary>
		/// Gets or sets a value indicating how many milliseconds the proxy will wait for incomming requests
		/// from clients. This timeout does not apply for responses from servers.
		/// </summary>
		/// <value>The number of milliseconds to wait for a client request. Negative values and zero are
		/// treated as infinite.</value>
		public int ReadTimeout { get; set; }

		private static IPAddress DefaultIPAddress
		{
			get
			{
				IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
				foreach (IPAddress a in host.AddressList)
				{
					if (a.AddressFamily == AddressFamily.InterNetwork)
					{
						return a;
					}
				}
				throw new Exception("The system has no IPv4 address to use by default.");
			}
		}

		private static string DefaultConfigDir
		{
			get
			{
				return Path.Combine(
					Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
					"Tiriryarai"
				);
			}
		}

		private static uint DefaultVerbosity
		{
			get { return 0; }
		}

		private static uint DefaultMaxLogSize
		{
			get { return 10; }
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Util.HttpsMitmProxyParams"/> class
		/// with no authentication required.
		/// </summary>
		/// <param name="mitm">The man-in-the-middle-handler that will receive incomming HTTP responses and requests</param>
		/// <param name="port">The port the server will listen on.</param>
		public HttpsMitmProxyParams(IManInTheMiddle mitm, ushort port)
		{
			MitM = mitm;
			Port = port;
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Util.HttpsMitmProxyParams"/> with
		/// HTTP basic authentication when accessing the custom MitM page. class.
		/// </summary>
		/// <param name="mitm">The man-in-the-middle-handler that will receive incomming HTTP responses and requests</param>
		/// <param name="port">The port the server will listen on.</param>
		/// <param name="username">The username required for basic HTTP authentication.</param>
		/// <param name="password">The password required for basic HTTP authentication.</param>
		public HttpsMitmProxyParams(IManInTheMiddle mitm, ushort port, string username, string password) : this(mitm, port)
		{
			SetCredentials(username, password);
		}

		/// <summary>
		/// Removes the need for clients to authenicate using HTTP basic authentication when
		/// accessing the custom MitM page.
		/// </summary>
		public void RemoveCredentials()
		{
			SetCredentials(null, null);
		}

		/// <summary>
		/// Updates the credentials required for basic HTTP authentication. when
		/// accessing the custom MitM page.
		/// </summary>
		/// <param name="username">The new username required for basic HTTP authentication.</param>
		/// <param name="password">The new password required for basic HTTP authentication.</param>
		public void SetCredentials(string username, string password)
		{
			if ((username != null || password != null) && (username == null || password == null))
				throw new ArgumentException("Both username and password must be given");

			if (username != null && password != null &&
			    (new Regex("[\x00-\x1f\x7f:]").IsMatch(username) || new Regex("[\x00-\x1f\x7f]").IsMatch(password)))
				throw new ArgumentException("Username \"" + username + "\" or password \"" + password + "\" contains invalid characters");
			Username = username;
			Password = password;
		}
	}
}
