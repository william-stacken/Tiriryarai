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
using System.Security.Cryptography;

using Tiriryarai.Server;

namespace Tiriryarai.Util
{
	class HttpsMitmProxyParams
	{
		private const int AES_BYTES = 32; // AES-256
		private const int KEY_ITERATIONS = 500;
		private static readonly byte[] SALT = {
			45, 213, 63, 89, 4, 121, 77, 19, 30, 91, 73, 244, 55, 98, 2, 157
		};

		public IManInTheMiddle MitM { get; }
		public ushort Port { get; }

		private string user;
		/// <summary>
		/// Gets the username required for HTTP basic authentication.
		/// </summary>
		public string Username
		{
			get
			{
				return user != null ? (string) user.Clone(): null;
			}
			set
			{
				bool set = !string.IsNullOrWhiteSpace(value);
				if ((PassKey != null || ProxyPassKey != null) && !set)
					throw new ArgumentException("Cannot remove username, passkeys must be removed first.");
				if (set && new Regex("[\x00-\x1f\x7f:]").IsMatch(value))
					throw new ArgumentException("Invalid username: " + value);

				user = set ? value : null;
			}
		}

		private byte[] passkey = null;

		/// <summary>
		/// Gets the RFC2898 derived bytes of the password required for HTTP basic authentication.
		/// This password is used to access the admin pages and is only sent
		/// over HTTPS.
		/// </summary>
		public byte[] PassKey
		{
			get
			{
				return passkey != null ? (byte[]) passkey.Clone() : null;
			}
		}

		/// <summary>
		/// Sets the password required for HTTP basic authentication.
		/// This password is used to access the admin pages and is only sent
		/// over HTTPS.
		/// </summary>
		public string Password
		{
			set
			{
				bool set = !string.IsNullOrWhiteSpace(value);
				if (Username == null && set)
					throw new ArgumentException("Cannot set password, username must be given.");
				if (set && new Regex("[\x00-\x1f\x7f]").IsMatch(value))
					throw new ArgumentException("Invalid password: " + value);

				passkey = ToPassKey(value);
			}
		}

		private byte[] proxypasskey = null;

		/// <summary>
		/// Gets the the RFC2898 derived bytes of the password required for HTTP basic authentication.
		/// This password is for using the proxy server and is sent over
		/// plain text HTTP.
		/// </summary>
		public byte[] ProxyPassKey
		{
			get
			{
				return proxypasskey != null ? (byte[]) proxypasskey.Clone() : null;
			}
		}

		/// <summary>
		/// Sets the password required for HTTP basic authentication.
		/// This password is for using the proxy server and is sent over
		/// plain text HTTP. DO NOT USE THE SAME PASSWORD TO ACCESS THE ADMIN PAGES!
		/// </summary>
		public string ProxyPassword
		{
			set
			{
				bool set = !string.IsNullOrWhiteSpace(value);
				if (Username == null && set)
					throw new ArgumentException("Cannot set proxy password, username must be given.");
				if (set && new Regex("[\x00-\x1f\x7f]").IsMatch(value))
					throw new ArgumentException("Invalid proxy password: " + value);

				proxypasskey = ToPassKey(value);
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
		public bool Authenticate { get { return PassKey != null; } }

		/// <summary>
		/// Gets a value indicating whether HTTP basic authentication is required to use
		/// the proxy.
		/// </summary>
		/// <value><c>true</c> if authentication is required; otherwise, <c>false</c>.</value>
		public bool ProxyAuthenticate { get { return ProxyPassKey != null; } }

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
		/// Checks if the given username and password is authenticated to access admin pages.
		/// </summary>
		/// <returns><c>true</c>, if the username and password was authenticated, <c>false</c> otherwise.</returns>
		/// <param name="username">The username to check.</param>
		/// <param name="password">The password to check</param>
		public bool IsAuthenticated(string username, string password)
		{
			byte[] key;
			if (!Authenticate)
				return true;
			if (username == null || (key = ToPassKey(password)) == null)
				return false;
			return username.Equals(Username) && KeysEqual(PassKey, key);
		}

		/// <summary>
		/// Checks if the given username and password is authenticated to use the proxy.
		/// </summary>
		/// <returns><c>true</c>, if the username and password was authenticated, <c>false</c> otherwise.</returns>
		/// <param name="username">The username to check.</param>
		/// <param name="password">The password to check</param>
		public bool IsProxyAuthenticated(string username, string password)
		{
			byte[] key;
			if (!ProxyAuthenticate)
				return true;
			if (username == null || (key = ToPassKey(password)) == null)
				return false;
			return username.Equals(Username) && KeysEqual(ProxyPassKey, key);
		}

		private byte[] ToPassKey(string pass)
		{
			return !string.IsNullOrWhiteSpace(pass) ?
			       new Rfc2898DeriveBytes(pass, SALT, KEY_ITERATIONS).GetBytes(AES_BYTES) :
			       null;
		}

		private bool KeysEqual(byte[] k1, byte[] k2)
		{
			if (k1.Length != k2.Length)
				return false;

			for (int i = 0; i < k1.Length; i++)
			{
				if (k1[i] != k2[i])
					return false;
			}
			return true;
		}
	}
}
