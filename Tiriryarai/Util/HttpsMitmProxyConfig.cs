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
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.ComponentModel;

using Tiriryarai.Server;

namespace Tiriryarai.Util
{
	/// <summary>
	/// A class containing configuration used by the MitM Proxy. If any attribute
	/// are set to <c>null</c>, the default value for that attribute will be used.
	/// </summary>
	// TODO The properties in this class should be made thread safe
	class HttpsMitmProxyConfig
	{
		private const int AES_BYTES = 32; // AES-256
		private const int KEY_ITERATIONS = 500;
		private static readonly byte[] SALT = {
			45, 213, 63, 89, 4, 121, 77, 19, 30, 91, 73, 244, 55, 98, 2, 157
		};

		private IManInTheMiddle mitm;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Static, "text", null)]
		[Description("The man-in-the-middle-handler that will receive incomming HTTP responses and requests.")]
		public IManInTheMiddle MitM
		{
			get
			{
				if (mitm == null)
					mitm = DefaultManInTheMiddle;
				return mitm;
			}
			set
			{
				if (value == null)
					throw new ArgumentException(nameof(value));
				mitm = value;
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		private string host;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Static, "text", "d|hostname=")]
		[Description("The hostname of the man-in-the-middle plugin. It will default " +
			"to the system IP if not specified.")]
		public string Hostname
		{
			get
			{
				if (host == null)
					host = IP.ToString();
				return host;
			}
			set
			{
				if (value != null && Uri.CheckHostName(value) == UriHostNameType.Unknown)
					throw new ArgumentException("Invalid hostname: " + value);
				host = value;
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		private ushort? port = null;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Static, "number", "p|port=")]
		[Description("The port the server will listen on, 8081 by default.")]
		public ushort Port
		{
			get
			{
				if (port == null)
					port = DefaultPort;
				return (ushort) port;
			}
			set
			{
				port = value;
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		private string user;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Authentication, "text", "u|username=")]
		[Description("The username required for basic HTTP authentication if one should be required. " +
			"Used for both proxy authentication and accessing the admin pages. Setting the username without " +
			" a password has no effect. <strong>NOTICE:</strong> Leaving the username empty will remove the " +
			"current admin password and proxy password.")]
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
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		private byte[] passkey = null;

		[HttpsMitmProxy(HttpsMitmProxyProperty.None, null, null)]
		[Description("The RFC2898 derived bytes of the password for accessing the admin pages.")]
		public byte[] PassKey
		{
			get
			{
				return passkey != null ? (byte[]) passkey.Clone() : null;
			}
		}

		[HttpsMitmProxy(HttpsMitmProxyProperty.Authentication, "password", "w|password=")]
		[Description("The password required for accessing the admin pages if one should be required. " +
			"It will be sent securely using HTTPS only. <strong>NOTICE:</strong> If this password is changed " +
			"Tiriryarai will be unable to read any existing logs. If that is a concern, please back up the logs first.")]
		public string Password
		{
			set
			{
				bool set = !string.IsNullOrWhiteSpace(value);
				if (Username == null && set)
					throw new ArgumentException("Cannot set password, username must be given.");
				if (set && new Regex("[\x00-\x1f\x7f]").IsMatch(value))
					throw new ArgumentException("Invalid password");

				passkey = ToPassKey(value);
				LastModifiedTime = DateTime.UtcNow;

				// Every component dependent on the password must be notified here
				// TODO Thread safety?
				Logger.GetSingleton().Key = PassKey;
			}
		}

		private byte[] proxypasskey = null;

		[HttpsMitmProxy(HttpsMitmProxyProperty.None, null, null)]
		[Description("The RFC2898 derived bytes of the password required for using the proxy.")]
		public byte[] ProxyPassKey
		{
			get
			{
				return proxypasskey != null ? (byte[]) proxypasskey.Clone() : null;
			}
		}

		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard, "password", "x|proxy-pass=")]
		[Description("The password required for using the proxy if one should be required. " +
			"It will be sent insecurely using HTTP and <strong>SHOULD NOT</strong> be the same as the admin password.")]
		public string ProxyPassword
		{
			set
			{
				bool set = !string.IsNullOrWhiteSpace(value);
				if (Username == null && set)
					throw new ArgumentException("Cannot set proxy password, username must be given.");
				if (set && new Regex("[\x00-\x1f\x7f]").IsMatch(value))
					throw new ArgumentException("Invalid proxy password");

				proxypasskey = ToPassKey(value);
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		[HttpsMitmProxy(HttpsMitmProxyProperty.None, null, null)]
		[Description("The HTTPS URL of the MitM proxy.")]
		public string HttpsUrl
		{
			get
			{
				return "https://" + Hostname + ":" + Port;
			}
		}

		private IPAddress ip;

		[HttpsMitmProxy(HttpsMitmProxyProperty.None, null, null)]
		[Description("The IP address the server is hosted on.")]
		public IPAddress IP
		{
			get
			{
				if (ip == null)
					ip = DefaultIPAddress;
				return ip;
			}
			set 
			{
				ip = value;
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		private string configDir;

		[HttpsMitmProxy(HttpsMitmProxyProperty.None, null, "f|configdir=")]
		[Description("The directory where certificates, server configuration, and log files will be stored.")]
		public string ConfigDirectory
		{
			get
			{
				if (configDir == null)
					configDir = DefaultConfigDir;
				return configDir;
			}
			set
			{
				configDir = value;
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		private uint? verbosity = null;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard, "number", "v|verbosity=")]
		[Description("The higher this value is, the more information will be logged. The default is " +
			"zero, meaning nothing gets logged.")]
		public uint LogVerbosity
		{
			get
			{
				if (verbosity == null)
					verbosity = DefaultVerbosity;
				return (uint) verbosity;
			}
			set
			{
				verbosity = value;
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		private int? maxLogSize = null;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard, "number", "s|logsize=")]
		[Description("The max log size in MiB. If a log exceeds this size, it is deleted. " +
			"Negative values and zero are infinite and the default is 10 MiB.")]
		public int MaxLogSize
		{
			get
			{
				if (maxLogSize == null)
					maxLogSize = DefaultMaxLogSize;
				return (int) maxLogSize;
			}
			set
			{
				maxLogSize = value;
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		private bool logmngmt;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Log, "checkbox", "l|logs")]
		[Description("Activate admin remote log management via the web interface. " +
			"Usage of authentication recommended. <strong>NOTICE:</strong> Once disabled, " +
			"it cannot be enabled without restarting Tiriryarai.")]
		public bool LogManagement
		{
			get { return logmngmt; }
			set { logmngmt = value; LastModifiedTime = DateTime.UtcNow; OptionLastModifiedTime = DateTime.UtcNow; }
		}

		private bool remoteconf;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard, "checkbox", "c|config")]
		[Description("Activate admin remote configuration via the web interface. " +
			"Usage of authentication recommended. <strong>NOTICE:</strong> Once disabled, " +
			"it cannot be enabled without restarting Tiriryarai.")]
		public bool Configuration
		{
			get { return remoteconf; }
			set { remoteconf = value; LastModifiedTime = DateTime.UtcNow; OptionLastModifiedTime = DateTime.UtcNow; }
		}

		private bool remoteauth = true;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Authentication, "checkbox", null)]
		[Description("Activate admin remote changing of username and admin password. " +
			"It is true by default, but if remote configuration is disabled this property is unused. " +
			"<strong>NOTICE:</strong> Once disabled, it cannot be enabled without restarting Tiriryarai.")]
		public bool ChangeAuthentication
		{
			get { return remoteauth; }
			set { remoteauth = value; LastModifiedTime = DateTime.UtcNow; }
		}

		private bool certignore;
		/// <summary>
		/// Gets or sets a value indicating whether invalid certificates should be ignored
		/// by the HttpsClient.
		/// </summary>
		/// <value><c>true</c> if certificates should be ignored; otherwise, <c>false</c>.</value>
		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard, "checkbox", "i|ignore-certs")]
		[Description("Ignore invalid certificates when sending HTTPS requests.")]
		public bool IgnoreCertificates
		{
			get { return certignore; }
			set { certignore = value; LastModifiedTime = DateTime.UtcNow; }
		}

		[HttpsMitmProxy(HttpsMitmProxyProperty.None, null, null)]
		[Description("Flag indicating whether HTTP basic authentication is required to access" +
			" the custom MitM plugin page and other admin pages.")]
		public bool Authenticate { get { return PassKey != null; } }

		[HttpsMitmProxy(HttpsMitmProxyProperty.None, null, null)]
		[Description("Flag indicating whether HTTP basic authentication is required to use the proxy.")]
		public bool ProxyAuthenticate { get { return ProxyPassKey != null; } }

		private int? loginattempts;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard, "number", "b|login-attempts=")]
		[Description("The amount of failed login attempts before a client IP is banned. This ban is in effect until " +
			"the internal proxy cache is cleared. Applies only to admin pages, not using the proxy, and only if " +
			"admin authentication is required. Negative values are treated as infinite and the default is 5.")]
		public int AllowedLoginAttempts
		{
			get
			{
				if (loginattempts == null)
					loginattempts = DefaultAllowedLoginAttempts;
				return (int) loginattempts;
			}
			set
			{
				loginattempts = value;
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		private int? readtimeout = null;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard, "number", "t|timeout=")]
		[Description("The time in milliseconds to wait on a client request or server response " +
			"before terminating the connection. Negative values and zero are infinite and the default is infinite.")]
		public int ReadTimeout
		{
			get
			{
				if (readtimeout == null)
					readtimeout = DefaultReadTimeout;
				return (int) readtimeout;
			}
			set
			{
				readtimeout = value;
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		private int? alivereadtimeout = null;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard, "number", "a|alive-timeout=")]
		[Description("The time in milliseconds to wait on a client request in a kept-alive connection " +
			"before terminating it. Negative values and zero are infinite and the default is 1000 ms.")]
		public int KeepAliveTimeout
		{
			get
			{
				if (alivereadtimeout == null)
					alivereadtimeout = DefaultKeepAliveTimeout;
				return (int) alivereadtimeout;
			}
			set
			{
				alivereadtimeout = value;
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		/// <summary>
		/// Gets the timestamp when Tiriryarai started up.
		/// </summary>
		/// <value>The timestamp when Tiriryarai started up.</value>
		public DateTime StartTime { get; }

		/// <summary>
		/// Gets the timestamp when the configuration was last modified.
		/// </summary>
		/// <value>The timestamp when configuration was last modified.</value>
		public DateTime LastModifiedTime { get; private set; }

		/// <summary>
		/// Gets the timestamp when one of the admin pages was last disabled
		/// or enabled.
		/// </summary>
		/// <value>The timestamp when configuration was last modified.</value>
		public DateTime OptionLastModifiedTime { get; private set; }

		private static IManInTheMiddle DefaultManInTheMiddle
		{
			get
			{
				IEnumerable<IManInTheMiddle> mitms =
				from t in Resources.Assembly.GetTypes()
				where t.GetInterfaces().Contains(typeof(IManInTheMiddle))
					  && t.GetConstructor(Type.EmptyTypes) != null
				select Activator.CreateInstance(t) as IManInTheMiddle;

				if (mitms.Count() == 0)
					throw new Exception(
						"No man-in-the-middle handler plugins could be found in the assembly." +
						"Please add a class that inplements the IManInTheMiddle interface."
					);
				if (mitms.Count() != 1)
					throw new NotSupportedException(
						"Multiple man-in-the-middle handler plugins in not supported." +
						"Please only add one class that implements the IManInTheMiddle interface."
					);
				return mitms.ElementAt(0);
			}
		}

		private static ushort DefaultPort
		{
			get { return 8081; }
		}

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

		private static int DefaultMaxLogSize
		{
			get { return 10; }
		}

		private static int DefaultAllowedLoginAttempts
		{
			get { return 5; }
		}

		private static int DefaultReadTimeout
		{
			get { return 0; }
		}

		private static int DefaultKeepAliveTimeout
		{
			get { return 1000; }
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Util.HttpsMitmProxyParams"/> class
		/// with no authentication required.
		/// </summary>
		public HttpsMitmProxyConfig()
		{
			StartTime = DateTime.UtcNow;
			LastModifiedTime = DateTime.UtcNow;
			OptionLastModifiedTime = DateTime.UtcNow;
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
