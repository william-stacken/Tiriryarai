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
using System.Reflection;

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
		private static HttpsMitmProxyConfig singleton;

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
				if (value.ToLower().Equals(Resources.HOSTNAME.ToLower()))
					throw new ArgumentException("The hostname may not be \"" + Resources.HOSTNAME + "\".");
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

		private bool remoteauth;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Authentication, "checkbox", "a|change-auth")]
		[Description("Activate admin remote changing of username and admin password. " +
			"If remote configuration is disabled this property is ignored. <strong>NOTICE:</strong> " +
			"Once disabled, it cannot be enabled without restarting Tiriryarai.")]
		public bool ChangeAuthentication
		{
			get { return remoteauth; }
			set { remoteauth = value; LastModifiedTime = DateTime.UtcNow; }
		}

		private string user;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Username | HttpsMitmProxyProperty.Authentication, "text", "u|username=")]
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

		[HttpsMitmProxy(HttpsMitmProxyProperty.Password | HttpsMitmProxyProperty.Authentication | HttpsMitmProxyProperty.Cache,
			"password", "w|password=")]
		[Description("The password required for accessing the admin pages if one should be required. " +
			"It will be sent securely using HTTPS only and can only be set if the username is set. " +
			"<strong>NOTICE:</strong> If this password is changed, Tiriryarai will be unable to read any existing " +
			"logs. If that is a concern, please back up the logs first. Furthermore, if updated at runtime, the " +
			"cache will be cleared, meaning that you must re-install the root certificate.")]
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

		[HttpsMitmProxy(HttpsMitmProxyProperty.Password | HttpsMitmProxyProperty.Standard, "password", "x|proxy-pass=")]
		[Description("The password required for using the proxy if one should be required. It will be sent " +
			"insecurely using HTTP and can only be set if the username is set. Also, it <strong>SHOULD NOT</strong> " +
			"be the same as the admin password.")]
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

		private bool certignore;

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

		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard, "number", "k|alive-timeout=")]
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

		private int? responsecachetime = null;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard, "number", "z|cache-response=")]
		[Description("The time in milliseconds to cache a HTTP response received from a remote server. " +
			"Negative values and zero are infinite means responses should not be cached which is the default.")]
		public int CacheResponseTime
		{
			get
			{
				if (responsecachetime == null)
					responsecachetime = DefaultCacheResponseTime;
				return (int)responsecachetime;
			}
			set
			{
				responsecachetime = value;
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		private uint? cachemmemlimit;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard | HttpsMitmProxyProperty.Cache,
			"number", "m|cache-mem=")]
		[Description("Memory limit imposed on the cache in megabytes. If this limit is breached, cache " +
			"entries will be expelled. Value must be positive and the default is 200. <strong>NOTICE:</strong> " +
			"If this property is updated at runtime, the cache will be cleared, meaning that you must re-install " +
			"the root certificate.")]
		public uint CacheMemoryLimit
		{
			get
			{
				if (cachemmemlimit == null)
					cachemmemlimit = DefaultCacheMemoryLimit;
				return (uint) cachemmemlimit;
			}
			set
			{
				cachemmemlimit = value;
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		private uint? cachepoll;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard | HttpsMitmProxyProperty.Cache,
			"number", "o|cache-poll=")]
		[Description("The polling interval at which to check that the cache size has not breached the limit in " +
			"milliseconds. Value must be positive and the default is 30000, or 30 min. <strong>NOTICE:</strong> " +
			"If this property is updated at runtime, the cache will be cleared, meaning that you must re-install " +
			"the root certificate.")]
		public uint CachePollingInterval
		{
			get
			{
				if (cachepoll == null)
					cachepoll = DefaultCachePollingInterval;
				return (uint) cachepoll;
			}
			set
			{
				cachepoll = value;
				LastModifiedTime = DateTime.UtcNow;
			}
		}

		private bool disablestdout;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard, "checkbox", "q|quiet")]
		[Description("Do not print anything to standard out, such as incomming requests " +
			"or status information.")]
		public bool DisableStdout
		{
			get { return disablestdout; }
			set { disablestdout = value; LastModifiedTime = DateTime.UtcNow; }
		}

		private bool lightMode;

		[HttpsMitmProxy(HttpsMitmProxyProperty.Standard, "checkbox", "j|light-mode")]
		[Description("Only the HTTP headers will be sent to plugins and the HTTP body " +
			"will be forwarded without being cached. For use on contrained devices. (CURRENTLY NOT SUPPORTED AND DOES NOTHING)")]
		public bool LightMode
		{
			get { return lightMode; }
			set { lightMode = value; LastModifiedTime = DateTime.UtcNow; }
		}

		[HttpsMitmProxy(HttpsMitmProxyProperty.None, null, null)]
		[Description("A flag indicating that Tiriryarai is undergoing maintenance. This could for " +
			"example happen due to the cache being cleared or another resource heavy operation.")]
		public bool Maintenance { get; set; }

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
		/// <value>The timestamp when admin page configuration was last modified.</value>
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

		private static int DefaultCacheResponseTime
		{
			get { return 0; }
		}

		private static uint DefaultCacheMemoryLimit
		{
			get { return 200; }
		}

		private static uint DefaultCachePollingInterval
		{
			get { return 30000; }
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Util.HttpsMitmProxyParams"/> class
		/// with no authentication required.
		/// </summary>
		private HttpsMitmProxyConfig()
		{
			StartTime = DateTime.UtcNow;
			LastModifiedTime = DateTime.UtcNow;
			OptionLastModifiedTime = DateTime.UtcNow;
		}

		public static HttpsMitmProxyConfig GetSingleton()
		{
			if (singleton == null)
				singleton = new HttpsMitmProxyConfig();
			return singleton;
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
		/// <param name="password">The password to check.</param>
		public bool IsProxyAuthenticated(string username, string password)
		{
			byte[] key;
			if (!ProxyAuthenticate)
				return true;
			if (username == null || (key = ToPassKey(password)) == null)
				return false;
			return username.Equals(Username) && KeysEqual(ProxyPassKey, key);
		}

		/// <summary>
		/// Sets properties based on the given dictionary mapping property names to new
		/// values. This method is atomic, it will either fail by throwing an exception or
		/// set all recognized properties found in the dictionary.
		/// </summary>
		/// <returns><c>true</c>, if a property that requires cache clear was set; otherwise, <c>false</c>.</returns>
		/// <param name="props">A dictionary of property names mapped to new values
		/// representing properties that should be updated.</param>
		/// <param name="init">Boolean indicating whether to allow updating static properties
		/// that can only be set during initialization of the proxy.</param>
		public bool SetProperties(Dictionary<string, string> props, bool init)
		{
			if (props == null)
				throw new ArgumentNullException(nameof(props));

			KeyValuePair<PropertyInfo, object>? username = null;
			List<KeyValuePair<PropertyInfo, object>> passwords = new List<KeyValuePair<PropertyInfo, object>>();
			List<KeyValuePair<PropertyInfo, object>> commits = new List<KeyValuePair<PropertyInfo, object>>();
			HttpsMitmProxyProperty type;
			object value = null;
			bool cacheClear = false;
			foreach (var p in GetType().GetProperties())
			{
				if (p.GetCustomAttribute(typeof(HttpsMitmProxyAttribute), false) is HttpsMitmProxyAttribute attr &&
					(type = attr.Type) != HttpsMitmProxyProperty.None &&
					(init || (type & HttpsMitmProxyProperty.Static) == 0) &&
					(init || ChangeAuthentication || ((type & HttpsMitmProxyProperty.Authentication) == 0)) &&
					(init || LogManagement || ((type & HttpsMitmProxyProperty.Log) == 0)) &&
					p.GetSetMethod() != null)
				{
					if ((value = GetValueInDict(p, props)) == null)
						continue;

					if (((type & HttpsMitmProxyProperty.Cache) != 0) &&
						!string.IsNullOrWhiteSpace(value.ToString()) &&
						(p.GetGetMethod() == null || !p.GetValue(this).Equals(value)))
					{
						cacheClear = true;
					}

					if ((type & HttpsMitmProxyProperty.Username) != 0 &&
						!string.IsNullOrWhiteSpace(value.ToString()))
					{
						if (new Regex("[\x00-\x1f\x7f:]").IsMatch(value.ToString()))
							throw new ArgumentException("Invalid username");
						username = new KeyValuePair<PropertyInfo, object>(p, value);
					}
					else if ((type & HttpsMitmProxyProperty.Password) != 0 &&
						!string.IsNullOrWhiteSpace(value.ToString()))
					{
						if (new Regex("[\x00-\x1f\x7f]").IsMatch(value.ToString()))
							throw new ArgumentException("Invalid password");
						passwords.Add(new KeyValuePair<PropertyInfo, object>(p, value));
					}
					else
					{
						commits.Add(new KeyValuePair<PropertyInfo, object>(p, value));
					}
				}
			}
			// Validate usernames and passwords and add them to commits
			if (username != null)
			{
				commits.Add((KeyValuePair<PropertyInfo, object>) username);
				foreach (KeyValuePair<PropertyInfo, object> pass in passwords)
					commits.Add(pass);
			}
			else if (Authenticate || ProxyAuthenticate)
			{
				throw new ArgumentException("Cannot remove the username once a password has been set.");
			}
			else if (passwords.Count > 0)
			{
				throw new ArgumentException("Cannot set a password without setting a username.");
			}

			// Finally, apply commits
			foreach (var commit in commits)
				commit.Key.SetValue(this, commit.Value);

			return cacheClear;
		}

		private object GetValueInDict(PropertyInfo p, Dictionary<string, string> props)
		{
			bool exists = props.TryGetValue(p.Name.ToLower(), out string rawValue);
			Type t = p.PropertyType;
			if (t.IsPrimitive)
			{
				if (t.Equals(typeof(bool)))
					return exists;
				else if (exists && rawValue != null)
					return Convert.ChangeType(rawValue, p.PropertyType);
			}
			else if (t.Equals(typeof(string)))
			{
				return rawValue;
			}
			return null;
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
