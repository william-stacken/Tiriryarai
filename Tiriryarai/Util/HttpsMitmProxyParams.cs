using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using Tiriryarai.Server;

namespace Tiriryarai.Util
{
	class HttpsMitmProxyParams
	{
		public IManInTheMiddle MitM { get; set; }
		public ushort Port { get; }
		public string Username { get; private set; }
		public string Password { get; private set; }

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

		public bool Authenticate { get { return Password != null; } }

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
			get { return 6; }
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Util.HttpsMitmProxyParams"/> class
		/// with no authentication required.
		/// </summary>
		/// <param name="port">The port the server will listen on.</param>
		public HttpsMitmProxyParams(ushort port)
		{
			Port = port;
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Util.HttpsMitmProxyParams"/> with
		/// HTTP basic authentication when accessing the custom MitM page. class.
		/// </summary>
		/// <param name="port">The port the server will listen on.</param>
		/// <param name="username">The username required for basic HTTP authentication.</param>
		/// /// <param name="password">The password required for basic HTTP authentication.</param>
		public HttpsMitmProxyParams(ushort port, string username, string password) : this(port)
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

			Username = username;
			Password = password;
		}
	}
}
