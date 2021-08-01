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
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using Tiriryarai.Http;

namespace Tiriryarai.Server
{
	/// <summary>
	/// A class for sending HTTP requests to hosts and retreiving HTTP responses.
	/// </summary>
	class HttpsClient
	{
		public string Hostname { get; }
		public string HostnameWithPort { get; }

		private readonly ushort port;
		private readonly int timeout;
		private readonly bool tls;
		private readonly bool ignoreCerts;
		private TcpClient openConnection;
		private Stream server;

		private static bool ValidateServerCertificate(
			object sender,
			X509Certificate certificate,
			X509Chain chain,
			SslPolicyErrors sslPolicyErrors)
		{
			// WARNING: Ignores invalid certificates
			return true;
		}

		public HttpsClient(string hostname) : this(hostname, 0) { }
		public HttpsClient(string hostname, int timeout) : this(hostname, timeout, true) { }
		public HttpsClient(string hostname, int timeout, bool tls) : this(hostname, timeout, tls, false) { }

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Server.HttpsClient"/> class
		/// with the host it should interact with. This does not start an HTTPS session.
		/// </summary>
		/// <param name="hostname">The host and optional port that the client should interact with.
		/// <example><c>example.org:1234</c> means connect to example.org at port 1234</example>
		/// <example><c>example.org</c> means connect to example.org at port 443 (default)</example>
		/// </param>
		/// <param name="timeout">The amount of time to wait for responses in milliseconds.</param>
		/// <param name="tls">if <c>true</c>, send requests over TLS</param>
		/// <param name="ignoreCerts">if <c>true</c>, ignore invalid certificates.</param>
		public HttpsClient(string hostname, int timeout, bool tls, bool ignoreCerts)
		{
			string[] nameSplit = hostname.Split(':');
			ushort p = (ushort)(tls ? 443 : 80);
			if (nameSplit.Length > 1)
			{
				ushort.TryParse(nameSplit[1], out p);
			}
			if (Uri.CheckHostName(nameSplit[0]) == UriHostNameType.Unknown)
			{
				throw new ArgumentException(hostname[0] + " is not a valid hostname!");
			}
			this.Hostname = nameSplit[0];
			this.HostnameWithPort = hostname;
			this.port = p;
			this.tls = tls;
			this.timeout = timeout;
			this.ignoreCerts = ignoreCerts;
		}

		/// <summary>
		/// Opens an HTTPS session to the host, sends the given HTTP request
		/// and retreives an HTTP response. Examines the <c>Connection</c>
		/// headers of the HTTP messages to determine whether to keep the
		/// connection alive or close it.
		/// </summary>
		/// <returns>The retreived HTTP response.</returns>
		/// <param name="req">The HTTP request to send.</param>
		public HttpResponse Send(HttpRequest req)
		{
			if (isClosed)
			{
				openConnection = new TcpClient(Hostname, port);
				server = openConnection.GetStream();
				if (timeout > 0)
					server.ReadTimeout = timeout;
			}
			if (tls && !(server is SslStream))
			{
				SslStream sslStream = ignoreCerts ? new SslStream(
					openConnection.GetStream(),
					false,
					new RemoteCertificateValidationCallback(ValidateServerCertificate),
					null
				) : new SslStream(openConnection.GetStream());
				sslStream.AuthenticateAsClient(Hostname, null,
					SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12 | SslProtocols.Tls13, false);

				server = sslStream;
			}
			req.ToStream(server);
			server.Flush();

			return HttpResponse.FromStream(server);
		}

		// TODO is it better to implement IDisposable? The object should be closable
		// but shouldn't necessarily be disposed when it is closed since we may want
		// to open another connection to the same server

		public bool isClosed
		{
			get
			{
				bool isClosed = openConnection == null ||
							!openConnection.Connected ||
							server == null ||
							!server.CanWrite;
				// Close just in case there is some half open connections
				if (isClosed)
					Close();
				return isClosed;
			}
		}

		public void Close()
		{
			if (server != null)
			{
				server.Close();
				server = null;
			}
			if (openConnection != null)
			{
				openConnection.Close();
				openConnection = null;
			}
		}
	}
}
