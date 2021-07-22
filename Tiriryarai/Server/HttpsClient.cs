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
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using Tiriryarai.Http;

namespace Tiriryarai.Server
{
	/// <summary>
	/// A class for sending HTTP requests to hosts and retreiving HTTP responses.
	/// WARNING: Ignores invalid certificates.
	/// </summary>
	class HttpsClient
	{
		private readonly string hostname;
		private readonly ushort port;
		private static bool ValidateServerCertificate(
			object sender,
			X509Certificate certificate,
			X509Chain chain,
			SslPolicyErrors sslPolicyErrors)
		{
			// TODO Make it possible to configure Tiriryarai to check invalid certificates
			// WARNING: Ignore invalid certificates
			return true;
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Server.HttpsClient"/> class
		/// with the host it should interact with. This does not start an HTTPS session.
		/// </summary>
		/// <param name="hostname">The host and optional port that the client should interact with.
		/// <example><c>example.org:1234</c> means connect to example.org at port 1234</example>
		/// <example><c>example.org</c> means connect to example.org at port 443 (default)</example>
		/// </param>
		public HttpsClient(string hostname)
		{
			string[] nameSplit = hostname.Split(':');
			ushort p = 443;
			if (nameSplit.Length > 1)
			{
				ushort.TryParse(nameSplit[1], out p);
			}
			if (Uri.CheckHostName(nameSplit[0]) == UriHostNameType.Unknown)
			{
				throw new ArgumentException(hostname[0] + " is not a valid hostname!");
			}
			this.hostname = nameSplit[0];
			this.port = p;
		}

		/// <summary>
		/// Opens an HTTPS session to the host, sends the given HTTP request
		/// and retreives an HTTP response.
		/// </summary>
		/// <returns>The retreived HTTP response.</returns>
		/// <param name="req">The HTTP request to send.</param>
		public HttpResponse Send(HttpRequest req)
		{
			HttpResponse resp = null;
			TcpClient client = new TcpClient(hostname, port);
			SslStream sslStream = new SslStream(
				client.GetStream(),
				false,
				new RemoteCertificateValidationCallback(ValidateServerCertificate),
				null
			);
			sslStream.AuthenticateAsClient(client.Client.RemoteEndPoint.ToString(), null, 
				SslProtocols.Tls | SslProtocols.Tls11 | SslProtocols.Tls12 | SslProtocols.Tls13, false);
			req.ToStream(sslStream);
			sslStream.Flush();

			resp = HttpResponse.FromStream(sslStream);

			client.Close();
			return resp;
		}
	}
}
