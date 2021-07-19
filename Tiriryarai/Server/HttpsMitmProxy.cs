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
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Collections.Generic;

using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using System.IO;

using Tiriryarai.Crypto;
using Tiriryarai.Http;
using Tiriryarai.Util;

using Mono.Security.X509;

namespace Tiriryarai.Server
{
	/// <summary>
	/// A class acting as an HTTPS proxy that can tamper with incoming requests
	/// and outgoing responses before forwarding them to their destination. To use the
	/// proxy, it's root CA must be installed in the client.
	/// </summary>
	class HttpsMitmProxy
	{
		private IPAddress ip;
		private readonly ushort port;

		private readonly Dictionary<string, Action<HttpRequest, HttpResponse>> handlers;

		private HttpsMitmProxyCache cache;
		private IManInTheMiddle mitm;
		private Logger logger;

		public HttpsMitmProxy(IManInTheMiddle mitm, ushort port) :
		    this(mitm, port, DefaultIPAddress, DefaultConfigDir, DefaultVerbosity) { }
		public HttpsMitmProxy(IManInTheMiddle mitm, ushort port, IPAddress ip) :
		    this(mitm, port, ip, DefaultConfigDir, DefaultVerbosity) { }
		public HttpsMitmProxy(IManInTheMiddle mitm, ushort port, string configDir) :
		    this(mitm, port, DefaultIPAddress, configDir, DefaultVerbosity) { }
		public HttpsMitmProxy(IManInTheMiddle mitm, ushort port, uint logVerbosity) :
		    this(mitm, port, DefaultIPAddress, DefaultConfigDir, logVerbosity) { }
		public HttpsMitmProxy(IManInTheMiddle mitm, ushort port, IPAddress ip, string configDir) :
		    this(mitm, port, ip, configDir, DefaultVerbosity) { }
		public HttpsMitmProxy(IManInTheMiddle mitm, ushort port, IPAddress ip, uint logVerbosity) :
		    this(mitm, port, ip, DefaultConfigDir, logVerbosity) { }
		public HttpsMitmProxy(IManInTheMiddle mitm, ushort port, string configDir, uint logVerbosity) :
		    this(mitm, port, DefaultIPAddress, configDir, logVerbosity) { }

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Server.HttpsMitmProxy"/> class.
		/// Does not start the server.
		/// </summary>
		/// <param name="mitm">A man-in-the-middle handler that will receive incomming requests and outgoing responses
		/// to tamper with them.</param>
		/// <param name="port">The port the server will listen on.</param>
		/// <param name="ip">The IP address the server will listen on.</param>
		/// <param name="configDir">A directory where certificates, server configuration, and log files will be stored.</param>
		/// <param name="logVerbosity">The higher this value is, the more information will be logged.</param>
		public HttpsMitmProxy(IManInTheMiddle mitm, ushort port, IPAddress ip, string configDir, uint logVerbosity)
		{
			Directory.CreateDirectory(configDir);
			string logDir = Path.Combine(configDir, "logs");
			logger = Logger.GetSingleton();
			logger.Initialize(logDir, logVerbosity);
			handlers = new Dictionary<string, Action<HttpRequest, HttpResponse>>
			{
				{"/favicon.ico", Favicon},
				{"/cert", Cert},
				{Resources.CA_ISSUER_PATH, CaIssuer},
				{Resources.OCSP_PATH, OCSP},
				{Resources.CRL_PATH, CRL}
			};
			X509CertificateUrls urls = new X509CertificateUrls(
				"http://" + ip + ":" + port + Resources.CA_ISSUER_PATH,
				"http://" + ip + ":" + port + Resources.OCSP_PATH,
				"http://" + ip + ":" + port + Resources.CRL_PATH
			);
			cache = new HttpsMitmProxyCache(configDir, 500, 60000, urls);

			this.ip = ip;
			this.port = port;
			this.mitm = mitm;
		}

		/* HTTP request handler callbacks */

		// TODO Figure out if there are any more standardized HTTP headers to send for these responses
		private void Favicon(HttpRequest req, HttpResponse resp)
		{
			resp.SetHeader("Content-Type", "image/x-icon");
			resp.SetBodyAndLength(Resources.Get("favicon.ico"));
			logger.Log(10, req.Host, "OUTGOING INTERNAL RESPONSE", resp);
		}

		private void Cert(HttpRequest req, HttpResponse resp)
		{
			resp.SetHeader("Content-Type", "application/octet-stream");
			resp.SetHeader("Content-Disposition", "attachment; filename=Tiriryarai.der");
			resp.SetBodyAndLength(cache.GetRootCA().GetRawCertData());
			logger.Log(9, req.Host, "OUTGOING INTERNAL RESPONSE", resp);
		}

		private void CaIssuer(HttpRequest req, HttpResponse resp)
		{
			resp.SetHeader("Content-Type", "application/pkix-cert");
			resp.SetBodyAndLength(cache.GetRootCA().GetRawCertData());
			logger.Log(9, req.Host, "OUTGOING INTERNAL RESPONSE", resp);
		}

		private void OCSP(HttpRequest req, HttpResponse resp)
		{
			X509OCSPResponse ocspResp = cache.GetOCSPResponse(req);
			resp.SetHeader("Content-Type", "application/ocsp-response");
			resp.SetBodyAndLength(ocspResp.RawData);
			logger.Log(8, req.Host, "OUTGOING INTERNAL RESPONSE", resp);
		}

		private void CRL(HttpRequest req, HttpResponse resp)
		{
			X509Crl crl = cache.GetCrl();
			resp.SetHeader("Content-Type", "application/pkix-crl");
			resp.SetHeader("Expires", crl.ThisUpdate.ToString("r"));
			resp.SetHeader("Last-Modified", crl.NextUpdate.ToString("r"));
			resp.SetBodyAndLength(crl.RawData);
			logger.Log(8, req.Host, "OUTGOING INTERNAL RESPONSE", resp);
		}

		/// <summary>
		/// Start the server and listens to incomming requests.
		/// </summary>
		public void Start()
		{
			TcpListener listener = new TcpListener(ip, port);
			listener.Start();
			Console.WriteLine("Listening for connections on https://" + ip + ":" + port + "/");
			while (true)
			{
				TcpClient client = listener.AcceptTcpClient();
				Task.Run(() => ProcessClient(client));
			}
		}

		private void ProcessClient(TcpClient client)
		{
			HttpRequest req;
			HttpResponse resp;
			HttpMessage http;
			try
			{
				Stream stream = client.GetStream();

				req = HttpRequest.FromStream(stream);
				if (req.Method == Method.CONNECT)
				{
					string host = req.Uri;
					resp = new HttpResponse(200, null, null, "Connection Established");
					resp.ToStream(stream);

					X509Certificate2 cert = cache.GetCertificate(host);

					SslStream sslStream = new SslStream(stream, false);
					sslStream.AuthenticateAsServer(cert);

					req = HttpRequest.FromStream(sslStream);

					if (!mitm.Block(host))
					{
						logger.Log(6, req.Host, "RECEIVED REQUEST", req);

						if (!IsDestinedToMitm(req))
						{
							Console.WriteLine("\n--------------------\n" + req.Method + " https://" + req.Host + req.Uri);

							http = mitm.HandleRequest(req);
							if (http is HttpRequest modified)
							{
								logger.Log(7, req.Host, "MODIFIED REQUEST", modified);
								resp = new HttpsClient(req.Host).Send(modified);
								logger.Log(6, req.Host, "RECEIVED RESPONSE", resp);
								resp = mitm.HandleResponse(resp, req);
								logger.Log(7, req.Host, "MODIFIED RESPONSE", resp);
							}
							else if (http is HttpResponse intercepted)
							{
								logger.Log(6, req.Host, "CUSTOM RESPONSE", intercepted);
								resp = intercepted;
							}
							else
							{
								throw new Exception("Invalid message type");
							}
							resp.ToStream(sslStream);
							sslStream.Close();
							client.Close();
							return;
						}
					}
					else // Host is blocked, send bad gateway
					{
						logger.Log(6, req.Host, "BLOCKED REQUEST", req);
						resp = new HttpResponse(502);
						resp.ToStream(sslStream);
						sslStream.Close();
						client.Close();
						return;
					}
				}
				resp = HomePage(req);
				resp.ToStream(stream);
				client.Close();
			}
			catch (Exception e)
			{
				logger.LogException(e);
			}
		}

		private bool IsDestinedToMitm(HttpRequest req)
		{
			string host = req.Host.Split(':')[0];
			return host.Equals(ip.ToString()) || host.Equals("localhost") || host.Equals("127.0.0.1");
		}

		public HttpResponse HomePage(HttpRequest req)
		{
			HttpResponse resp = new HttpResponse(200);
			resp.SetHeader("Date", DateTime.Now.ToString("r"));

			if (handlers.TryGetValue(req.Path, out Action<HttpRequest, HttpResponse> handler))
			{
				handler(req, resp);
				return resp;
			}
			return mitm.HomePage(req);
		}

		public static IPAddress DefaultIPAddress
		{
			get
			{
				IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
				foreach (IPAddress ipa in host.AddressList)
				{
					if (ipa.AddressFamily == AddressFamily.InterNetwork)
					{
						return ipa;
					}
				}
				throw new Exception("The system has no IPv4 address to use by default.");
			}
		}

		public static string DefaultConfigDir
		{
			get
			{
				return Path.Combine(
					Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
					"Tiriryarai"
				);
			}
		}

		public static uint DefaultVerbosity
		{
			get { return 6; }
		}
	}
}
