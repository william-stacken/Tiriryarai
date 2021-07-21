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
using System.Text;
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
		private HttpsMitmProxyParams prms;

		private readonly Dictionary<string, Action<HttpRequest, HttpResponse>> handlers;

		private HttpsMitmProxyCache cache;
		private Logger logger;

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Server.HttpsMitmProxy"/> class.
		/// Does not start the server.
		/// </summary>
		/// <param name="prms">Various parameters and configuration used by the proxy.</param>
		public HttpsMitmProxy(HttpsMitmProxyParams prms)
		{
			IPAddress ip = prms.IP;
			Directory.CreateDirectory(prms.ConfigDirectory);
			string logDir = Path.Combine(prms.ConfigDirectory, "logs");
			logger = Logger.GetSingleton();
			logger.Initialize(logDir, (uint) prms.LogVerbosity);
			handlers = new Dictionary<string, Action<HttpRequest, HttpResponse>>
			{
				{"/favicon.ico", Favicon},
				{"/cert", Cert},
				{Resources.CA_ISSUER_PATH, CaIssuer},
				{Resources.OCSP_PATH, OCSP},
				{Resources.CRL_PATH, CRL}
			};
			X509CertificateUrls urls = new X509CertificateUrls(
				"http://" + ip + ":" + prms.Port + Resources.CA_ISSUER_PATH,
				"http://" + ip + ":" + prms.Port + Resources.OCSP_PATH,
				"http://" + ip + ":" + prms.Port + Resources.CRL_PATH
			);
			cache = new HttpsMitmProxyCache(prms.Hostname, prms.ConfigDirectory, 500, 60000, urls);

			this.prms = prms;
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
			logger.Log(9, req.Host, "INCOMMING ISSUER REQUEST", req);
			resp.SetHeader("Content-Type", "application/pkix-cert");
			resp.SetBodyAndLength(cache.GetRootCA().GetRawCertData());
			logger.Log(9, req.Host, "OUTGOING INTERNAL RESPONSE", resp);
		}

		private void OCSP(HttpRequest req, HttpResponse resp)
		{
			logger.Log(8, req.Host, "INCOMMING OCSP REQUEST", req);
			X509OCSPResponse ocspResp = cache.GetOCSPResponse(req);
			resp.SetHeader("Content-Type", "application/ocsp-response");
			resp.SetBodyAndLength(ocspResp.RawData);
			logger.Log(8, req.Host, "OUTGOING INTERNAL RESPONSE", resp);
		}

		private void CRL(HttpRequest req, HttpResponse resp)
		{
			logger.Log(8, req.Host, "INCOMMING CRL REQUEST", req);
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
			TcpListener listener = new TcpListener(IPAddress.Any, prms.Port);
			listener.Start();
			Console.WriteLine("Listening for connections on https://" +
			                   prms.Hostname + ":" + prms.Port + "/");
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
			string host = null;
			try
			{
				host = null;
				Stream stream = client.GetStream();

				req = HttpRequest.FromStream(stream);
				if (req.Method == Method.CONNECT)
				{
					host = req.Uri.Split(':')[0];
					X509Certificate2 cert = cache.GetCertificate(host);

					resp = new HttpResponse(200, null, null, "Connection Established");
					resp.ToStream(stream);

					SslStream sslStream = new SslStream(stream, false);
					try
					{
						sslStream.AuthenticateAsServer(cert);

						req = HttpRequest.FromStream(sslStream);
						resp = HandleRequest(req, tls: true);

						resp.ToStream(sslStream);
					}
					catch (Exception e)
					{
						logger.LogException(e);
					}
					finally
					{
						sslStream.Close();
					}
				}
				else
				{
					// TODO Either redirect the client to the host but in HTTPS using 301,
					// or send a 405 that only CONNECT is supported. Either way, proxying
					// non-HTTPS traffic should probably not be supported since it's kind of
					// unorthodox and it would be tricky to support proxy authentication
					// alongside it.
					resp = HandleRequest(req, tls: false);
					resp.ToStream(stream);
				}
			}
			catch (Exception e)
			{
				logger.LogException(e, host);
			}
			finally
			{
				client.Close();
			}
		}

		private HttpResponse HandleRequest(HttpRequest req, bool tls)
		{
			HttpResponse resp;
			HttpMessage http;
			string host = req.Host;

			if (!IsDestinedToMitm(req))
			{
				if (!prms.MitM.Block(host))
				{
					logger.Log(6, host, "RECEIVED REQUEST", req);
					Console.WriteLine("\n--------------------\n" +
					    req.Method + " https://" + host + req.Path);

					http = prms.MitM.HandleRequest(req);
					if (http is HttpRequest modified)
					{
						logger.Log(7, host, "MODIFIED REQUEST", modified);

						resp = new HttpsClient(host).Send(modified);
						logger.Log(6, host, "RECEIVED RESPONSE", resp);

						resp = prms.MitM.HandleResponse(resp, req);
						logger.Log(7, host, "MODIFIED RESPONSE", resp);
					}
					else if (http is HttpResponse intercepted)
					{
						logger.Log(6, host, "CUSTOM RESPONSE", intercepted);
						resp = intercepted;
					}
					else // Should never be reached
					{
						throw new Exception("Invalid message type");
					}
				}
				else // Host is blocked, send bad gateway
				{
					logger.Log(6, req.Host, "BLOCKED REQUEST", req);
					resp = new HttpResponse(502);
				}
			}
			else
			{
				resp = HomePage(req, tls);
			}
			return resp;
		}

		private bool IsDestinedToMitm(HttpRequest req)
		{
			// TODO: This may not be an exhaustive list, if there is another
			// loopback IP, there is a risk of an infinite loop where the proxy
			// sends requests to itself
			string host = req.Host.Split(':')[0];
			return host.Equals(prms.Hostname) ||
			       host.Equals(prms.IP.ToString()) ||
				   host.Equals("localhost") ||
				   host.Equals("127.0.0.1");
		}

		public HttpResponse HomePage(HttpRequest req, bool tls)
		{
			HttpResponse resp = new HttpResponse(200);
			resp.SetHeader("Server", "Tiriryarai/" + Resources.Version);
			resp.SetHeader("Date", DateTime.Now.ToString("r"));

			if (handlers.TryGetValue(req.Path, out Action<HttpRequest, HttpResponse> handler))
			{
				handler(req, resp);
			}
			else if (!tls)
			{
				// If the client is attempting to access insecurely, show
				// default welcome page with info.
				resp.SetHeader("Content-Type", "text/html");
				resp.SetHeader("Expires", new DateTime(1990, 1, 1).ToString("r"));
				resp.SetHeader("Pragma", "no-cache");
				resp.SetHeader("Cache-Control", "no-store, must-revalidate");
				resp.SetBodyAndLength(Encoding.Default.GetBytes(
					string.Format(Resources.WELCOME_PAGE, prms.Hostname, prms.Port)
				));
			}
			else if (prms.Authenticate && !req.BasicAuthenticated(prms.Username, prms.Password))
			{
				resp.Status = 401;
				resp.SetHeader("Content-Type", "text/html");
				resp.SetHeader("Content-Length", "0");
				resp.SetHeader("WWW-Authenticate", "Basic realm=\"Access to MitM plugin homepage\"");
			}
			else
			{
				resp = prms.MitM.HomePage(req);
			}
			return resp;
		}
	}
}
