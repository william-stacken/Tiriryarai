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

		private readonly Dictionary<string, Action<HttpRequest, HttpResponse>> httpHandlers;
		private readonly Dictionary<string, Action<HttpRequest, HttpResponse>> httpsHandlers;

		private HttpsMitmProxyCache cache;
		private Logger logger;

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Server.HttpsMitmProxy"/> class.
		/// Does not start the server.
		/// </summary>
		/// <param name="prms">Various parameters and configuration used by the proxy.</param>
		public HttpsMitmProxy(HttpsMitmProxyParams prms)
		{
			if (!prms.Authenticate)
			{
				Console.WriteLine(
					"NOTICE: Authentication for accessing admin pages is disabled. " +
					"Hosting Tiriryarai on the public internet or an untrusted network is strongly discouraged. " +
					"If this was unintentional, see the help by using the \"-h\" flag."
				);
			}

			string host = prms.Hostname;
			Directory.CreateDirectory(prms.ConfigDirectory);
			logger = Logger.GetSingleton();
			logger.Initialize(
			    Path.Combine(prms.ConfigDirectory, "logs"),
				(uint) prms.LogVerbosity,
				(uint) prms.MaxLogSize);
			httpHandlers = new Dictionary<string, Action<HttpRequest, HttpResponse>>
			{
				{"favicon.ico", (req, resp) => {
					if (req.GetDateHeader("If-Modified-Since") != null)
					{
						resp.Status = 304;
						return;
					}
					resp.SetHeader("Cache-Control", "public");
					resp.SetHeader("Content-Type", "image/x-icon");
					resp.SetDecodedBodyAndLength(Resources.Get("favicon.ico"));
					logger.Log(15, req.Host, "OUTGOING INTERNAL RESPONSE", resp);
				}},
				{"cert", (req, resp) => {
					if (req.GetDateHeader("If-Modified-Since") != null)
					{
						resp.Status = 304;
						return;
					}
					resp.SetHeader("Cache-Control", "public");
					resp.SetHeader("Content-Type", "application/octet-stream");
					resp.SetHeader("Content-Disposition", "attachment; filename=Tiriryarai.der");
					resp.SetDecodedBodyAndLength(cache.GetRootCA().GetRawCertData());
					logger.Log(15, req.Host, "OUTGOING INTERNAL RESPONSE", resp);
				}},
				{Resources.CA_ISSUER_PATH, (req, resp) =>
				{
					logger.Log(8, req.Host, "INCOMMING ISSUER REQUEST", req);
					if (req.GetDateHeader("If-Modified-Since") != null)
					{
						resp.Status = 304;
						return;
					}
					resp.SetHeader("Content-Type", "application/pkix-cert");
					resp.SetDecodedBodyAndLength(cache.GetRootCA().GetRawCertData());
					logger.Log(15, req.Host, "OUTGOING ISSUER RESPONSE", resp);
				}},
				{Resources.OCSP_PATH, (req, resp) =>
				{
					logger.Log(8, req.Host, "INCOMMING OCSP REQUEST", req);
					X509OCSPResponse ocspResp = cache.GetOCSPResponse(req);
					if (req.GetDateHeader("If-Modified-Since")?.CompareTo(ocspResp.ExpiryDate) < 0)
					{
						resp.Status = 304;
						return;
					}
					resp.SetHeader("Content-Type", "application/ocsp-response");
					resp.SetDecodedBodyAndLength(ocspResp.RawData);
					logger.Log(15, req.Host, "OUTGOING OCSP RESPONSE", resp);
				}},
				{Resources.CRL_PATH, (req, resp) =>
				{
					logger.Log(8, req.Host, "INCOMMING CRL REQUEST", req);
					X509Crl crl = cache.GetCrl();
					if (req.GetDateHeader("If-Modified-Since")?.CompareTo(crl.NextUpdate) < 0)
					{
						resp.Status = 304;
						return;
					}
					resp.SetHeader("Content-Type", "application/pkix-crl");
					resp.SetHeader("Expires", crl.ThisUpdate.ToString("r"));
					resp.SetHeader("Last-Modified", crl.NextUpdate.ToString("r"));
					resp.SetDecodedBodyAndLength(crl.RawData);
					logger.Log(15, req.Host, "OUTGOING CRL RESPONSE", resp);
				}}
			};
			httpsHandlers = new Dictionary<string, Action<HttpRequest, HttpResponse>>
			{
				{"logs", (req, resp) => {
					if (prms.LogManagement)
					{
						logger.Log(8, req.Host, "INCOMMING LOG REQUEST", req);
						DateTime? ifModified = req.GetDateHeader("If-Modified-Since");
						string logFile = req.SubPath(1);

						if ("".Equals(logFile))
						{
							logFile = req.GetQueryParam("delete");
							if (logFile != null)
							{
								logger.DeleteLog(logFile);
							}
							// Get log directory
							string[] logs;
							StringBuilder entryBuilder = new StringBuilder();
							if (ifModified?.CompareTo(logger.LastWriteTimeDirectory) < 0)
							{
								resp.Status = 304;
								return;
							}
							resp.SetHeader("Content-Type", "text/html");
							logs = logger.LogNames;
							foreach (string log in logs)
							{
								entryBuilder.Append(string.Format(
								    Resources.LOG_ENTRY,
									log,
									string.Format("{0:0.00}", (double)logger.LogSize(log) / 1024) + " kiB",
									logger.LastWriteTime(log).ToString("r")
								));
							}
							resp.SetDecodedBodyAndLength(Encoding.Default.GetBytes(
							    string.Format(Resources.LOG_PAGE, entryBuilder)
							));
							return;
						}
						else
						{
							bool exists = logger.Exists(logFile);
							if (ifModified?.CompareTo(logger.LastWriteTime(logFile)) < 0)
							{
								resp.Status = 304;
								return;
							}
							resp.SetHeader("Content-Type", "text/html");
							if (exists && "".Equals(req.SubPath(2))) // Only one path level allowed
							{
								resp.SetHeader("Vary", "Accept-Encoding");
								resp.PickEncoding(req, new Dictionary<ContentEncoding, int> {
									{ ContentEncoding.GZip, 2},
									{ ContentEncoding.Deflate, 1},
								});

								resp.SetDecodedBodyAndLength(logger.ReadLog(logFile));
								return;
							}
						}
					}
					resp.Status = 404;
					resp.SetDecodedBodyAndLength(Encoding.Default.GetBytes(Resources.NON_PAGE));
				}}
			};
			X509CertificateUrls urls = new X509CertificateUrls(
				"http://" + host + ":" + prms.Port + "/" + Resources.CA_ISSUER_PATH,
				"http://" + host + ":" + prms.Port + "/" + Resources.OCSP_PATH,
				"http://" + host + ":" + prms.Port + "/" + Resources.CRL_PATH
			);
			cache = new HttpsMitmProxyCache(prms.Hostname, prms.ConfigDirectory, 500, 60000, urls);

			this.prms = prms;
		}

		/// <summary>
		/// Start the server and listens to incomming requests.
		/// </summary>
		public void Start()
		{
			TcpListener listener = new TcpListener(IPAddress.Any, prms.Port);
			listener.Start();
			Console.WriteLine("Listening for connections on " + prms.HttpsUrl);
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

			Console.WriteLine("\n--------------------\n" +
						req.Method + (tls ? " https://" : " http://") + host + req.Path);

			if (!IsDestinedToMitm(req))
			{
				if (!prms.MitM.Block(host))
				{
					logger.Log(3, host, "RECEIVED REQUEST", req);

					http = prms.MitM.HandleRequest(req);
					if (http is HttpRequest modified)
					{
						logger.Log(12, host, "MODIFIED REQUEST", modified);

						resp = new HttpsClient(host).Send(modified);
						logger.Log(3, host, "RECEIVED RESPONSE", resp);

						resp = prms.MitM.HandleResponse(resp, req);
						logger.Log(12, host, "MODIFIED RESPONSE", resp);
					}
					else if (http is HttpResponse intercepted)
					{
						logger.Log(3, host, "CUSTOM RESPONSE", intercepted);
						resp = intercepted;
					}
					else // Should never be reached
					{
						throw new Exception("Invalid message type");
					}
				}
				else // Host is blocked, send bad gateway
				{
					logger.Log(3, req.Host, "BLOCKED REQUEST", req);
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

		private HttpResponse HomePage(HttpRequest req, bool tls)
		{
			HttpResponse resp = new HttpResponse(200);
			resp.SetHeader("Server", "Tiriryarai/" + Resources.Version);
			resp.SetHeader("Date", DateTime.Now.ToString("r"));
			resp.SetHeader("Connection", "close");

			if (httpHandlers.TryGetValue(req.SubPath(0), out Action<HttpRequest, HttpResponse> handler))
			{
				handler(req, resp);
			}
			else if (!tls)
			{
				// If the client is attempting to access insecurely, show
				// default welcome page with info.
				resp.SetHeader("Content-Type", "text/html");
				if ("/".Equals(req.Path))
				{
					string httpsUrl = prms.HttpsUrl;
					StringBuilder optBuilder = new StringBuilder();
					if (prms.LogManagement)
						optBuilder.Append("<li><a href=\"" + httpsUrl + "/logs\">Log Management</a></li>");

					resp.SetHeader("Expires", new DateTime(1990, 1, 1).ToString("r"));
					resp.SetHeader("Pragma", "no-cache");
					resp.SetHeader("Cache-Control", "no-store, must-revalidate");
					resp.SetDecodedBodyAndLength(Encoding.Default.GetBytes(
						string.Format(
						    Resources.WELCOME_PAGE,
							httpsUrl,
							optBuilder.ToString()
						)
					));
				}
				else // Redirect to root
				{
					resp.Status = 301;
					resp.SetHeader("Content-Length", "0");
					resp.SetHeader("Location", "/");
				}
			}
			else if (prms.Authenticate && !req.BasicAuthenticated(prms.Username, prms.Password))
			{
				resp.Status = 401;
				resp.SetHeader("Content-Type", "text/html");
				resp.SetHeader("WWW-Authenticate", "Basic realm=\"Access to admin pages\"");
				resp.SetDecodedBodyAndLength(Encoding.Default.GetBytes(Resources.AUTH_PAGE));
			}
			// From here on, the client is authenticated to access configuration and plugin pages
			else if (httpsHandlers.TryGetValue(req.SubPath(0), out Action<HttpRequest, HttpResponse> shandler))
			{
				shandler(req, resp);
			}
			else
			{
				resp = prms.MitM.HomePage(req);
			}
			return resp;
		}
	}
}
