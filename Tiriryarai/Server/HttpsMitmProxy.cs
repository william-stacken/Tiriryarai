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
using System.Web;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Collections.Generic;

using System.Threading.Tasks;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.IO;

using Tiriryarai.Crypto;
using Tiriryarai.Http;
using Tiriryarai.Util;

using Mono.Security.X509;

using HttpRequest = Tiriryarai.Http.HttpRequest;
using HttpResponse = Tiriryarai.Http.HttpResponse;

namespace Tiriryarai.Server
{
	/// <summary>
	/// A class acting as an HTTPS proxy that can tamper with incoming requests
	/// and outgoing responses before forwarding them to their destination. To use the
	/// proxy, it's root CA must be installed in the client.
	/// </summary>
	class HttpsMitmProxy
	{
		private TcpListener listener;
		private HttpsMitmProxyParams prms;

		private readonly Dictionary<string, Action<HttpRequest, HttpResponse>> httpHandlers;
		private readonly Dictionary<string, Action<HttpRequest, HttpResponse>> httpsHandlers;
		private readonly HashSet<string> pluginHosts;

		private HttpsMitmProxyCache cache;
		private Logger logger;

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Server.HttpsMitmProxy"/> class.
		/// Does not start the server.
		/// </summary>
		/// <param name="prms">Various parameters and configuration used by the proxy.</param>
		public HttpsMitmProxy(HttpsMitmProxyParams prms)
		{
			if (prms.Hostname.Split(':')[0].ToLower().Equals(Resources.HOSTNAME.ToLower()))
				throw new ArgumentException("The hostname may not be \"" + Resources.HOSTNAME + "\".");

			string host = prms.Hostname;
			Directory.CreateDirectory(prms.ConfigDirectory);
			logger = Logger.GetSingleton();
			logger.Initialize(
			    Path.Combine(prms.ConfigDirectory, "logs"),
				(uint) prms.LogVerbosity,
				(uint) prms.MaxLogSize,
				prms.PassKey);
			prms.MitM.Initialize(prms.ConfigDirectory);
			httpHandlers = new Dictionary<string, Action<HttpRequest, HttpResponse>>
			{
				{"", (req, resp) => {
					if (req.GetDateHeader("If-Modified-Since") != null)
						resp.Status = 304;

					switch (req.Method)
					{
						case Method.HEAD:
						case Method.GET:
							string httpsUrl = prms.HttpsUrl;
							StringBuilder optBuilder = new StringBuilder();
							if (prms.LogManagement)
								optBuilder.Append("<li><a href=\"https://" + Resources.HOSTNAME + "/logs\">Log Management</a></li>");

							DefaultHttpBody(resp, "text/html",
								Encoding.Default.GetBytes(
									string.Format(
										Resources.WELCOME_PAGE,
										httpsUrl,
										optBuilder.ToString()
									)
								), false, req);
							break;
						case Method.OPTIONS:
							DefaultOptions(resp, req);
							break;
						default:
							DefaultUnsupported(resp, req);
							break;
					}
				}},
				{"favicon.ico", (req, resp) => {
					switch (req.Method)
					{
						case Method.HEAD:
						case Method.GET:
							resp.SetHeader("Last-Modified", DateTime.Now.AddYears(-1).ToString("r"));
							resp.SetHeader("Expires", DateTime.Now.AddMonths(1).ToString("r"));
							resp.SetHeader("Cache-Control", "public");
							if (req.GetDateHeader("If-Modified-Since") != null)
								resp.Status = 304;

							DefaultHttpBody(resp, "image/x-icon", Resources.Get("favicon.ico"), false, req);
							break;
						case Method.OPTIONS:
							DefaultOptions(resp, req);
							break;
						default:
							DefaultUnsupported(resp, req);
							break;
					}
					logger.Log(15, req.Host, "OUTGOING INTERNAL RESPONSE", resp);
				}},
				{"cert", (req, resp) => {
					switch (req.Method)
					{
						case Method.HEAD:
						case Method.GET:
							X509Certificate2 root = cache.GetRootCA();
							resp.SetHeader("Last-Modified", root.NotBefore.ToString("r"));
							resp.SetHeader("Expires", root.NotAfter.ToString("r"));
							resp.SetHeader("Cache-Control", "public");
							resp.SetHeader("Content-Disposition", "attachment; filename=Tiriryarai.der");
							if (req.GetDateHeader("If-Modified-Since") != null)
								resp.Status = 304;

							DefaultHttpBody(resp, "application/octet-stream", root.GetRawCertData(), false, req);
							break;
						case Method.OPTIONS:
							DefaultOptions(resp, req);
							break;
						default:
							DefaultUnsupported(resp, req);
							break;
					}
					logger.Log(15, req.Host, "OUTGOING INTERNAL RESPONSE", resp);
				}},
				{Resources.CA_ISSUER_PATH, (req, resp) =>
				{
					logger.Log(8, req.Host, "INCOMMING ISSUER REQUEST", req);
					switch (req.Method)
					{
						case Method.HEAD:
						case Method.GET:
							X509Certificate2 root = cache.GetRootCA();
							resp.SetHeader("Last-Modified", root.NotBefore.ToString("r"));
							resp.SetHeader("Expires", root.NotAfter.ToString("r"));
							resp.SetHeader("Cache-Control", "public");
							if (req.GetDateHeader("If-Modified-Since") != null)
								resp.Status = 304;

							DefaultHttpBody(resp, "application/pkix-cert", root.GetRawCertData(), false, req);
							break;
						case Method.OPTIONS:
							DefaultOptions(resp, req);
							break;
						default:
							DefaultUnsupported(resp, req);
							break;
					}
					logger.Log(15, req.Host, "OUTGOING ISSUER RESPONSE", resp);
				}},
				{Resources.OCSP_PATH, (req, resp) =>
				{
					logger.Log(8, req.Host, "INCOMMING OCSP REQUEST", req);
					switch (req.Method)
					{
						case Method.HEAD:
						case Method.GET:
						case Method.POST:
							X509OCSPRequest ocspReq = null;
							try
							{
								// Fetch the OCSP request from the URI as base64 if the content type isn't an
								// OCSP request.
								byte[] rawOcspReq = "application/ocsp-request".Equals(req.GetHeader("Content-Type")?[0]) ?
									req.Body : Convert.FromBase64String(HttpUtility.UrlDecode(req.SubPath(1)));
								ocspReq = new X509OCSPRequest(rawOcspReq);
							}
							catch (Exception e)
							{
								logger.LogException(e, req);
							}
							X509OCSPResponse ocspResp = ocspReq != null ?
							    cache.GetOCSPResponse(ocspReq) :
							    new X509OCSPResponse(
								    new X509OCSPResponse(X509OCSPResponse.ResponseStatus.MalformedRequest).Sign(cache.GetOCSPCA())
							    );
							DateTime expiry = ocspResp.ExpiryDate;
							resp.SetHeader("Expires", expiry.ToString("r"));
							if (req.GetDateHeader("If-Modified-Since")?.CompareTo(expiry) < 0)
								resp.Status = 304;

							DefaultHttpBody(resp, "application/ocsp-response", ocspResp.RawData, false, req);
							break;
						case Method.OPTIONS:
							DefaultOptions(resp, req, Method.POST);
							break;
						default:
							DefaultUnsupported(resp, req);
							break;
					}
					logger.Log(15, req.Host, "OUTGOING OCSP RESPONSE", resp);
				}},
				{Resources.CRL_PATH, (req, resp) =>
				{
					logger.Log(8, req.Host, "INCOMMING CRL REQUEST", req);
					switch (req.Method)
					{
						case Method.HEAD:
						case Method.GET:
							X509Crl crl = cache.GetCrl();
							resp.SetHeader("Expires", crl.NextUpdate.ToString("r"));
							resp.SetHeader("Last-Modified", crl.ThisUpdate.ToString("r"));
							if (req.GetDateHeader("If-Modified-Since")?.CompareTo(crl.NextUpdate) < 0)
								resp.Status = 304;

							DefaultHttpBody(resp, "application/pkix-crl", crl.RawData, false, req);
							break;
						case Method.OPTIONS:
							DefaultOptions(resp, req);
							break;
						default:
							DefaultUnsupported(resp, req);
							break;
					}
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
							// Request to log directory
							switch (req.Method)
							{
								case Method.HEAD:
								case Method.GET:
									DateTime lastWrite = logger.LastWriteTimeDirectory;
									resp.SetHeader("Last-Modified", lastWrite.ToString("r"));
									if (ifModified?.CompareTo(lastWrite) < 0)
										resp.Status = 304;

									StringBuilder entryBuilder = new StringBuilder();
									foreach (string log in logger.LogNames)
									{
										entryBuilder.Append(string.Format(
											Resources.LOG_ENTRY,
											log,
											string.Format("{0:0.00}", (double)logger.LogSize(log) / 1024) + " kiB",
											logger.LastWriteTime(log).ToString("r")
										));
									}
									DefaultHttpBody(resp, "text/html", Encoding.Default.GetBytes(
										string.Format(Resources.LOG_PAGE, entryBuilder)
									), false, req);
									return;
								case Method.OPTIONS:
									DefaultOptions(resp, req);
									return;
								default:
									DefaultUnsupported(resp, req);
									return;
							}
						}
						else if (logger.Exists(logFile) && "".Equals(req.SubPath(2))) // Only one path level allowed
						{
							switch (req.Method)
							{
								case Method.HEAD:
								case Method.GET:
									DateTime lastWrite = logger.LastWriteTime(logFile);
									resp.SetHeader("Last-Modified", lastWrite.ToString("r"));
									if (ifModified?.CompareTo(lastWrite) < 0)
										resp.Status = 304;

									try
									{
										DefaultHttpBody(resp, "text/html", logger.ReadLog(logFile), true, req);
									}
									catch (IOException)
									{
										DefaultInternalError(resp, req, Resources.LOG_ERR_MSG);
									}
									return;
								case Method.POST:
									if ("application/x-www-form-urlencoded".Equals(req.ContentTypeWithoutCharset) &&
										"Delete".Equals(req.GetBodyParam("submit")))
									{
										logger.DeleteLog(logFile);
									}
									break;
								case Method.DELETE:
									logger.DeleteLog(logFile);
									break;
								case Method.OPTIONS:
									DefaultOptions(resp, req, Method.POST, Method.DELETE);
									return;
								default:
									DefaultUnsupported(resp, req);
									return;
							}
							resp.Status = 303;
							resp.SetHeader("Location", "/logs");
							resp.ContentLength = 0;
							return;
						}
					}
					resp.Status = 404;
					DefaultHttpBody(resp, "text/html", Encoding.Default.GetBytes(Resources.NON_PAGE), false, req);
				}}
			};
			X509CertificateUrls urls = new X509CertificateUrls(
				"http://" + Resources.HOSTNAME + "/" + Resources.CA_ISSUER_PATH,
				"http://" + Resources.HOSTNAME + "/" + Resources.OCSP_PATH,
				"http://" + Resources.HOSTNAME + "/" + Resources.CRL_PATH
			);
			cache = new HttpsMitmProxyCache(
			    new string[] { Resources.HOSTNAME, prms.Hostname },
				prms.ConfigDirectory, 500, 60000, urls
			);
			pluginHosts = new HashSet<string>
			{
				prms.Hostname,
				prms.IP.ToString(),
				"localhost",
				"127.0.0.1"
			};

			this.prms = prms;

			listener = new TcpListener(IPAddress.Any, prms.Port);
			listener.Start();
		}

		/// <summary>
		/// Start the server and listens to incomming requests.
		/// </summary>
		public void Start()
		{
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
			string host, hostWithPort;
			string user = null;
			string pass = null;
			HttpsClient destination = null;
			bool toTiriryarai = false;
			bool keepAlive = false;
			X509Certificate2 cert = null;
			NetworkStream stream = client.GetStream();
			IPAddress clientIp = (client.Client.RemoteEndPoint as IPEndPoint)?.Address;
			try
			{
				if (clientIp == null)
					throw new NullReferenceException(nameof(clientIp));

				if (cache.GetIPStatistics(clientIp).IsBanned(prms.AllowedLoginAttempts))
				{
					resp = DefaultHttpResponse(403);
					resp.ToStream(stream);
					client.Close();
					return;
				}

				if (prms.ReadTimeout > 0)
					stream.ReadTimeout = prms.ReadTimeout;

				do // while connection keep-alive
				{
					try
					{
						if (keepAlive)
							stream.ReadTimeout = 1000; // TODO Add this to params

						req = HttpRequest.FromStream(stream);

						hostWithPort = req.Host;
						host = hostWithPort.Split(':')[0];
						if (Uri.CheckHostName(host) == UriHostNameType.Unknown)
							throw new Exception("Invalid hostname: " + hostWithPort);
					}
					catch (Exception e)
					{
						if (e is IOException ||
						    e is ObjectDisposedException ||
							e.InnerException is IOException)
						{
							// Connection has become inactive or was closed by the remote
							keepAlive = false;
							break;
						}
						resp = DefaultHttpResponse(400);
						resp.ToStream(stream);
						throw e;
					}
					toTiriryarai = IsTiriryarai(host);

					if (req.Method == Method.CONNECT)
					{
						if (prms.ProxyAuthenticate &&
							!toTiriryarai &&
							(!req.TryGetBasicAuthentication("Proxy-Authorization", out user, out pass) ||
							!prms.IsProxyAuthenticated(user, pass)))
						{
							// Don't count login attempts here as it would be really easy to get banned by mistake otherwise
							resp = DefaultHttpResponse(407, req);
							resp.ToStream(stream);
							client.Close();
							return;
						}
						try
						{
							cert = cache.GetCertificate(host);
						}
						catch (Exception e)
						{
							resp = DefaultHttpResponse(500, req);
							resp.ToStream(stream);
							throw e;
						}
						destination = new HttpsClient(hostWithPort, prms.ReadTimeout, true, prms.IgnoreCertificates);

						resp = new HttpResponse(200, null, null, "Connection Established");
						resp.ToStream(stream);
						SslStream sslStream = new SslStream(stream);
						try
						{
							sslStream.AuthenticateAsServer(cert);
							do
							{
								try
								{
									if (keepAlive)
										stream.ReadTimeout = 1000; // TODO Add this to params

									req = HttpRequest.FromStream(sslStream);

									resp = toTiriryarai ?
									    HomePage(req, host, clientIp, tls: true) :
									    HandleRequest(req, destination, tls: true);
								}
								catch (Exception e)
								{
									if (e is IOException ||
									    e is ObjectDisposedException ||
									    e.InnerException is IOException)
									{
										// Connection has become inactive or was closed by the remote
										keepAlive = false;
										break;
									}
									logger.LogException(e);
									resp = DefaultHttpResponse(400);
								}
								resp.ToStream(sslStream);
								sslStream.Flush();
								keepAlive = !req.HeaderContains("Connection", "closed") && !resp.HeaderContains("Connection", "closed");
							} while (keepAlive);
						}
						catch (Exception e)
						{
							logger.LogException(e);
						}
						finally
						{
							// Close destination in case it wasn't closed already
							destination.Close();
							sslStream.Close();
						}
					}
					else
					{
						// If a non-CONNECT request is received, it will be proxied directly
						if (prms.ProxyAuthenticate &&
							!toTiriryarai &&
							(!req.TryGetBasicAuthentication("Proxy-Authorization", out user, out pass) ||
							!prms.IsProxyAuthenticated(user, pass)))
						{
							// Don't count login attempts here as it would be really easy to get banned by mistake otherwise
							resp = DefaultHttpResponse(407, req);
						}
						else
						{
							destination = new HttpsClient(hostWithPort, prms.ReadTimeout, false, prms.IgnoreCertificates);
							resp = toTiriryarai ?
								HomePage(req, host, clientIp, tls: false) :
								HandleRequest(req, destination, tls: false);
							// Always close the destination connection. Further plain text HTTP requests
							// may be destined to another host. This could cause some confusion if the
							// destination wanted to keep the connection alive however.
							destination.Close();
							keepAlive = !req.HeaderContains("Connection", "closed") && !resp.HeaderContains("Connection", "closed");
						}
						resp.ToStream(stream);
					}
				}
				while (keepAlive);
			}
			catch (Exception e)
			{
				logger.LogException(e);
			}
			finally
			{
				client.Close();
			}
		}

		private HttpResponse HandleRequest(HttpRequest req, HttpsClient destination, bool tls)
		{
			HttpResponse resp = null;
			HttpMessage http;
			try
			{
				Console.WriteLine("\n--------------------\n" +
							req.Method + (tls ? " https://" : " http://") + destination.HostnameWithPort + req.Path);
				if (!prms.MitM.Block(destination.Hostname))
				{
					logger.Log(3, destination.Hostname, "RECEIVED REQUEST", req);

					http = prms.MitM.HandleRequest(req);
					if (http is HttpRequest modified)
					{
						logger.Log(12, destination.Hostname, "MODIFIED REQUEST", modified);

						try
						{
							resp = destination.Send(modified);
						}
						catch (Exception e)
						{
							destination.Close();
							if (e is IOException || e is SocketException)
								return DefaultHttpResponse(504);

							logger.LogException(e);
							return DefaultHttpResponse(502);
						}
						if (modified.HeaderContains("Connection", "close") || resp.HeaderContains("Connection", "close"))
							destination.Close();

						logger.Log(3, destination.Hostname, "RECEIVED RESPONSE", resp);

						resp = prms.MitM.HandleResponse(resp, req);
						logger.Log(12, destination.Hostname, "MODIFIED RESPONSE", resp);
					}
					else if (http is HttpResponse intercepted)
					{
						logger.Log(3, destination.Hostname, "CUSTOM RESPONSE", intercepted);
						resp = intercepted;
					}
					else // Should never be reached
					{
						throw new Exception("Invalid message type");
					}
				}
				else // Host is blocked, send gateway timeout
				{
					logger.Log(3, destination.Hostname, "BLOCKED REQUEST", req);
					resp = DefaultHttpResponse(504, req);
				}
			}
			catch (Exception e)
			{
				logger.LogException(e);
				resp = DefaultHttpResponse(500, req);
			}
			return resp;
		}

		private bool IsTiriryarai(string host)
		{
			// TODO: This may not be an exhaustive list, if there is another
			// loopback IP, there is a risk of an infinite loop where the proxy
			// sends requests to itself
			return host.Equals(Resources.HOSTNAME) ||
				   pluginHosts.Contains(host);
		}

		private HttpResponse HomePage(HttpRequest req, string host, IPAddress client, bool tls)
		{
			HttpResponse resp;
			string user = null;
			string pass = null;
			try
			{
				if (pluginHosts.Contains(host))
				{
					if (!tls)
					{
						// If the client is attempting to access insecurely, redirect to
						// HTTPS page.
						resp = DefaultHttpResponse(301, req);
						resp.SetHeader("Location", prms.HttpsUrl + req.Path);
					}
					else if (prms.Authenticate &&
					         (!req.TryGetBasicAuthentication("Authorization", out user, out pass) ||
					         !prms.IsAuthenticated(user, pass)))
					{
						cache.GetIPStatistics(client).LoginAttempt();
						resp = DefaultHttpResponse(401, req);
					}
					// From here on, the client is authenticated to access the plugin page
					else
					{
						resp = prms.MitM.HomePage(req);
					}
				}
				else // Let Tiriryarai handle request
				{
					string rootPath = req.SubPath(0);
					if (req.Method == Method.TRACE)
					{
						resp = DefaultHttpResponse(200, req);
						DefaultHttpBody(resp, "message/http", Encoding.Default.GetBytes(
							req.RequestLine + req.RawHeaders
						), false, req);
					}
					else if (req.Method == Method.OPTIONS && "*".Equals(rootPath))
					{
						resp = DefaultHttpResponse(204, req);
						DefaultOptions(resp, req, Method.POST, Method.DELETE, Method.CONNECT);
					}
					else if (httpHandlers.TryGetValue(rootPath, out Action<HttpRequest, HttpResponse> handler))
					{
						resp = DefaultHttpResponse(200, req);
						handler(req, resp);
					}
					else if (!tls)
					{
						// If the client is attempting to access insecurely, redirect to
						// HTTPS version of page.
						resp = DefaultHttpResponse(301, req);
					}
					// From here on, only HTTPS is allowed
					else if (prms.Authenticate &&
							 (!req.TryGetBasicAuthentication("Authorization", out user, out pass) ||
							 !prms.IsAuthenticated(user, pass)))
					{
						cache.GetIPStatistics(client).LoginAttempt();
						resp = DefaultHttpResponse(401, req);
					}
					// From here on, the client is authenticated to access configuration pages
					else if (httpsHandlers.TryGetValue(rootPath, out Action<HttpRequest, HttpResponse> shandler))
					{
						resp = DefaultHttpResponse(200, req);
						shandler(req, resp);
					}
					else
					{
						resp = DefaultHttpResponse(404, req);
					}
				}
			}
			catch (Exception e)
			{
				logger.LogException(e);
				resp = DefaultHttpResponse(500, req);
			}
			return resp;
		}

		private HttpResponse DefaultHttpResponse(int status)
		{
			return DefaultHttpResponse(status, null);
		}

		private HttpResponse DefaultHttpResponse(int status, HttpRequest req)
		{
			string body = null;
			HttpResponse resp = new HttpResponse(status);
			resp.SetHeader("Server", "Tiriryarai/" + Resources.Version);
			resp.SetHeader("Date", DateTime.Now.ToString("r"));
			if (req != null && !req.HeaderContains("Connection", "close"))
				resp.SetHeader("Connection", "keep-alive");
			else
				resp.SetHeader("Connection", "close");
			switch (status)
			{
				case 301:
					resp.SetHeader("Location", "https://" + Resources.HOSTNAME + req?.Path);
					body = "";
					break;
				case 400:
					body = Resources.BAD_PAGE;
					break;
				case 401:
					resp.SetHeader("WWW-Authenticate",
						"Basic realm=\"Access to admin pages. This is sent securely over HTTPS.\"");
					body = Resources.AUTH_PAGE;
					break;
				case 403:
					body = Resources.FORBIDDEN_PAGE;
					break;
				case 404:
					body = Resources.NON_PAGE;
					break;
				case 407:
					resp.SetHeader("Proxy-Authenticate",
					    "Basic realm=\"Use of the proxy server. This is sent insecurely over HTTP.\"");
					body = Resources.PROXY_PAGE;
					break;
				case 408:
					body = Resources.TIMEOUT_PAGE;
					break;
				case 500:
					body = string.Format(Resources.ERR_PAGE, Resources.GENERIC_ERR_MSG);
					break;
				case 502:
					body = Resources.GATE_PAGE;
					break;
				case 504:
					body = Resources.GATE_TIMEOUT_PAGE;
					break;
				default:
					// Non standardized HTTP body
					return resp;
			}
			DefaultHttpBody(resp, "text/html", Encoding.Default.GetBytes(body), false, req);
			return resp;
		}

		private void DefaultHttpBody(HttpResponse resp, string contentType, byte[] body, bool chunked, HttpRequest req)
		{
			resp.SetHeader("Content-Type", contentType);
			if (req != null && body.Length > 500)
			{
				// Don't encode if the body is trivially small
				resp.PickEncoding(req, new Dictionary<ContentEncoding, int> {
					{ContentEncoding.Br, 3},
					{ContentEncoding.GZip, 2},
					{ContentEncoding.Deflate, 1}
				});
				resp.SetHeader("Vary", "Accept-Encoding");
			}
			resp.Chunked = chunked;
			resp.SetDecodedBodyAndLength(body);
			if ((req != null && req.Method == Method.HEAD) || resp.Status == 204 || resp.Status == 304)
			{
				resp.Body = new byte[0];
			}
		}

		private void DefaultOptions(HttpResponse resp, HttpRequest req)
		{
			DefaultOptions(resp, req, null);
		}

		private void DefaultOptions(HttpResponse resp, HttpRequest req, params Method[] extras)
		{
			List<Method> list = new List<Method> {
				Method.GET,
				Method.HEAD,
				Method.OPTIONS,
				Method.TRACE
			};
			if (extras != null)
			{
				list.AddRange(extras);
			}

			resp.Status = 204;
			resp.Allow = list.ToArray();
		}

		private void DefaultUnsupported(HttpResponse resp, HttpRequest req)
		{
			resp.Status = 405;
			DefaultHttpBody(resp, "text/html", Encoding.Default.GetBytes(Resources.METHOD_PAGE), false, req);
		}

		private void DefaultInternalError(HttpResponse resp, HttpRequest req, string msg)
		{
			resp.Status = 500;
			DefaultHttpBody(resp, "text/html", Encoding.Default.GetBytes(
				string.Format(Resources.ERR_PAGE, msg)
			), false, req);
		}
	}
}
