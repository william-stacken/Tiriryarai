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
using System.ComponentModel;
using System.Reflection;
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
		private HttpsMitmProxyConfig conf;

		private readonly Dictionary<string, Action<HttpRequest, HttpResponse>> httpHandlers;
		private readonly Dictionary<string, Action<HttpRequest, HttpResponse>> httpsHandlers;
		private readonly HashSet<string> pluginHosts;

		private HttpsMitmProxyCache cache;
		private Logger logger;

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Server.HttpsMitmProxy"/> class.
		/// Does not start the server.
		/// </summary>
		/// <param name="conf">Various parameters and configuration used by the proxy.</param>
		public HttpsMitmProxy(HttpsMitmProxyConfig conf)
		{
			string host = conf.Hostname;
			Directory.CreateDirectory(conf.ConfigDirectory);
			logger = Logger.GetSingleton();

			httpHandlers = new Dictionary<string, Action<HttpRequest, HttpResponse>>
			{
				{"", (req, resp) => {
					if (req.GetDateHeader("If-Modified-Since")?.CompareTo(conf.OptionLastModifiedTime) < 0)
						resp.Status = 304;

					switch (req.Method)
					{
						case Method.HEAD:
						case Method.GET:
							string httpsUrl = conf.HttpsUrl;
							StringBuilder optBuilder = new StringBuilder();
							if (conf.LogManagement)
								optBuilder.Append("<li><a href=\"https://" + Resources.HOSTNAME + "/logs\">Log Management</a></li>");
							if (conf.Configuration)
								optBuilder.Append("<li><a href=\"https://" + Resources.HOSTNAME + "/config\">Configuration</a></li>");

							resp.SetHeader("Last-Modified", conf.OptionLastModifiedTime.ToString("r"));
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
					if (!string.Empty.Equals(req.SubPath(1)))
					{
						DefaultNotFound(resp, req);
						return;
					}
					switch (req.Method)
					{
						case Method.HEAD:
						case Method.GET:
							resp.SetHeader("Last-Modified", conf.StartTime.ToString("r"));
							resp.SetHeader("Expires", DateTime.UtcNow.AddMonths(1).ToString("r"));
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
					if (!string.Empty.Equals(req.SubPath(1)))
					{
						DefaultNotFound(resp, req);
						return;
					}
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
					if (!string.Empty.Equals(req.SubPath(1)))
					{
						DefaultNotFound(resp, req);
						return;
					}
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
					if (!string.Empty.Equals(req.SubPath(1)))
					{
						DefaultNotFound(resp, req);
						return;
					}
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
								logger.LogDebug(10, e);
								logger.LogDebug(10, req);
							}
							X509OCSPResponse ocspResp = ocspReq != null ?
							    cache.GetOCSPResponse(ocspReq) :
							    new X509OCSPResponse(
								    new X509OCSPResponse(X509OCSPResponse.ResponseStatus.MalformedRequest).Sign(cache.GetOCSPCA())
							    );
							DateTime? expiry = ocspResp.ExpiryDate;
							DateTime? update = ocspResp.UpdateDate;
							resp.SetHeader("Expires", (expiry ?? DateTime.UtcNow).ToString("r"));
							resp.SetHeader("Last-Modified", (update ?? DateTime.UtcNow).ToString("r"));
							if (req.GetDateHeader("If-Modified-Since")?.CompareTo(update) < 0)
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
					if (!string.Empty.Equals(req.SubPath(1)))
					{
						DefaultNotFound(resp, req);
						return;
					}
					logger.Log(8, req.Host, "INCOMMING CRL REQUEST", req);
					switch (req.Method)
					{
						case Method.HEAD:
						case Method.GET:
							X509Crl crl = cache.GetCrl();
							resp.SetHeader("Expires", crl.NextUpdate.ToString("r"));
							resp.SetHeader("Last-Modified", crl.ThisUpdate.ToString("r"));
							if (req.GetDateHeader("If-Modified-Since")?.CompareTo(crl.ThisUpdate) < 0)
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
					if (conf.LogManagement)
					{
						logger.Log(8, req.Host, "INCOMMING LOG REQUEST", req);
						DateTime? ifModified = req.GetDateHeader("If-Modified-Since");
						string logFile = req.SubPath(1);

						if (string.Empty.Equals(logFile))
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
								case Method.POST:
									if (!"application/x-www-form-urlencoded".Equals(req.ContentTypeWithoutCharset))
									{
										DefaultBadMediaType(resp, req);
										return;
									}
									else if ("on".Equals(req.GetBodyParam("sure")) && "Delete All".Equals(req.GetBodyParam("deleteall")))
									{
										foreach (string log in logger.LogNames)
											logger.DeleteLog(log);
									}
									break;
								case Method.DELETE:
									foreach (string log in logger.LogNames)
										logger.DeleteLog(log);
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
						else if (logger.Exists(logFile) && string.Empty.Equals(req.SubPath(2))) // Only one path level allowed
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
									catch (Exception e)
									{
										if (e is IOException)
											DefaultInternalError(resp, req, Resources.LOG_ERR_MSG);
										else
											throw e;
									}
									return;
								case Method.POST:
									if (!"application/x-www-form-urlencoded".Equals(req.ContentTypeWithoutCharset))
									{
										DefaultBadMediaType(resp, req);
										return;
									}
									else if ("Delete".Equals(req.GetBodyParam("submit")))
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
					DefaultNotFound(resp, req);
				}},
				{"config", (req, resp) => {
					if (conf.Configuration && string.Empty.Equals(req.SubPath(1)))
					{
						logger.Log(8, req.Host, "INCOMMING CONFIG REQUEST", req);
						string value, description;
						HttpsMitmProxyProperty type;
						bool success = true;
						switch (req.Method)
						{
							case Method.HEAD:
							case Method.GET:
								DateTime lastUpdate = conf.LastModifiedTime;
								resp.SetHeader("Last-Modified", lastUpdate.ToString("r"));
								if (req.GetDateHeader("If-Modified-Since")?.CompareTo(lastUpdate) < 0)
									resp.Status = 304;

								StringBuilder configTable = new StringBuilder();
								foreach (var p in conf.GetType().GetProperties())
								{
									if (p.GetCustomAttribute(typeof(HttpsMitmProxyAttribute), false) is HttpsMitmProxyAttribute attr &&
										(type = attr.Type) != HttpsMitmProxyProperty.None &&
										(conf.ChangeAuthentication || ((type & HttpsMitmProxyProperty.Authentication) == 0)) &&
										(conf.LogManagement || ((type & HttpsMitmProxyProperty.Log) == 0)))
									{
										description = (p.GetCustomAttribute(typeof(DescriptionAttribute), false)
											as DescriptionAttribute)?.Description;

										if (p.GetGetMethod() == null)
											value = string.Empty;
										else if (p.PropertyType.Equals(typeof(bool)) &&
											"checkbox".Equals(attr.HtmlInputType))
											value = (p.GetValue(conf) is bool b) && b ? "checked" : "";
										else
											value = "value=\"" + p.GetValue(conf) + "\"";

										if ((type & HttpsMitmProxyProperty.Static) != 0)
											value += " readonly";

										configTable.Append(string.Format(
											Resources.CONFIG_ENTRY,
											p.Name.ToLower(),
											p.Name,
											attr.HtmlInputType ?? "text",
											value,
											description ?? "(no description)"
										));
									}
								}
								if ((value = req.GetQueryParam("success")) != null)
								{
									description = "y".Equals(value) ?
										"<p style=\"color:#00FF00\";>Configuration successfully saved!</p>" :
										"<p style=\"color:#FF0000\";>Configuration contained invalid values and was not saved!</p>";
								}
								else
								{
									description = string.Empty;
								}
								DefaultHttpBody(resp, "text/html", Encoding.Default.GetBytes(
									string.Format(Resources.CONFIG_PAGE, description, configTable)
								), false, req);
								return;
							case Method.POST:
								bool clearCache = false;
								if (!"application/x-www-form-urlencoded".Equals(req.ContentTypeWithoutCharset))
								{
									DefaultBadMediaType(resp, req);
									return;
								}
								try
								{
									clearCache = conf.SetProperties(req.BodyParams, init: false);
								}
								catch (Exception e)
								{
									logger.LogDebug(5, e);
									success = false;
								}
								if (clearCache)
								{
									Task.Run(() => {
										conf.Maintenance = true;
										cache.Clear();
										conf.Maintenance = false;
									});
									DefaultUnavailable(resp, req, Resources.CACHE_CLEAR_MSG);
									return;
								}
								break;
							case Method.OPTIONS:
								DefaultOptions(resp, req, Method.POST);
								return;
							default:
								DefaultUnsupported(resp, req);
								return;
						}
						resp.Status = 303;
						resp.SetHeader("Location", "/config?success=" + (success ? "y" : "n"));
						resp.ContentLength = 0;
						return;
					}
					DefaultNotFound(resp, req);
				}}
			};
			cache = HttpsMitmProxyCache.GetSingleton();
			pluginHosts = new HashSet<string>
			{
				conf.Hostname,
				conf.IP.ToString(),
				"localhost",
				"127.0.0.1"
			};

			this.conf = conf;

			listener = new TcpListener(IPAddress.Any, conf.Port);
			listener.Start();
		}

		/// <summary>
		/// Starts the server and listens to incomming requests.
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

				if (cache.GetIPStatistics(clientIp).IsBanned(conf.AllowedLoginAttempts))
				{
					resp = DefaultHttpResponse(403);
					resp.ToStream(stream);
					client.Close();
					return;
				}
				else if (conf.Maintenance)
				{
					resp = DefaultHttpResponse(503);
					resp.ToStream(stream);
					client.Close();
					return;
				}

				if (conf.ReadTimeout > 0)
					stream.ReadTimeout = conf.ReadTimeout;

				do // while connection keep-alive
				{
					try
					{
						if (keepAlive)
							stream.ReadTimeout = conf.KeepAliveTimeout;

						req = HttpRequest.FromStream(stream);

						hostWithPort = req.Host;
						host = hostWithPort.Split(':')[0];
						if (Uri.CheckHostName(host) == UriHostNameType.Unknown)
							throw new Exception("Invalid hostname: " + hostWithPort);
					}
					catch (Exception e)
					{
						resp = DefaultHttpResponse(400);
						resp.ToStream(stream);
						throw e;
					}
					toTiriryarai = IsTiriryarai(host);
					if (!toTiriryarai && conf.MitM.Block(host))
					{
						resp = DefaultHttpResponse(403);
						resp.ToStream(stream);
						client.Close();
						return;
					}

					if (req.Method == Method.CONNECT)
					{
						if (conf.ProxyAuthenticate &&
							!toTiriryarai &&
							(!req.TryGetBasicAuthentication("Proxy-Authorization", out user, out pass) ||
							!conf.IsProxyAuthenticated(user, pass)))
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
						destination = new HttpsClient(hostWithPort, conf.ReadTimeout, true, conf.IgnoreCertificates);

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
										stream.ReadTimeout = conf.KeepAliveTimeout;

									req = HttpRequest.FromStream(sslStream);

									resp = toTiriryarai ?
									    HomePage(req, host, clientIp, tls: true) :
									    HandleRequest(req, destination, tls: true);
								}
								catch (Exception e)
								{
									if (e is IOException ||
										e is SocketException ||
									    e is ObjectDisposedException ||
									    e.InnerException is IOException ||
										e is AggregateException)
									{
										// Connection has become inactive or was closed by the remote
										logger.LogDebug(12, e);
										keepAlive = false;
										break;
									}
									logger.LogDebug(8, e);
									resp = DefaultHttpResponse(400);
								}
								resp.ToStream(sslStream);
								sslStream.Flush();
								keepAlive = !req.HeaderContains("Connection", "closed") && !resp.HeaderContains("Connection", "closed");
							} while (keepAlive);
						}
						catch (Exception e)
						{
							logger.LogDebug(13, e);
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
						if (conf.ProxyAuthenticate &&
							!toTiriryarai &&
							(!req.TryGetBasicAuthentication("Proxy-Authorization", out user, out pass) ||
							!conf.IsProxyAuthenticated(user, pass)))
						{
							// Don't count login attempts here as it would be really easy to get banned by mistake otherwise
							resp = DefaultHttpResponse(407, req);
						}
						else
						{
							destination = new HttpsClient(hostWithPort, conf.ReadTimeout, false, conf.IgnoreCertificates);
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
				if (e is IOException ||
					e is SocketException ||
					e is ObjectDisposedException ||
					e.InnerException is IOException)
				{
					// Connection was probably closed by the remote
					logger.LogDebug(15, e);
				}
				else
				{
					logger.LogDebug(8, e);
				}
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
				logger.WriteStdout("\n--------------------\n" +
					req.Method + (tls ? " https://" : " http://") + destination.HostnameWithPort);
				if (!conf.MitM.Block(destination.Hostname))
				{
					logger.Log(3, destination.Hostname, "RECEIVED REQUEST", req);

					http = conf.MitM.HandleRequest(req);
					if (http is HttpRequest modified)
					{
						logger.Log(12, destination.Hostname, "MODIFIED REQUEST", modified);

						try
						{
							if (conf.CacheResponseTime > 0)
							{
								resp = cache.GetHttpResponse(modified, r =>
									destination.Send(r as HttpRequest), DateTime.Now.AddMilliseconds(conf.CacheResponseTime));
							}
							else
							{
								resp = destination.Send(modified);
							}
						}
						catch (Exception e)
						{
							destination.Close();
							if (e is IOException || e is SocketException)
								return DefaultHttpResponse(504);

							logger.LogDebug(6, e);
							return DefaultHttpResponse(502);
						}
						if (modified.HeaderContains("Connection", "close") || resp.HeaderContains("Connection", "close"))
							destination.Close();

						logger.Log(3, destination.Hostname, "RECEIVED RESPONSE", resp);

						resp = conf.MitM.HandleResponse(resp, req);
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
				logger.LogDebug(2, e);
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
						resp.SetHeader("Location", conf.HttpsUrl + req.Path);
					}
					else if (conf.Authenticate &&
					         (!req.TryGetBasicAuthentication("Authorization", out user, out pass) ||
					         !conf.IsAuthenticated(user, pass)))
					{
						cache.GetIPStatistics(client).LoginAttempt();
						resp = DefaultHttpResponse(401, req);
					}
					// From here on, the client is authenticated to access the plugin page
					else
					{
						cache.GetIPStatistics(client).ResetLoginAttempts();
						resp = conf.MitM.HomePage(req);
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
					else if (conf.Authenticate &&
							 (!req.TryGetBasicAuthentication("Authorization", out user, out pass) ||
							 !conf.IsAuthenticated(user, pass)))
					{
						cache.GetIPStatistics(client).LoginAttempt();
						resp = DefaultHttpResponse(401, req);
					}
					// From here on, the client is authenticated to access configuration pages
					else
					{
						cache.GetIPStatistics(client).ResetLoginAttempts();
						if (httpsHandlers.TryGetValue(rootPath, out Action<HttpRequest, HttpResponse> shandler))
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
			}
			catch (Exception e)
			{
				logger.LogDebug(2, e);
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
			resp.SetHeader("Date", DateTime.UtcNow.ToString("r"));
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
				case 503:
					body = string.Format(Resources.DOWN_PAGE, Resources.CACHE_CLEAR_MSG);
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

		private void DefaultNotFound(HttpResponse resp, HttpRequest req)
		{
			resp.Status = 404;
			DefaultHttpBody(resp, "text/html", Encoding.Default.GetBytes(Resources.NON_PAGE), false, req);
		}

		private void DefaultUnsupported(HttpResponse resp, HttpRequest req)
		{
			resp.Status = 405;
			DefaultHttpBody(resp, "text/html", Encoding.Default.GetBytes(Resources.METHOD_PAGE), false, req);
		}

		private void DefaultBadMediaType(HttpResponse resp, HttpRequest req)
		{
			resp.Status = 415;
			DefaultHttpBody(resp, "text/html", Encoding.Default.GetBytes(Resources.MEDIA_PAGE), false, req);
		}

		private void DefaultInternalError(HttpResponse resp, HttpRequest req, string msg)
		{
			resp.Status = 500;
			DefaultHttpBody(resp, "text/html", Encoding.Default.GetBytes(
				string.Format(Resources.ERR_PAGE, msg)
			), false, req);
		}

		private void DefaultUnavailable(HttpResponse resp, HttpRequest req, string msg)
		{
			resp.Status = 503;
			DefaultHttpBody(resp, "text/html", Encoding.Default.GetBytes(
				string.Format(Resources.DOWN_PAGE, msg)
			), false, req);
		}
	}
}
