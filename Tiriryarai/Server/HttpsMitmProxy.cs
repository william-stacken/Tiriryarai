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
using System.Text;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading;
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

		private readonly string logDir;
		private ConcurrentDictionary<string, byte> logMutex;

		private HttpsMitmProxyCache cache;

        private IManInTheMiddle mitm;

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Server.HttpsMitmProxy"/> class.
		/// Does not start the server.
		/// </summary>
		/// <param name="ip">The IP address the server will listen on.</param>
		/// <param name="port">The port the server will listen on.</param>
		/// <param name="configDir">A directory where certificates, server configuration, and log files will be stored.</param>
		/// <param name="mitm">A man-in-the-middle handler that will receive incomming requests and outgoing responses
		/// to tamper with them.</param>
		public HttpsMitmProxy(IPAddress ip, ushort port, string configDir, IManInTheMiddle mitm)
        {
			logDir = Path.Combine(configDir, "logs");
			Directory.CreateDirectory(logDir);
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
			logMutex = new ConcurrentDictionary<string, byte>();

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
		}

		private void Cert(HttpRequest req, HttpResponse resp)
		{
			resp.SetHeader("Content-Type", "application/octet-stream");
			resp.SetHeader("Content-Disposition", "attachment; filename=Tiriryarai.der");
			resp.SetBodyAndLength(cache.GetRootCA().GetRawCertData());
		}

		private void CaIssuer(HttpRequest req, HttpResponse resp)
		{
			Console.WriteLine("\n----------------------------\n" + req);
			resp.SetHeader("Content-Type", "application/pkix-cert");
			resp.SetBodyAndLength(cache.GetRootCA().GetRawCertData());
			Log(req.Host, "OUTGOING INTERNAL RESPONSE", resp);
		}

		private void OCSP(HttpRequest req, HttpResponse resp)
		{
			Console.WriteLine("\n----------------------------\n" + req);

			X509OCSPResponse ocspResp = cache.GetOCSPResponse(req);
			resp.SetHeader("Content-Type", "application/ocsp-response");
			resp.SetBodyAndLength(ocspResp.RawData);
			Log(req.Host, "OUTGOING INTERNAL RESPONSE", resp);
		}

		private void CRL(HttpRequest req, HttpResponse resp)
		{
			Console.WriteLine("\n----------------------------\n" + req);

			X509Crl crl = cache.GetCrl();
			resp.SetHeader("Content-Type", "application/pkix-crl");
			resp.SetHeader("Expires", crl.ThisUpdate.ToString("r"));
			resp.SetHeader("Last-Modified", crl.NextUpdate.ToString("r"));
			resp.SetBodyAndLength(crl.RawData);
			Log(req.Host, "OUTGOING INTERNAL RESPONSE", resp);
		}

		/// <summary>
		/// Start the server and listens to incomming requests.
		/// </summary>
		public void Start()
        {
            TcpListener listener = new TcpListener(ip, port);
            listener.Start();
            Console.WriteLine("Listening for connections on https://*:" + port + "/");
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
                    if (!mitm.Block(host))
                    {
                        resp = new HttpResponse(200, null, null, "Connection Established");
                        resp.ToStream(stream);

                        X509Certificate2 cert = cache.GetCertificate(host);

                        SslStream sslStream = new SslStream(stream, false);
                        sslStream.AuthenticateAsServer(cert);

                        req = HttpRequest.FromStream(sslStream);
                        Log(req.Host, "INCOMMING REQUEST", req);

                        if (!IsDestinedToMitm(req))
                        {
                            Console.WriteLine("\n--------------------\n" + req.Method + " https://" + req.Host + req.Uri);

                            http = mitm.HandleRequest(req);
                            if (http is HttpRequest modified)
                            {
                                //Log(req.Host, "MODIFIED REQUEST", modified);
                                resp = new HttpsClient(req.Host).Send(modified);
                                resp = mitm.HandleResponse(resp, req);
                            }
                            else if (http is HttpResponse intercepted)
                            {
                                //Log(req.Host, "CUSTOM RESPONSE", intercepted);
                                resp = intercepted;
                            }
                            else
                            {
                                throw new Exception("Invalid message type");
                            }
                            Log(req.Host, "OUTGOING RESPONSE", resp);
                            resp.ToStream(sslStream);

                            sslStream.Close();
                            client.Close();
                            return;
                        }
                    }
                    else
                    {
                        resp = new HttpResponse(502);
                        resp.ToStream(stream);
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
                // TODO Need an appropriate method for how and when to log exceptions
                Console.WriteLine(e.Message);
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

		private void Log(string filename, string head, HttpMessage http)
		{
			int attempts = 0;
			while (!logMutex.TryAdd(filename, 0))
			{
				if (++attempts > 5)
				{
					Console.WriteLine("Warning: Request to log HttpMessage timed out.");
					return;
				}
				Thread.Sleep(100);
			}
			try
			{
				using (var s = new FileStream(Path.Combine(logDir, filename + ".log"), FileMode.Append))
				{
					byte[] header = Encoding.UTF8.GetBytes(
						$"################ {head} {DateTime.Now.ToLongTimeString()} {DateTime.Now.ToLongDateString()} ################\n"
					);
					byte[] footer = Encoding.UTF8.GetBytes("\n\n");
					s.Write(header, 0, header.Length);
					http.ToStream(s);
					s.Write(footer, 0, footer.Length);
				}
			}
			finally
			{
				logMutex.TryRemove(filename, out _);
			}
        }
	}
}