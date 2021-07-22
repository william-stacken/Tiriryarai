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

using System.Text;
using System.Text.RegularExpressions;

using Tiriryarai.Http;
using Tiriryarai.Server;
using Tiriryarai.Util;

namespace TiriryaraiMitm
{
	public class MiddleMan : IManInTheMiddle
	{
		private bool intercept;
		private Logger logger;

		public MiddleMan()
		{
			intercept = false;
			logger = Logger.GetSingleton();
		}

		public bool Block(string hostname)
		{
			// Block all hostnames containing "hacker"
			return new Regex("^.*hacker.*$").IsMatch(hostname);
		}

		public HttpMessage HandleRequest(HttpRequest req)
		{
			if (intercept)
			{
				// Intercept the request and return a response instead
				HttpResponse resp = new HttpResponse(200);
				resp.SetHeader("Content-Type", "text/html");
				resp.SetBodyAndLength(Encoding.Default.GetBytes(
					"<p>Your request was intercepted and not sent to the host!</p>"
				));
				return resp;
			}

			// Add header if the request was destined to example.org
			if ("example.org".Equals(req.Host))
			{
				req.SetHeader("X-To-Example", "true");
				logger.Log(3, req.Host, "ADDED A HEADER", req);
			}
			return req;
		}

		public HttpResponse HandleResponse(HttpResponse resp, HttpRequest req)
		{
			// Add header if the request was destined to example.org
			if ("example.org".Equals(req.Host))
			{
				resp.SetHeader("X-From-Example", "true");
				logger.Log(3, req.Host, "ADDED A HEADER", resp);
			}
			return resp;
		}

		public HttpResponse HomePage(HttpRequest req)
		{
			// Display a simple web page for downloading the root CA certificate
			// and set a boolean to intercept requests
			string msg = "";
			string path = req.Path;
			string[] contentType = req.GetHeader("Content-Type");
			HttpResponse resp = new HttpResponse(200);
			resp.SetHeader("Content-Type", "text/html");

			if ("/save".Equals(path) && req.Method == Method.POST &&
				contentType.Length > 0 && "application/x-www-form-urlencoded".Equals(contentType[0]))
			{
				intercept = "on".Equals(req.GetBodyParam("intercept"));
				msg = "<p style=\"color:#00FF00\";>Saved!</p>";
			}
			resp.SetBodyAndLength(Encoding.Default.GetBytes(string.Format(
				"<!DOCTYPE html>" +
				"<html>" +
				  "<head>" +
					"<title>Tiriryarai</title>" +
					"<meta charset=\"utf-8\"/>" +
				  "</head>" +
				  "<body>" +
					"<h1>Custom MitM configuration page</h1>" +
					"<form method=\"post\" action=\"/save\">" +
					  "<input type=\"checkbox\" name=\"intercept\" id=\"intercept\" {0}/>" +
					  "<label for=\"intercept\">Intercept</label><br><br>" +
					  "<input type=\"submit\" name=\"submit\" value=\"Save\"/>" +
					"</form>" +
					"{1}" +
				  "</body>" +
				"</html>", intercept ? "checked" : "", msg)
			));
			return resp;
		}
	}
}
