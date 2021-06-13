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
using System.Collections.Generic;

namespace Tiriryarai.Http
{

	/// <summary>
	/// A class representing an HTTP response.
	/// </summary>
	public class HttpResponse : HttpMessage
	{
		protected static readonly string[][] statusMsg = {
			new string[] {
				"Continue", "Switching Protocols", "Processing",
				"Early Hints"
			},
			new string[] {
				"OK", "Created", "Accepted",
				"Non-Authoritative Information", "No Content", "Reset Content",
				"Partial Content", "Multi-Status", "Already Reported",
				null, null, null,
				null, null, null,
				null, null, null,
				null, null, null,
				null, null, null,
				null, null, "IM Used"
			},
			new string[] {
				"Multiple Choices", "Moved Permanently", "Found",
				"See Other", "Not Modified", "Use Proxy",
				"Switch Proxy", "Temporary Redirect", "Permanent Redirect"
			},
			new string[] {
				"Bad Request", "Unauthorized", "Payment Required",
				"Forbidden", "Not Found", "Method Not Allowed",
				"Not Acceptable", "Proxy Authentication Required", "Request Timeout",
				"Conflict", "Gone", "Length Required",
				"Precondition Failed", "Payload Too Large", "URI Too Long",
				"Unsupported Media Type", "Range Not Satisfiable", "Expectation Failed",
				"I'm a teapot", null, null,
				"Misdirected Request", "Unprocessable Entity", "Locked",
				"Failed Dependency", "Too Early", "Upgrade Required",
				null, "Precondition Required", "Too Many Requests",
				null, "Request Header Fields Too Large", null,
				null, null, null,
				null, null, null,
				null, null, null,
				null, null, null,
				null, null, null,
				null, null, null,
				"Unavailable For Legal Reasons"
			},
			new string[] {
				"Internal Server Error", "Not Implemented", "Bad Gateway",
				"Service Unavailable", "Gateway Timeout", "HTTP Version Not Supported",
				"Variant Also Negotiates", "Insufficient Storage", "Loop Detected",
				null, "Not Extended", "Network Authentication Required"
			}
		};

		public int Status { get; set; }
		public string StatusMessage { get; set; }

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Http.HttpResponse"/> class.
		/// </summary>
		/// <param name="status">The status of the response.</param>
		public HttpResponse(int status) : this(status, null, null, null) { }

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Http.HttpResponse"/> class.
		/// </summary>
		/// <param name="status">The status of the response.</param>
		/// <param name="headers">A list of HTTP headers.</param>
		/// <param name="body">The entity body of the response.</param>
		public HttpResponse(int status, List<KeyValuePair<string, string[]>> headers, byte[] body) : this(status, headers, body, null) { }

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Http.HttpResponse"/> class.
		/// </summary>
		/// <param name="status">The status of the response.</param>
		/// <param name="headers">A list of HTTP headers.</param>
		/// <param name="body">The entity body of the response.</param>
		/// <param name="statusMessage">A custom status message to use instead of the default for the given status.</param>
		public HttpResponse(int status, List<KeyValuePair<string, string[]>> headers, byte[] body, string statusMessage) : base(headers, body)
		{
			int type = status / 100 - 1;
			int id = status % 100;
			if (type < 0 || type >= statusMsg.Length)
				throw new ArgumentException("Bad status");
			if (id >= statusMsg[type].Length || statusMsg[type][id] == null)
				throw new ArgumentException("Bad status");
			Status = status;
			StatusMessage = statusMessage;
		}

		/// <summary>
		/// Creates an <see cref="T:Tiriryarai.Http.HttpResponse"/> instance from a stream.
		/// </summary>
		/// <returns>A new instance.</returns>
		/// <param name="stream">The stream to read the <see cref="T:Tiriryarai.Http.HttpResponse"/> from.</param>
		public static new HttpResponse FromStream(Stream stream)
		{
			return FromStream(stream, true);
		}

		/// <summary>
		/// Creates an <see cref="T:Tiriryarai.Http.HttpResponse"/> instance from a stream.
		/// </summary>
		/// <returns>A new instance.</returns>
		/// <param name="stream">The stream to read the <see cref="T:Tiriryarai.Http.HttpResponse"/> from.</param>
		/// <param name="hasBody">If set to <c>false</c>, the response is assumed to not have a body.</param>
		private static new HttpResponse FromStream(Stream stream, bool hasBody)
		{
			HttpMessage http;
			string respLine = ReadLine(stream);
			if (respLine == null)
				throw new Exception("Unexpected EOF");

			string[] respLineParts = respLine.Split(' ');
			if (respLineParts.Length < 3)
				throw new Exception("Bad Response Line");

			if (!respLineParts[0].Split('/')[0].Equals("HTTP"))
				throw new Exception("Bad Response Line");
			if (!int.TryParse(respLineParts[1], out int status))
				throw new Exception("Bad Response Line");

			http = HttpMessage.FromStream(stream, hasBody && status >= 200 && status != 204 && status != 304);
			return new HttpResponse(status, http.Headers, http.Body);
		}

		/// <summary>
		/// Creates an <see cref="T:Tiriryarai.Http.HttpResponse"/> instance from a string.
		/// </summary>
		/// <returns>A new instance.</returns>
		/// <param name="s">The string to parse the <see cref="T:Tiriryarai.Http.HttpResponse"/> from.</param>
		public static HttpResponse FromString(string s)
		{
			return FromStream(Streamify(s));
		}

		/// <summary>
		/// Returns a <see cref="T:System.String"/> that represents the current <see cref="T:Tiriryarai.Http.HttpResponse"/>.
		/// The entity body is ignored.
		/// </summary>
		/// <returns>A <see cref="T:System.String"/> that represents the current <see cref="T:Tiriryarai.Http.HttpResponse"/>.</returns>
		public override string ToString()
		{
			return "HTTP/1.1 " + Status + " " + (StatusMessage ?? statusMsg[Status / 100 - 1][Status % 100]) + "\r\n" + base.ToString();
		}
	}
}
