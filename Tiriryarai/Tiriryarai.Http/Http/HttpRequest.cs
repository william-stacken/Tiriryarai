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
using System.Text;
using System.Collections.Generic;

namespace Tiriryarai.Http
{
	/// <summary>
	/// HTTP request methods.
	/// </summary>
	public enum Method
	{
		GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE, CONNECT
	}

	/// <summary>
	/// A class representing an HTTP request.
	/// </summary>
	public class HttpRequest : HttpMessage
	{
		public Method Method { get; set; }
		public string Uri { get; set; }

		public string RequestLine
		{
			get
			{
				return Method + " " + Uri + " HTTP/1.1\r\n";
			}
		}

		/// <summary>
		/// Gets the path in the URI relative to the hostname.
		/// <example>
		/// http://example.org/path/to/something?a=b becomes /path/to/something
		/// </example>
		/// </summary>
		/// <value>The path.</value>
		public string Path
		{
			get
			{
				int i = Uri.IndexOf('?');
				string path = i < 0 ? Uri : Uri.Substring(0, i);
				i = path.IndexOf("://", StringComparison.Ordinal);
				path = i < 0 ? path : path.Substring(i + 3);
				i = path.IndexOf('/');
				return i > 0 ? path.Substring(i) : path;
			}
		}

		/// <summary>
		/// Gets a subpath in the URI relative to the hostname with the given level.
		/// </summary>
		/// <example>
		/// http://example.org/path/to/something?a=b with level 0 becomes path
		/// http://example.org/path/to/something?a=b with level 2 becomes something
		/// http://example.org/path/to/something?a=b with level 3 becomes <c>string.Empty</c>
		/// http://example.org/path/to/something?a=b with level 5 becomes <c>null</c>
		/// </example>
		/// <returns>The path.</returns>
		/// <param name="level">Level.</param>
		public string SubPath(int level)
		{
			string[] pathParts;
			string path = Path;

			// Append slash if not present
			if (path[path.Length - 1] != '/')
				path += '/';

			// Remove first slash
			if (path[0] == '/')
				path = path.Substring(1, path.Length - 1);

			pathParts = path.Split('/');
			if (level < pathParts.Length)
			{
				return pathParts[level];
			}
			return null;
		}

		/// <summary>
		/// Gets the host the request is or was destined to.
		/// </summary>
		/// <value>The host.</value>
		public string Host
		{
			get
			{
				return GetHeader("Host")[0];
			}
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Http.HttpRequest"/> class.
		/// </summary>
		/// <param name="method">The HTTP method of the request.</param>
		/// <param name="uri">The URI of the request.</param>
		/// <param name="headers">A list of HTTP headers.</param>
		/// <param name="body">The entity body of the request.</param>
		public HttpRequest(Method method, string uri, List<KeyValuePair<string, string[]>> headers, byte[] body) : base(headers, body)
		{
			Method = method;
			Uri = uri ?? throw new ArgumentNullException(nameof(uri));
		}

		/// <summary>
		/// Gets a query parameter from the URI.
		/// </summary>
		/// <returns>The value of the parameter if it exists; otherwise, <c>null</c>.</returns>
		/// <param name="param">The parameter to retrieve.</param>
		public string GetQueryParam(string param)
		{
			int i = Uri.IndexOf('?');
			if (i >= 0)
			{
				string query = Uri.Substring(i + 1);
				return ParseUrlEncoded(query).TryGetValue(param.ToLower(), out string value) ?
					value : null;
			}
			return null;
		}

		/// <summary>
		/// Creates an <see cref="T:Tiriryarai.Http.HttpRequest"/> instance from a stream.
		/// </summary>
		/// <returns>A new instance.</returns>
		/// <param name="stream">The stream to read the <see cref="T:Tiriryarai.Http.HttpRequest"/> from.</param>
		public static new HttpRequest FromStream(Stream stream)
		{
			return FromStream(stream, true);
		}

		/// <summary>
		/// Creates an <see cref="T:Tiriryarai.Http.HttpRequest"/> instance from a stream.
		/// </summary>
		/// <returns>A new instance.</returns>
		/// <param name="stream">The stream to read the <see cref="T:Tiriryarai.Http.HttpRequest"/> from.</param>
		/// <param name="hasBody">If set to <c>false</c>, the request is assumed to not have a body.</param>
		public static new HttpRequest FromStream(Stream stream, bool hasBody)
		{
			ReqLineFromStream(stream, out Method method, out string uri);
			HttpMessage http = HttpMessage.FromStream(stream, hasBody);
			return new HttpRequest(method, uri, http.Headers, http.Body);
		}

		/// <summary>
		/// Creates an <see cref="T:Tiriryarai.Http.HttpRequest"/> instance from a stream.
		/// The body to the HTTP request is decoded appropriately and written to another stream.
		/// </summary>
		/// <returns>A new instance.</returns>
		/// <param name="stream">The stream to read the <see cref="T:Tiriryarai.Http.HttpRequest"/> from.</param>
		/// <param name="body">The stream to write the decoded HTTP body of the request to.</param>
		public static new HttpRequest FromStream(Stream stream, Stream body)
		{
			ReqLineFromStream(stream, out Method method, out string uri);
			HttpMessage http = HttpMessage.FromStream(stream, body);
			return new HttpRequest(method, uri, http.Headers, http.Body);
		}

		/// <summary>
		/// Writes an <see cref="T:Tiriryarai.Http.HttpRequest"/> instance to a stream.
		/// </summary>
		/// <param name="stream">The stream to write the <see cref="T:Tiriryarai.Http.HttpRequest"/> to.</param>
		public override void ToStream(Stream stream)
		{
			byte[] enc = Encoding.Default.GetBytes(RequestLine);
			stream.Write(enc, 0, enc.Length);
			base.ToStream(stream);
		}

		/// <summary>
		/// Writes an <see cref="T:Tiriryarai.Http.HttpRequest"/> instance to a stream.
		/// </summary>
		/// <param name="stream">The stream to write the <see cref="T:Tiriryarai.Http.HttpRequest"/> to.</param>
		/// <param name="body">The stream to copy the HTTP body from.</param>
		public override void ToStream(Stream stream, Stream body)
		{
			byte[] enc = Encoding.Default.GetBytes(RequestLine);
			stream.Write(enc, 0, enc.Length);
			base.ToStream(stream, body);
		}

		/// <summary>
		/// Creates an <see cref="T:Tiriryarai.Http.HttpRequest"/> instance from a string.
		/// </summary>
		/// <returns>A new instance.</returns>
		/// <param name="s">The string to parse the <see cref="T:Tiriryarai.Http.HttpRequest"/> from.</param>
		public static HttpRequest FromString(string s)
		{
			return FromStream(Streamify(s));
		}

		/// <summary>
		/// Returns a <see cref="T:System.String"/> that represents the current <see cref="T:Tiriryarai.Http.HttpRequest"/>.
		/// The entity body is ignored.
		/// </summary>
		/// <returns>A <see cref="T:System.String"/> that represents the current <see cref="T:Tiriryarai.Http.HttpRequest"/>.</returns>
		public override string ToString()
		{
			return RequestLine + base.ToString();
		}

		private static void ReqLineFromStream(Stream stream, out Method method, out string uri)
		{
			string reqLine = ReadLine(stream);
			if (reqLine == null)
				throw new IOException("Unexpected EOF");

			string[] reqLineParts = reqLine.Split(' ');
			if (reqLineParts.Length < 3)
				throw new Exception("Bad Request Line: " + reqLine);

			if (!Enum.TryParse(reqLineParts[0], false, out method))
				throw new Exception("Bad Request Line: " + reqLine);
			uri = reqLineParts[1];
			if (!reqLineParts[2].Split('/')[0].Equals("HTTP"))
				throw new Exception("Bad Request Line: " + reqLine);
		}
	}
}
