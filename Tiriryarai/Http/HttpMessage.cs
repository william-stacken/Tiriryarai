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
using System.Globalization;
using System.Collections.Generic;

namespace Tiriryarai.Http
{
	/// <summary>
	/// A class representing a generic HTTP message with only headers and
	/// the entity body.
	/// </summary>
	public class HttpMessage
	{
		public List<KeyValuePair<string, string[]>> Headers { get; }

		public byte[] Body { get; set; }

		/// <summary>
		/// Gets the entity body without chunk encoding.
		/// </summary>
		/// <value>The chunk decoded body.</value>
		public byte[] ChunkDecodedBody
		{
			get
			{
				return Chunked ? ReadChunked(new MemoryStream(Body), false) : Body;
			}
		}

		/// <summary>
		/// Gets the value of the <code>Content-Length</code> header if present; otherwise, <c>null</c>.
		/// </summary>
		/// <value>The value of the <code>Content-Length</code> header if present.</value>
		public uint? ContentLength
		{
			get
			{
				string[] len = GetHeader("Content-Length");
				if (len != null && len.Length > 0 && uint.TryParse(len[0], out uint contentLength))
				{
					return contentLength;
				}
				return null;
			}
		}

		/// <summary>
		/// Gets a value indicating whether the entity body of this <see cref="T:Tiriryarai.Http.HttpMessage"/> is chunked.
		/// </summary>
		/// <value><c>true</c> if chunked; otherwise, <c>false</c>.</value>
		public bool Chunked
		{
			get
			{
				string[] transferEncoding = GetHeader("Transfer-Encoding");
				if (transferEncoding != null)
				{
					for (int i = 0; i < transferEncoding.Length; i++)
					{
						if (transferEncoding[i].ToLower().Equals("chunked"))
							return true;
					}
				}
				return false;
			}
		}

		protected HttpMessage(List<KeyValuePair<string, string[]>> headers): this(headers, new byte[0]) { }

		protected HttpMessage(List<KeyValuePair<string, string[]>> headers, byte[] body)
		{
			if (headers == null)
				headers = new List<KeyValuePair<string, string[]>>();
			if (body == null)
				body = new byte[0];
			Headers = headers;
			Body = body;
		}

		/// <summary>
		/// Gets the values of the given header.
		/// </summary>
		/// <returns>The values of the given header.</returns>
		/// <param name="key">The header whose values to retreive.</param>
		public string[] GetHeader(string key)
		{
			if (key != null)
			{
				foreach (KeyValuePair<string, string[]> header in Headers)
				{
					if (key.Equals(header.Key))
						return header.Value;
				}
			}
			return null;
		}

		/// <summary>
		/// Adds the given header and value if not present; otherwise, replaces the existing headers value.
		/// </summary>
		/// <param name="key">The header to set.</param>
		/// <param name="val">The header's value.</param>
		public void SetHeader(string key, string val)
		{
			SetHeader(new KeyValuePair<string, string[]>(key, new string[] { val }));
		}

		/// <summary>
		/// Adds the given header and value if not present; otherwise, replaces the existing headers value.
		/// </summary>
		/// <param name="header">The header and value to set.</param>
		public void SetHeader(KeyValuePair<string, string[]> header)
		{
			for (int i = 0; i < Headers.Count; i++)
			{
				if (Headers[i].Key.Equals(header.Key))
				{
					Headers[i] = header;
					return;
				}
			}
			Headers.Add(header);
		}

		/// <summary>
		/// Sets the entity body and automatically updates or adds the <code>Content-Length</code>
		/// header accordingly.
		/// </summary>
		/// <param name="body">The new entity body.</param>
		public void SetBodyAndLength(byte[] body)
		{
			SetHeader("Content-Length", "" + body.Length);
			Body = body;
		}

		/// <summary>
		/// Checks if the message has HTTP basic authentication matching the
		/// given username and password. Assumes valid username and password.
		/// </summary>
		/// <returns><c>true</c>, if authenticated, <c>false</c> otherwise.</returns>
		/// <param name="user">The given username.</param>
		/// <param name="pass">The given password.</param>
		public bool BasicAuthenticated(string user, string pass)
		{
			string[] auth;
			string[] authArr = GetHeader("Authorization");
			if (authArr != null && authArr.Length > 0)
			{
				auth = authArr[0].Split(' ');
				if (auth != null && auth.Length > 1 && "Basic".Equals(auth[0]))
				{
					return Convert.ToBase64String(
						Encoding.Default.GetBytes(user + ":" + pass)
					).Equals(auth[1]);
				}
			}
			return false;
		}

		/// <summary>
		/// Treats the entity body as form-encoded a string and retrives the value of a given parameter.
		/// </summary>
		/// <returns>The value of the parameter if it exists; otherwise, <c>null</c>.</returns>
		/// <param name="param">The parameter to retrieve.</param>
		public string GetBodyParam(string param)
		{
			return ExtractUrlEncodedParam(Encoding.Default.GetString(Body), param);
		}

		protected string ExtractUrlEncodedParam(string urlEncoded, string param)
		{
			int i;
			string[] keyVals = urlEncoded.Split('&');
			foreach (string keyVal in keyVals)
			{
				if (string.IsNullOrWhiteSpace(keyVal))
					continue;
				string key;
				string val;
				i = keyVal.IndexOf('=');
				if (i >= 0)
				{
					key = keyVal.Substring(0, i);
					val = keyVal.Substring(i + 1);
				}
				else
				{
					key = keyVal;
					val = "";
				}
				if (key.Equals(param))
				{
					return val;
				}
			}
			return null;
		}

		protected static HttpMessage FromStream(Stream stream)
		{
			return FromStream(stream, true);
		}

		protected static HttpMessage FromStream(Stream stream, bool hasBody)
		{
			HttpMessage http;
			List<KeyValuePair<string, string[]>> headers = new List<KeyValuePair<string, string[]>>();
			string[] keyVal;
			string[] vals;

			for (string line = ReadLine(stream); line != null && !"".Equals(line); line = ReadLine(stream))
			{
				int split = line.IndexOf(": ", StringComparison.Ordinal);
				if (split < 0)
					throw new Exception("Bad header: " + line);
				keyVal = new string[] {line.Substring(0, split), line.Substring(split + 2)};

				vals = keyVal[1].Split(',');
				for (int i = 0; i < vals.Length; i++)
					vals[i] = vals[i].Trim();
				headers.Add(new KeyValuePair<string, string[]>(keyVal[0], vals));
			}
			http = new HttpMessage(headers);
			return hasBody ? ReadMessageBody(http, stream) : http;
		}

		public virtual void ToStream(Stream stream)
		{
			byte[] enc = Encoding.Default.GetBytes(HeadersToString());

			stream.Write(enc, 0, enc.Length);
			stream.Write(Body, 0, Body.Length);
			stream.Flush();
		}

		public override string ToString()
		{
			//char[] charBody = new char[Body.Length / sizeof(char)];

			//Buffer.BlockCopy(Body, 0, charBody, 0, Body.Length);
			return HeadersToString() + /*new string(charBody)*/ Encoding.Default.GetString(Body);
		}

		protected string HeadersToString()
		{
			StringBuilder builder = new StringBuilder();
			foreach (KeyValuePair<string, string[]> header in Headers)
			{
				builder.Append(header.Key + ": " + string.Join(", ", header.Value) + "\r\n");
			}
			builder.Append("\r\n");
			return builder.ToString();
		}

		protected static Stream Streamify(string s)
		{
			MemoryStream stream = new MemoryStream();
			StreamWriter writer = new StreamWriter(stream);
			writer.Write(s);
			writer.Flush();
			stream.Position = 0;
			return stream;
		}

		protected static string ReadLine(Stream stream)
		{
			return ReadLine(stream, 4096);
		}

		protected static string ReadLine(Stream stream, int maxLen)
		{
			int bytes = 0;
			char[] headBuf = new char[maxLen];
			int b;
			do
			{
				b = stream.ReadByte();
				if (b < 0)
				{
					if (bytes == 0)
						return null;
					break;
				}

				headBuf[bytes] = (char)b;

				if (bytes >= 1)
				{
					if (headBuf[bytes] == '\n' &&
						headBuf[bytes - 1] == '\r')
					{
						return new string(headBuf, 0, bytes - 1);
					}
				}
				bytes++;
			} while (bytes < headBuf.Length);

			throw new Exception("Remote sent an unexpectedly long line: " + new string(headBuf, 0, headBuf.Length));
		}

		private static HttpMessage ReadMessageBody(HttpMessage http, Stream stream)
		{
			byte[] bytes = new byte[0];
			uint? contentLength;

			if (http.Chunked)
			{
				bytes = ReadChunked(stream, true);
			}
			else
			{
				contentLength = http.ContentLength;
				if (contentLength != null)
				{
					bytes = ReadBytes(stream, (uint)contentLength);
				}
			}
			http.Body = bytes;
			return http;
		}

		private static byte[] ReadChunked(Stream stream, bool keepEncoding)
		{
			List<byte> bytesList = new List<byte>(4096);
			string chunkSizeHex;
			uint chunkSize;
			byte[] chunk;
			do
			{
				chunkSizeHex = ReadLine(stream, 24);
				if (!uint.TryParse(chunkSizeHex, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out chunkSize))
					throw new Exception("Remote sent bad chunk size: " + chunkSizeHex);
				if (keepEncoding)
				{
					bytesList.AddRange(Encoding.Default.GetBytes(chunkSizeHex + "\r\n"));
				}
				chunk = ReadBytes(stream, chunkSize);
				bytesList.AddRange(chunk);
				// Assmue trailing CRLF
				stream.ReadByte();
				stream.ReadByte();
				if (keepEncoding)
				{
					bytesList.Add(0xD);
					bytesList.Add(0xA);
				}
			} while (chunkSize > 0 && chunk.Length >= chunkSize);
			return bytesList.ToArray();
		}

		private static byte[] ReadBytes(Stream stream, uint len)
		{
			if (stream == null)
				return new byte[0];
			if (len > (1 << 30))
				throw new Exception("The server tried to send way too much data.");
			int i;
			int b;
			byte[] bytes = new byte[len];
			for (i = 0; i < len && (b = stream.ReadByte()) >= 0; i++)
			{
				bytes[i] = (byte)b;
			}

			if (i < len)
			{
				Array.Resize(ref bytes, i);
			}
			return bytes;
		}

		private static byte[] ReadAllBytes(Stream stream)
		{
			// Read until the server closes the connection
			if (stream == null)
				return new byte[0];
			List<byte> bytesList = new List<byte>(4096);
			byte[] bytes;
			long b;
			while ((b = stream.ReadByte()) >= 0)
			{
				bytesList.Add((byte)b);
			}
			bytes = bytesList.ToArray();

			return bytes;
		}
	}
}
