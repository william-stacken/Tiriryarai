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
using System.Web;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Globalization;
using System.Collections.Generic;

using BrotliSharpLib;

namespace Tiriryarai.Http
{
	/// <summary>
	/// An enumerable representing values for the Content-Encoding header
	/// </summary>
	public enum ContentEncoding
	{
		None = 0,
		GZip,
		Br,
		Deflate,
		UNKNOWN
	}

	/// <summary>
	/// A class representing a generic HTTP message with only headers and
	/// the entity body.
	/// </summary>
	public class HttpMessage
	{
		public List<KeyValuePair<string, string[]>> Headers { get; }

		public byte[] Body { get; set; }

		/// <summary>
		/// Gets or sets the entity body without chunk encoding. Will chunk
		/// encode or decode the body according to the <code>Transfer-Encoding</code> header
		/// </summary>
		/// <value>The chunk decoded body.</value>
		public byte[] ChunkDecodedBody
		{
			get
			{
				return Chunked ? ReadChunked(new MemoryStream(Body), false) : Body;
			}

			set
			{
				if (value == null)
					throw new ArgumentNullException(nameof(value));

				if (Chunked)
				{
					using (MemoryStream ms = new MemoryStream())
					{
						using (HttpChunkStream chunkStream = new HttpChunkStream(ms, ChunkMode.WriteEncoded))
						{
							chunkStream.Write(value, 0, value.Length);
							chunkStream.FlushFinal();
						}
						Body = ms.ToArray();
					}
				}
				else
				{
					Body = value;
				}

			}
		}

		/// <summary>
		/// Gets or sets the entity body without any encoding. Will encode or decode the body
		/// according to the <code>Content-Encoding</code> and <code>Transfer-Encoding</code> headers
		/// </summary>
		/// <value>The content decoded body.</value>
		public byte[] DecodedBody
		{
			get
			{
				Stream encStream;
				byte[] chunkDecoded = ChunkDecodedBody;
				switch (ContentEncoding)
				{
					case ContentEncoding.None:
						return chunkDecoded;
					case ContentEncoding.GZip:
						encStream = new GZipStream(new MemoryStream(chunkDecoded), CompressionMode.Decompress);
						break;
					case ContentEncoding.Br:
						encStream = new BrotliStream(new MemoryStream(chunkDecoded), CompressionMode.Decompress);
						break;
					case ContentEncoding.Deflate:
						encStream = new DeflateStream(new MemoryStream(chunkDecoded), CompressionMode.Decompress);
						break;
					default:
						throw new NotSupportedException("Cannot decode body, message has an unknown encoding.");
					
				}
				using (MemoryStream ms = new MemoryStream())
				{
					encStream.CopyTo(ms);
					return ms.ToArray();
				}
			}

			set
			{
				if (value == null)
					throw new ArgumentNullException(nameof(value));

				Stream encStream;
				using (MemoryStream ms = new MemoryStream())
				{
					switch (ContentEncoding)
					{
						case ContentEncoding.None:
							ChunkDecodedBody = value;
							return;
						case ContentEncoding.GZip:
							encStream = new GZipStream(ms, CompressionMode.Compress);
							break;
						case ContentEncoding.Br:
							encStream = new BrotliStream(ms, CompressionMode.Compress);
							break;
						case ContentEncoding.Deflate:
							encStream = new DeflateStream(ms, CompressionMode.Compress);
							break;
						default:
							throw new NotSupportedException("Cannot encode body, message has an unknown encoding.");
					}
					encStream.Write(value, 0, value.Length);
					encStream.Flush();
					encStream.Close();
					ChunkDecodedBody = ms.ToArray();
				}
			}
		}

		/// <summary>
		/// Gets or sets the value of the <code>Content-Length</code> header. <c>null</c> means
		/// no header or remove the header.
		/// </summary>
		/// <value>The value of the <code>Content-Length</code> header.</value>
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

			set
			{
				string key = "Content-Length";
				if (value != null)
				{
					SetHeader(key, "" + value);
				}
				else
				{
					RemoveHeader(key);
				}
			}
		}

		public string ContentTypeWithoutCharset
		{
			get
			{
				string type = GetHeader("Content-Type")?[0];
				return type != null ? type.Split(';')[0].ToLower() : null;
			}
		}

		/// <summary>
		/// Gets or sets the value of the <code>Content-Encoding</code> header.
		/// </summary>
		/// <value>The enumeration of the <code>Content-Encoding</code> header.</value>
		public ContentEncoding ContentEncoding
		{
			get
			{
				string[] enc = GetHeader("Content-Encoding");
				if (enc != null && enc.Length > 0 && enc[0] != null)
				{
					if (Enum.TryParse(enc[0].Trim(), true, out ContentEncoding contentEncoding))
					{
						return contentEncoding;
					}
					return ContentEncoding.UNKNOWN;
				}
				return ContentEncoding.None;
			}

			set
			{
				string key = "Content-Encoding";
				switch (value)
				{
					case ContentEncoding.GZip:
					case ContentEncoding.Br:
					case ContentEncoding.Deflate:
						SetHeader(key, value.ToString().ToLower());
						break;
					default:
						RemoveHeader(key);
						break;
				}
			}
		}

		/// <summary>
		/// Gets or sets the values of the <code>Accept-Encoding</code> header.
		/// </summary>
		/// <value>The enumerations of the <code>Accept-Encoding</code> header.</value>
		public ContentEncoding[] AcceptEncoding
		{
			get
			{
				List<ContentEncoding> list = new List<ContentEncoding>();

				string[] encs = GetHeader("Accept-Encoding");
				for (int i = 0; i < encs?.Length; i++)
				{
					if (Enum.TryParse(encs[i].Trim(), true, out ContentEncoding result))
					{
						list.Add(result);
					}
				}
				return list.ToArray();
			}

			set
			{
				string key = "Accept-Encoding";
				if (value != null && value.Length > 0)
				{
					string[] encs = new string[value.Length];
					for (int i = 0; i < value.Length; i++)
						encs[i] = value[i].ToString();

					SetHeader(new KeyValuePair<string, string[]>(key, encs));
				}
				else
				{
					RemoveHeader(key);
				}
			}
		}

		/// <summary>
		/// Gets or sets the values of the <code>Allow</code> header.
		/// </summary>
		/// <value>The enumerations of the <code>Allow</code> header.</value>
		public Method[] Allow
		{
			get
			{
				List<Method> list = new List<Method>();

				string[] allw = GetHeader("Allow");
				for (int i = 0; i < allw?.Length; i++)
				{
					if (Enum.TryParse(allw[i].Trim(), true, out Method result))
					{
						list.Add(result);
					}
				}
				return list.ToArray();
			}

			set
			{
				string key = "Allow";
				if (value != null && value.Length > 0)
				{
					string[] allw = new string[value.Length];
					for (int i = 0; i < value.Length; i++)
						allw[i] = value[i].ToString();

					SetHeader(new KeyValuePair<string, string[]>(key, allw));
				}
				else
				{
					RemoveHeader(key);
				}
			}
		}

		/// <summary>
		/// Gets or sets a value indicating whether the entity body of this <see cref="T:Tiriryarai.Http.HttpMessage"/> is chunked.
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
						if (transferEncoding[i].ToLower().Trim().Equals("chunked"))
							return true;
					}
				}
				return false;
			}

			set
			{
				string key = "Transfer-Encoding";
				if (value)
				{
					SetHeader(key, "chunked");
				}
				else
				{
					RemoveHeader(key);
				}
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
		/// <param name="key">The header whose values to retrieve.</param>
		public string[] GetHeader(string key)
		{
			string lower = key.ToLower();
			if (key != null)
			{
				foreach (KeyValuePair<string, string[]> header in Headers)
				{
					if (lower.Equals(header.Key.ToLower()))
						return header.Value;
				}
			}
			return null;
		}

		/// <summary>
		/// Gets the values of the given header as a date-time.
		/// </summary>
		/// <returns>The value of the given header as a date-time.</returns>
		/// <param name="key">The header whose date-time value to retrieve.</param>
		public DateTime? GetDateHeader(string key)
		{
			string[] dt = GetHeader(key);
			if (dt != null && dt.Length > 1)
			{
				if (DateTime.TryParse(string.Join(", ", dt), out DateTime result))
				{
					DateTime.SpecifyKind(result, DateTimeKind.Local);
					return result.ToUniversalTime();
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
			string lower = header.Key.ToLower();
			for (int i = 0; i < Headers.Count; i++)
			{
				if (Headers[i].Key.ToLower().Equals(lower))
				{
					Headers[i] = header;
					return;
				}
			}
			Headers.Add(header);
		}

		/// <summary>
		/// Removes the given header and value if present.
		/// </summary>
		/// <param name="header">The header to remove.</param>
		public void RemoveHeader(string key)
		{
			string lower = key.ToLower();
			for (int i = 0; i < Headers.Count; i++)
			{
				if (Headers[i].Key.ToLower().Equals(lower))
				{
					Headers.RemoveAt(i);
					return;
				}
			}
		}

		/// <summary>
		/// returns a boolean indicating whether the given token is present
		/// in the header value
		/// </summary>
		/// <returns><c>true</c> if the token is present; otherwise, <c>false</c>.</returns>
		/// <param name="key">The header whose token values to check.</param>
		/// <param name="token">The token to check for.</param>
		public bool HeaderContains(string key, string token)
		{
			token = token.Trim().ToLower();
			string[] val = GetHeader(key);
			for (int i = 0; i < val?.Length; i++)
			{
				if (val[i].Trim().ToLower().Equals(token))
					return true;
			}
			return false;
		}

		/// <summary>
		/// Sets the decoded entity body, encodes it according to the headers, and automatically updates or adds
		/// the <code>Content-Length</code> header to the encoded length, but only if the body does not have a
		/// chunked transfer encoding.
		/// </summary>
		/// <param name="body">The new entity body.</param>
		public void SetDecodedBodyAndLength(byte[] body)
		{
			DecodedBody = body;
			if (!Chunked)
				ContentLength = (uint) Body.Length;
		}

		/// <summary>
		/// Checks if the message has HTTP basic authentication in the given header and returns
		/// its username and password. Assumes valid username and password.
		/// </summary>
		/// <returns><c>true</c>, if the username and password was found, <c>false</c> otherwise.</returns>
		/// <param name="header">The header that should contain the basic authentication.</param>
		/// <param name="user">The username in the given header.</param>
		/// <param name="pass">The password in the given header.</param>
		public bool TryGetBasicAuthentication(string header, out string user, out string pass)
		{
			user = null;
			pass = null;

			int colon;
			string[] auth;
			string[] authArr = GetHeader(header);
			if (authArr != null && authArr.Length > 0 && authArr[0] != null)
			{
				auth = authArr[0].Split(' ');
				try
				{
					if (auth != null && auth.Length > 1 && auth[0] != null && "basic".Equals(auth[0].ToLower().Trim()))
					{
						auth[0] = Encoding.UTF8.GetString(Convert.FromBase64String(auth[1]));
						colon = auth[0].IndexOf(':');
						if (colon < 0)
							return false;

						user = auth[0].Substring(0, colon);
						pass = auth[0].Substring(colon + 1, auth[0].Length - colon - 1);
						return true;
					}
				}
				catch { /* Authentication was not valid */ }
			}
			return false;
		}

		/// <summary>
		/// Treats the entity body as a form-encoded string and retrives the URL decoded
		/// value of a given parameter.
		/// </summary>
		/// <returns>The value of the parameter if it exists; otherwise, <c>null</c>.</returns>
		/// <param name="param">The parameter to retrieve.</param>
		public string GetBodyParam(string param)
		{
			return ExtractUrlEncodedParam(Encoding.Default.GetString(DecodedBody), param);
		}

		protected string ExtractUrlEncodedParam(string urlEncoded, string param)
		{
			int i;
			string lower = param.ToLower();
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
					key = keyVal.Substring(0, i).ToLower();
					val = keyVal.Substring(i + 1);
				}
				else
				{
					key = keyVal.ToLower();
					val = "";
				}
				if (key.Equals(lower))
				{
					return HttpUtility.UrlDecode(val);
				}
			}
			return null;
		}

		/// <summary>
		/// Sets the content encoding by picking one of the encodings in the provided
		/// <see cref="T:Tiriryarai.Http.HttpMessage"/>'s <code>Accept-Encoding</code> header.
		/// The encoding is picked using the given dictionary contining content encodings and
		/// a list of priority values.
		/// </summary>
		/// <param name="http">The <see cref="T:Tiriryarai.Http.HttpMessage"/> whose
		/// <code>Accept-Encoding</code> header to select a content encoding from.</param>
		/// <param name="encodings">A dictionary of content encodings mapped to priority values.
		/// Higher values means higher priority.</param>
		public void PickEncoding(HttpMessage http, Dictionary<ContentEncoding, int> encodings)
		{
			ContentEncoding enc = ContentEncoding.None;
			int currPrio = int.MinValue;

			ContentEncoding[] accepted = http.AcceptEncoding;
			for (int i = 0; i < accepted?.Length; i++)
			{
				if (encodings.TryGetValue(accepted[i], out int prio) && prio > currPrio)
				{
					currPrio = prio;
					enc = accepted[i];
				}
			}
			ContentEncoding = enc;
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

			for (string line = ReadLine(stream); !string.IsNullOrEmpty(line); line = ReadLine(stream))
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
			byte[] enc = Encoding.Default.GetBytes(RawHeaders);

			stream.Write(enc, 0, enc.Length);
			stream.Write(Body, 0, Body.Length);
			stream.Flush();
		}

		/// <summary>
		/// Returns a <see cref="T:System.String"/> that represents the current <see cref="T:Tiriryarai.Http.HttpMessage"/>.
		/// </summary>
		/// <returns>A <see cref="T:System.String"/> that represents the current <see cref="T:Tiriryarai.Http.HttpMessage"/>.</returns>
		public override string ToString()
		{
			return RawHeaders + Encoding.Default.GetString(DecodedBody);
		}

		/// <summary>
		/// Returns a string representation of the HTTP headers.
		/// </summary>
		/// <returns>The string representation of the HTTP headers.</returns>
		public string RawHeaders
		{
			get
			{
				StringBuilder builder = new StringBuilder();
				foreach (KeyValuePair<string, string[]> header in Headers)
				{
					builder.Append(header.Key + ": " + string.Join(", ", header.Value) + "\r\n");
				}
				builder.Append("\r\n");
				return builder.ToString();
			}
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
			return ReadLine(stream, 8192);
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

		// TODO: This should be moved to <see cref="T:Tiriryarai.Http.HttpChunkStream"/>
		// along with a mode optionally keep the encoding of the stream intact
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
