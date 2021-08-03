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
using System.IO.Compression;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Concurrent;

using System.Security.Cryptography;

using Tiriryarai.Http;

namespace Tiriryarai.Util
{
	/// <summary>
	/// Class that logs objects to logs with dynamically given filenames.
	/// </summary>
	public class Logger
	{
		internal class LogEntry
		{
			public byte[] Raw { get; }

			public LogEntry(string head, object obj)
			{
				Raw = Encoding.Default.GetBytes(
					($"<strong>{head} {DateTime.Now.ToLongDateString()} {DateTime.Now.ToLongTimeString()}</strong>\n" +
						ToLogEntryBody(obj, null, null)).Replace("\n", "\n<br>")
				);
			}

			public LogEntry(string head, HttpRequest req, uint verbosity)
			{
				Raw = Encoding.Default.GetBytes(
					($"<strong>{head} {DateTime.Now.ToLongDateString()} {DateTime.Now.ToLongTimeString()}</strong>\n" +
						req.RequestLine + ToLogEntryBody((HttpMessage)req, verbosity)).Replace("\n", "\n<br>")
				);
			}

			public LogEntry(string head, HttpResponse resp, uint verbosity)
			{
				Raw = Encoding.Default.GetBytes(
					($"<strong>{head} {DateTime.Now.ToLongDateString()} {DateTime.Now.ToLongTimeString()}</strong>\n" +
						resp.ResponseLine + ToLogEntryBody((HttpMessage)resp, verbosity)).Replace("\n", "\n<br>")
				);
			}

			private string ToLogEntryBody(HttpMessage http, uint verbosity)
			{
				StringBuilder builder = new StringBuilder();
				if (verbosity > 3)
					builder.Append(http.RawHeaders);
				if (verbosity > 6)
				{
					byte[] contentDecodedBody = http.DecodedBody;
					if (contentDecodedBody.Length > 0)
					{
						string htmlTag = null;
						string type = http.ContentTypeWithoutCharset;
						string category = type != null ? type.Split('/')[0].ToLower().Trim() : null;

						if ("image".Equals(category))
						{
							htmlTag = "<img alt=\"Image\" style=\"max-width:300px;max-height:300px\" src=\"data:{0};base64,{1}\"/>";
						}
						else if ("audio".Equals(category))
						{
							htmlTag = "<audio controls src=\"data:{0};base64,{1}\">" +
								  "Your browser cannot play audio." +
								"</audio>";
						}
						else if ("video".Equals(category))
						{
							htmlTag = "<video controls src=\"data:{0};base64,{1}\">" +
								  "Your browser cannot play video." +
								"</video>";
						}
						else
						{
							// TODO Firefox treats some content types as attachments, which is why
							// all non-text categories are treated as plain text, should be investigated further
							if (!"text".Equals(category))
								type = null;
						}
						builder.Append(ToLogEntryBody(contentDecodedBody, type, htmlTag));
					}
				}
				else if (http.Body.Length > 0)
				{
					builder.Append("<p style=\"color:red\">---Skipping body---</p>");
				}
				builder.Append("\n\n");
				return builder.ToString();
			}

			private string ToLogEntryBody(object obj, string type, string htmlTag)
			{
				byte[] raw = obj is byte[] rawObj ? rawObj : Encoding.Default.GetBytes(obj.ToString());
				if (type == null)
					type = "text/plain";
				if (htmlTag == null)
					htmlTag = "<iframe height=\"400\" width=\"100%\" src=\"data:{0};base64,{1}\"></iframe>\n<br>\n<br>";

				return string.Format(
						htmlTag,
						type,
						Convert.ToBase64String(raw)
				);
			}
		}

		internal class LogStream : Stream
		{
			private Stream basestream;
			private readonly bool mode;
			private readonly bool leaveOpen;

			private static readonly RNGCryptoServiceProvider RAND = new RNGCryptoServiceProvider();

			private CryptoStream decryptStream = null;
			private int bytesLeft = 0;

			private byte[] key;
			private byte[] ivBuf;
			private byte[] lenBuf;
			private byte[] memBuf;

			public LogStream(Stream stream, byte[] key, bool mode)
				: this(stream, key, mode, false) { }

			public LogStream(Stream stream, byte[] key, bool mode, bool leaveOpen)
			{
				this.basestream = stream;
				this.key = key != null ? key : new byte[16];
				this.mode = mode;
				this.leaveOpen = leaveOpen;

				ivBuf = new byte[16];
				lenBuf = new byte[sizeof(int)];
				memBuf = new byte[8192];
			}

			public override bool CanRead { get { return mode; } }

			public override bool CanWrite { get { return !mode; } }

			public override bool CanSeek { get { return false; } }

			public override long Length => throw new NotSupportedException("Length is not supported");

			public override long Position
			{
				get => throw new NotSupportedException("Position is not supported");
				set => throw new NotImplementedException("Position is not supported");
			}

			public override void Flush()
			{
				ThrowIfDisposed();

				basestream.Flush();
			}

			public override long Seek(long offset, SeekOrigin origin)
			{
				throw new NotSupportedException("Seek is not supported");
			}

			public override void SetLength(long value)
			{
				throw new NotSupportedException("SetLength is not supported");
			}

			public LogEntry Read()
			{
				// TODO
				throw new NotImplementedException("Reading a log entry is not implemented.");
			}

			public override int Read(byte[] buffer, int offset, int count)
			{
				if (!CanRead)
					throw new InvalidOperationException("LogEntryStream is not readable");
				ThrowIfDisposed();
				ThrowIfInvalidParams(buffer, offset, count);

				int readCount, realReadCount;

				if (decryptStream == null)
				{
					if (basestream.Read(ivBuf, 0, ivBuf.Length) < ivBuf.Length)
						return 0;

					if (basestream.Read(lenBuf, 0, lenBuf.Length) < lenBuf.Length)
						return 0;

					bytesLeft = BitConverter.ToInt32(lenBuf, 0);
					if (bytesLeft < 0)
						throw new InvalidDataException("Entry Length was negative");

					MemoryStream ms = new MemoryStream();
					CopyBasestreamTo(ms, bytesLeft);
					ms.Position = 0;

					Aes aes = Aes.Create();
					aes.Padding = PaddingMode.PKCS7;
					ICryptoTransform decryptor = aes.CreateDecryptor(key, ivBuf);
					decryptStream = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
				}
				readCount = count > bytesLeft ? bytesLeft : count;
				realReadCount = decryptStream.Read(buffer, offset, readCount);

				bytesLeft -= readCount;

				if (realReadCount <= 0)
					return 0;

				if (bytesLeft < 1)
				{
					decryptStream.Flush();
					decryptStream.Close();
					decryptStream = null;
				}
				return realReadCount;
			}

			public void Write(LogEntry entry)
			{
				Write(entry.Raw, 0, entry.Raw.Length);
			}

			public override void Write(byte[] buffer, int offset, int count)
			{
				if (!CanWrite)
					throw new InvalidOperationException("LogEntryStream is not writable");
				ThrowIfDisposed();
				ThrowIfInvalidParams(buffer, offset, count);

				RAND.GetBytes(ivBuf);

				using (Aes aes = Aes.Create())
				{
					aes.Padding = PaddingMode.PKCS7;
					ICryptoTransform encryptor = aes.CreateEncryptor(key, ivBuf);

					using (MemoryStream ms = new MemoryStream())
					{
						using (CryptoStream encryptStream = new CryptoStream(ms, encryptor, CryptoStreamMode.Write, leaveOpen: true))
						{
							encryptStream.Write(buffer, offset, count);
							encryptStream.FlushFinalBlock();
						}
						using (BinaryWriter br = new BinaryWriter(basestream, Encoding.Default, leaveOpen: true))
						{
							br.Write(ivBuf);
							br.Write((int)ms.Length);
							br.Write(ms.ToArray());
						}
					}
				}
			}

			protected override void Dispose(bool disposing)
			{
				try
				{
					if (disposing && !leaveOpen && basestream != null)
						basestream.Close();
				}
				finally
				{
					basestream = null;
				}
				base.Dispose(disposing);
			}

			private void CopyBasestreamTo(Stream s, int max)
			{
				int bytesToRead, read;
				int bytesRead = 0;
				while (bytesRead < max)
				{
					bytesToRead = memBuf.Length < max - bytesRead ? memBuf.Length : max - bytesRead;
					read = basestream.Read(memBuf, 0, bytesToRead);
					if (read <= 0)
						return;
					s.Write(memBuf, 0, read);
					bytesRead += read;
				}
			}

			private void ThrowIfDisposed()
			{
				if (basestream == null)
					throw new ObjectDisposedException(null, "Stream is disposed.");
			}

			private void ThrowIfInvalidParams(byte[] buffer, int offset, int count)
			{
				if (buffer == null)
					throw new ArgumentNullException(nameof(buffer));
				if (offset < 0)
					throw new ArgumentOutOfRangeException(nameof(offset));
				if (count < 0)
					throw new ArgumentOutOfRangeException(nameof(count));
				if (buffer.Length - offset < count)
					throw new ArgumentException("Invalid offset and count for the given buffer");
			}
		}

		private static string UNINIT_MSG = "Logger is not initialized, call Initialize() first.";
		private static string LOG_SUFFIX = ".tirlog";

		private static Logger instance = null;

		private string logDir = null;
		private uint verbosity;
		private uint maxLogSize;
		private byte[] key;

		private Logger() { }

		/// <summary>
		/// Initialize the logger with a specified log directory and verbosity.
		/// </summary>
		/// <param name="logDir">The directory to contain the log files.</param>
		/// <param name="verbosity">The higher the value, the more objects will be logged.</param>
		/// <param name="maxLogSize">The largest size allowed for a log in MiB. If a log
		/// exceeds this size, it is deleted.</param>
		/// <param name="key">The key that will be used to encypt logs. If null or
		/// empty, the logs will not be encrypted.</param>
		public void Initialize(string logDir, uint verbosity, uint maxLogSize, byte[] key)
		{
			if (this.logDir != null)
				throw new InvalidOperationException("Logger has already been initialized.");

			if (key != null && key.Length != 16 && key.Length != 24 && key.Length != 32)
				throw new ArgumentException("Invalid key length: " + key.Length);

			this.logDir = logDir ?? throw new ArgumentNullException(nameof(logDir));
			this.verbosity = verbosity;
			this.maxLogSize = maxLogSize;
			this.key = key;
			Directory.CreateDirectory(logDir);
		}

		/// <summary>
		/// Gets the singleton.
		/// </summary>
		/// <returns>The singleton.</returns>
		public static Logger GetSingleton()
		{
			if (instance == null)
			{
				instance = new Logger();
			}
			return instance;
		}

		/// <summary>
		/// Logs the specified object to the log with the given filename on a new thread if the
		/// verbosity is higher than the given level.
		/// </summary>
		/// <param name="level">The log level to use for the object.</param>
		/// <param name="logname">The filename of the log in the log directory.</param>
		/// <param name="head">A descriptive name for the object or log entry.</param>
		/// <param name="obj">The object to log.</param>
		public void Log(uint level, string logname, string head, object obj)
		{
			if (level < 1 || verbosity < level)
				return;
			ThrowIfInvalid(level, logname, head, obj);

			Task.Run(() => LogInternal(level, logname, head, obj));
		}

		private void LogInternal(uint level, string logname, string head, object obj)
		{
			int attempts = 5;
			LogEntry entry;
			try
			{
				// Delete the log if it has gotten too large
				if (Exists(logname) && LogSize(logname) >> 20 >= maxLogSize)
					DeleteLog(logname);

				// TODO Is there a need to check what the object is before calling
				// ToLogEntry
				if (obj is HttpRequest req)
				{
					entry = new LogEntry(head, req, verbosity);
				}
				else if (obj is HttpResponse resp)
				{
					entry = new LogEntry(head, resp, verbosity);
				}
				else
				{
					entry = new LogEntry(head, obj);
				}

				for (int i = 0; i < attempts; i++)
				{
					try
					{
						using (var s = new FileStream(LogPath(logname), FileMode.Append))
						{
							using (var entryStream = new LogStream(s, key, mode: false))
							{
								entryStream.Write(entry);
								entryStream.Flush();
							}
						}
						return;
					}
					catch
					{
						Thread.Sleep(100);
					}
				}
			}
			catch (Exception e)
			{
				LogException(e);
			}
		}

		/// <summary>
		/// Logs an exception to stdout.
		/// </summary>
		/// <param name="e">The exception.</param>
		public void LogException(Exception e)
		{
			LogException(e, null);
		}

		/// <summary>
		/// Logs an exception to stdout.
		/// </summary>
		/// <param name="e">The exception.</param>
		/// <param name="info">Optional information object to log.</param>
		public void LogException(Exception e, object info)
		{
			if (logDir == null)
				throw new InvalidOperationException(UNINIT_MSG);

			switch (verbosity)
			{
				case 0:
				case 1:
				case 2:
				case 3:
					break;
				case 4:
				case 5:
				case 6:
				case 7:
					Console.WriteLine(e.Message);
					if (info != null)
						Console.WriteLine(info);
					break;
				default:
					Console.WriteLine(e);
					if (info != null)
						Console.WriteLine(info);
					break;

			}
		}

		public string[] LogNames
		{
			get
			{
				if (logDir == null)
					throw new InvalidOperationException(UNINIT_MSG);

				string[] files = Directory.GetFiles(logDir, "*" + LOG_SUFFIX);
				for (int i = 0; i < files.Length; i++)
				{
					files[i] = Path.GetFileName(files[i]);
					files[i] = files[i].Substring(0, files[i].Length - LOG_SUFFIX.Length);
				}
				Array.Sort(files, StringComparer.InvariantCulture);
				return files;
			}
		}

		/// <summary>
		/// Checks if the specified log exists.
		/// </summary>
		/// <returns><c>true</c> if it exists; otherwise <c>false</c>.</returns>
		/// <param name="logname">The specified log.</param>
		public bool Exists(string logname)
		{
			ThrowIfInvalid(logname);

			string logPath = LogPath(logname);
			return logPath != null ?
				File.Exists(logPath) :
				false;
		}

		/// <summary>
		/// Returns the write time for the given log file.
		/// </summary>
		/// <returns>The last write time if the log file exists.</returns>
		/// <param name="logname">Name of the log file.</param>
		public DateTime LastWriteTime(string logname)
		{
			ThrowIfInvalid(logname);

			string logPath = LogPath(logname);
			return logPath != null ?
			    File.GetLastWriteTime(logPath) :
				throw new FileNotFoundException(logname);
		}

		/// <summary>
		/// Gets the last write time for the log directory.
		/// </summary>
		/// <value>The last write time for the log directory.</value>
		public DateTime LastWriteTimeDirectory
		{
			get
			{
				if (logDir == null)
					throw new InvalidOperationException(UNINIT_MSG);

				return Directory.GetLastWriteTime(logDir);
			}
		}

		/// <summary>
		/// Gets the size of the given log file in bytes.
		/// </summary>
		/// <returns>The size in bytes if the log file exists.</returns>
		/// <param name="logname">Name of the log file.</param>
		public long LogSize(string logname)
		{
			ThrowIfInvalid(logname);

			string logPath = LogPath(logname);
			return logPath != null ?
				new FileInfo(logPath).Length :
				throw new FileNotFoundException(logname);
		}

		/// <summary>
		/// Reads the given log as raw data.
		/// </summary>
		/// <returns>The raw log.</returns>
		/// <param name="logname">Name of the log file to read.</param>
		public byte[] ReadLog(string logname)
		{
			// TODO This method should be changed to write a log to a given stream instead since
			// reading the entire log into memory is not ideal.
			int attempts = 5;
			ThrowIfInvalid(logname);

			string path = LogPath(logname);
			if (path != null && File.Exists(path))
			{
				using (MemoryStream ms = new MemoryStream())
				{
					for (int i = 0; i < attempts; i++)
					{
						try
						{
							using (var s = new FileStream(path, FileMode.Open))
							{
								using (var logStream = new LogStream(s, key, mode: true))
								{
									logStream.CopyTo(ms);
									return ms.ToArray();
								}
							}
						}
						catch (Exception e)
						{
							LogException(e);
							Thread.Sleep(100);
						}
					}
				}
				throw new IOException("Failed to read the log");
			}
			throw new FileNotFoundException(logname);
		}

		/// <summary>
		/// Deletes the given log file if it exists.
		/// </summary>
		/// <param name="logname">Name of the log file to delete.</param>
		public void DeleteLog(string logname)
		{
			int attempts = 5;
			ThrowIfInvalid(logname);

			string path = LogPath(logname);
			if (path != null && File.Exists(path))
			{
				for (int i = 0; i < attempts; i++)
				{
					try
					{
						File.Delete(path);
						return;
					}
					catch
					{
						Thread.Sleep(100);
					}
				}
				throw new IOException("Failed to delete the log");
			}
		}

		private string LogPath(string logname)
		{
			// TODO Implement better path escaping
			if (logname != null && !".".Equals(logname) && !"..".Equals(logname) && !logname.Contains("/"))
			{
				try
				{
					return Path.Combine(logDir, logname + LOG_SUFFIX);
				}
				catch { /* Ignore */ }
			}
			return null;
		}

		private void ThrowIfInvalid(string logname)
		{
			if (logDir == null)
				throw new InvalidOperationException(UNINIT_MSG);
			if (logname == null)
				throw new ArgumentNullException("Arguments may not be null");
		}

		private void ThrowIfInvalid(uint level, string logname, string head, object obj)
		{
			if (logDir == null)
				throw new InvalidOperationException(UNINIT_MSG);
			if (logname == null || head == null || obj == null)
				throw new ArgumentNullException("Arguments may not be null");
		}
	}
}
