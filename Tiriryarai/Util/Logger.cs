﻿using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading;
using System.Collections.Concurrent;

using Tiriryarai.Http;

namespace Tiriryarai.Util
{
	/// <summary>
	/// Class that logs objects to logs with dynamically given filenames.
	/// </summary>
	public class Logger
	{
		private static string UNINIT_MSG = "Logger is not initialized, call Initialize() first.";
		private static string LOG_SUFFIX = ".log.html";

		private static Logger instance = null;
		private string logDir = null;
		private uint verbosity;
		private uint maxLogSize;

		private ConcurrentDictionary<string, byte> logMutex;

		private Logger()
		{
			logMutex = new ConcurrentDictionary<string, byte>();
		}

		/// <summary>
		/// Initialize the logger with a specified logDir and verbosity.
		/// </summary>
		/// <param name="logDir">The directory to contain the log files.</param>
		/// <param name="verbosity">The higher the value, the more objects will be logged.</param>
		/// <param name="maxLogSize">The largest size allowed for a log in MiB. If a log
		/// exceeds this size, it is deleted.</param>
		public void Initialize(string logDir, uint verbosity, uint maxLogSize)
		{
			this.logDir = logDir ?? throw new ArgumentNullException(nameof(logDir));
			this.verbosity = verbosity;
			this.maxLogSize = maxLogSize;
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
		/// Logs the specified HTTP request to the log with the given filename if the verbosity is higher than the given level.
		/// </summary>
		/// <param name="level">The log level to use for the object.</param>
		/// <param name="logname">The filename of the log in the log directory.</param>
		/// <param name="head">A descriptive name for the object or log entry.</param>
		/// <param name="req">The HTTP request to log.</param>
		public void Log(uint level, string logname, string head, HttpRequest req)
		{
			if (logDir == null)
				throw new InvalidOperationException(UNINIT_MSG);
			if (logname == null || head == null || req == null)
				throw new ArgumentNullException(nameof(logname) + " " + nameof(head) + " " + nameof(req));
			if (level < 1 || verbosity < level)
				return;

			Log(level, logname, head, req.RequestLine + ToLogEntry(req) + "\n\n");
		}

		/// <summary>
		/// Logs the specified HTTP response to the log with the given filename if the verbosity is higher than the given level.
		/// </summary>
		/// <param name="level">The log level to use for the object.</param>
		/// <param name="logname">The filename of the log in the log directory.</param>
		/// <param name="head">A descriptive name for the object or log entry.</param>
		/// <param name="req">The HTTP response to log.</param>
		public void Log(uint level, string logname, string head, HttpResponse resp)
		{
			if (logDir == null)
				throw new InvalidOperationException(UNINIT_MSG);
			if (logname == null || head == null || resp == null)
				throw new ArgumentNullException(nameof(logname) + " " + nameof(head) + " " + nameof(resp));
			if (level < 1 || verbosity < level)
				return;

			Log(level, logname, head, resp.ResponseLine + ToLogEntry(resp) + "\n\n");
		}

		/// <summary>
		/// Logs the specified object to the log with the given filename if the verbosity is higher than the given level.
		/// </summary>
		/// <param name="level">The log level to use for the object.</param>
		/// <param name="logname">The filename of the log in the log directory.</param>
		/// <param name="head">A descriptive name for the object or log entry.</param>
		/// <param name="obj">The object to log.</param>
		public void Log(uint level, string logname, string head, object obj)
		{
			if (logDir == null)
				throw new InvalidOperationException(UNINIT_MSG);
			if (logname == null || head == null || obj == null)
				throw new ArgumentNullException(nameof(logname) + " " + nameof(head) + " " + nameof(obj));
			if (level < 1 || verbosity < level)
				return;

			Log(level, logname, head, obj + "\n\n");
		}

		private void Log(uint level, string logname, string head, string entry)
		{
			int attempts = 0;
			while (!logMutex.TryAdd(logname, 0))
			{
				if (++attempts > 5)
				{
					Console.WriteLine("Warning: Request to log object timed out.");
					return;
				}
				Thread.Sleep(100);
			}
			try
			{
				// Delete the log if it has gotten too large
				if (Exists(logname))
				{
					if (LogSize(logname) >> 20 >= maxLogSize)
						DeleteLog(logname);
				}

				using (var s = new FileStream(LogPath(logname), FileMode.Append))
				{
					byte[] header = Encoding.UTF8.GetBytes(
						$"<strong>{head} {DateTime.Now.ToLongTimeString()} {DateTime.Now.ToLongDateString()}</strong>\n<br>"
					);
					byte[] rawEntry = Encoding.UTF8.GetBytes(entry.Replace("\n", "\n<br>"));
					s.Write(header, 0, header.Length);
					s.Write(rawEntry, 0, rawEntry.Length);
				}
			}
			finally
			{
				logMutex.TryRemove(logname, out _);
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
				case 4:
				case 5:
					break;
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
			if (logDir == null)
				throw new InvalidOperationException(UNINIT_MSG);

			string logPath = LogPath(logname);
			return logPath != null ?
				File.Exists(logPath) :
				false;
		}

		/// <summary>
		/// Returns the write time for the given log file.
		/// </summary>
		/// <returns>The last write time if the log file exists; otherwise, <c>Datetime.MaxValue</c>.</returns>
		/// <param name="logname">Name of the log file.</param>
		public DateTime LastWriteTime(string logname)
		{
			if (logDir == null)
				throw new InvalidOperationException(UNINIT_MSG);

			string logPath = LogPath(logname);
			return logPath != null ?
			    File.GetLastWriteTime(logPath) :
			    DateTime.MaxValue;
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
		/// <returns>The size in bytes if the log file exists; otherwise, <c>-1</c>.</returns>
		/// <param name="logname">Name of the log file.</param>
		public long LogSize(string logname)
		{
			if (logDir == null)
				throw new InvalidOperationException(UNINIT_MSG);

			string logPath = LogPath(logname);
			return logPath != null ?
				new FileInfo(logPath).Length :
				-1;
		}

		/// <summary>
		/// Reads the log as raw data.
		/// </summary>
		/// <returns>The raw log.</returns>
		/// <param name="logname">Name of the log file.</param>
		public byte[] ReadLog(string logname)
		{
			return ReadLog(logname, null);
		}


		/// <summary>
		/// Reads the given log as raw data and encodes it according to the given encoding.
		/// </summary>
		/// <returns>The raw log.</returns>
		/// <param name="logname">Name of the log file to read.</param>
		/// <param name="encoding">The encoding to use. <c>"gzip"</c> and <c>"deflate"</c>
		/// are supported. If <c>null</c>, no encoding will be used.</param>
		public byte[] ReadLog(string logname, string encoding)
		{
			if (logDir == null)
				throw new InvalidOperationException(UNINIT_MSG);

			int attempts = 0;
			while (!logMutex.TryAdd(logname, 0))
			{
				if (++attempts > 5)
				{
					throw new IOException("Request to read log timed out.");
				}
				Thread.Sleep(100);
			}
			try
			{
				MemoryStream ms = new MemoryStream();
				Stream encStream = null;
				using (var fs = new FileStream(LogPath(logname), FileMode.Open))
				{
					if (encoding != null)
					{
						if ("gzip".Equals(encoding))
							encStream = new GZipStream(ms, CompressionMode.Compress);
						else if ("deflate".Equals(encoding))
							encStream = new DeflateStream(ms, CompressionMode.Compress);
						else
							throw new ArgumentException("No such encoding supported: " + encoding);

						fs.CopyTo(encStream);
						encStream.Close();
					}
					else
					{
						fs.CopyTo(ms);
					}
				}
				return ms.ToArray();
			}
			finally
			{
				logMutex.TryRemove(logname, out _);
			}
		}

		/// <summary>
		/// Deletes the given log file if it exists.
		/// </summary>
		/// <param name="logname">Name of the log file to delete.</param>
		public void DeleteLog(string logname)
		{
			if (logDir == null)
				throw new InvalidOperationException(UNINIT_MSG);

			string path = LogPath(logname);
			if (path != null)
				File.Delete(path);
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

		private string ToLogEntry(HttpMessage http)
		{
			StringBuilder builder = new StringBuilder();
			if (verbosity > 3)
				builder.Append(http.RawHeaders);
			if (verbosity > 6)
			{
				byte[] contentDecodedBody = http.ContentDecodedBody;
				if (contentDecodedBody.Length > 0)
				{
					string htmlBody = null;
					string category;
					string htmlTag;
					string type = http.GetHeader("Content-Type")?[0];

					category = type != null ? type.Split('/')[0].ToLower().Trim() : null;
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
						htmlTag = "<iframe height=\"400\" width=\"100%\" src=\"data:{0};base64,{1}\">" +
							"</iframe>";
						// TODO Firefox treats some content types as attachments, which is why
						// all non-text categories are treaded as plain text, should be investigated further
						type = "text".Equals(category) ? type : "text/plain";
					}
					htmlBody = string.Format(
						htmlTag,
						type,
						Convert.ToBase64String(contentDecodedBody)
					);
					builder.Append(htmlBody);
				}
			}
			return builder.ToString();
		}
	}
}
