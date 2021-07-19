using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Collections.Concurrent;

namespace Tiriryarai.Util
{
	/// <summary>
	/// Class that logs objects to logs with dynamically given filenames.
	/// </summary>
	public class Logger
	{
		private static Logger instance = null;
		private string logDir = null;
		private uint verbosity;

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
		public void Initialize(string logDir, uint verbosity)
		{
			this.logDir = logDir ?? throw new ArgumentNullException(nameof(logDir));
			this.verbosity = verbosity;
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
		/// Logs the specified object to the log with the given filename if the verbosity is higher than the given level.
		/// </summary>
		/// <param name="level">The log level to use for the object.</param>
		/// <param name="filename">The filename of the log in the log directory.</param>
		/// <param name="head">A descriptive name for the object or log entry.</param>
		/// <param name="obj">The object to log.</param>
		public void Log(uint level, string filename, string head, object obj)
		{
			if (logDir == null)
				throw new InvalidOperationException("Logger is not initialized, call Initialize() first.");

			if (level < 1 || verbosity < level)
				return;
		
			int attempts = 0;
			byte[] entry = Encoding.UTF8.GetBytes(obj + "\n\n");
			while (!logMutex.TryAdd(filename, 0))
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
				using (var s = new FileStream(Path.Combine(logDir, Path.GetFileName(filename) + ".log"), FileMode.Append))
				{
					byte[] header = Encoding.UTF8.GetBytes(
						$"################ {head} {DateTime.Now.ToLongTimeString()} {DateTime.Now.ToLongDateString()} ################\n"
					);
					s.Write(header, 0, header.Length);
					s.Write(entry, 0, entry.Length);
				}
			}
			finally
			{
				logMutex.TryRemove(filename, out _);
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
				throw new InvalidOperationException("Logger is not initialized, call Initialize() first.");

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
	}
}
