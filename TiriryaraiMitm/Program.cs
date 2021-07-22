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
using System.Collections.Generic;

using Mono.Options;

using Tiriryarai.Server;
using Tiriryarai.Util;


namespace TiriryaraiMitm
{
	/// <summary>
	/// The main program run at startup.
	/// </summary>
	class Program
	{
		private static string Hostname = null;
		private static ushort Port = 8081;
		private static uint? Verbosity = null;
		private static uint? MaxLogSize = null;
		private static string Username = null;
		private static string Password = null;
		private static string ConfigDir = null;
		private static bool Logs = false;
		private static bool Help = false;

		/// <summary>
		/// The entry point of the program, where the program control starts and ends.
		/// </summary>
		/// <param name="args">The command-line arguments.</param>
		static void Main(string[] args)
		{
			List<string> extraOpts = new List<string>();
			OptionSet opts = new OptionSet
			{
				{ "d|hostname=", "The hostname of the server, if it has one.", (host) => Hostname = host },
				{ "p|port=", "The port the server will listen on, 8081 by default.", (ushort port) => Port = port },
				{ "v|verbosity=", "The higher this value is, the more information will be logged.", (uint v) => Verbosity = v },
				{ "s|logsize=", "The maximum allowed size of a log in MiB before it is deleted.", (uint s) => MaxLogSize = s },
				{ "u|username=", "The username required for basic HTTP authentication if one should be required.", (user) => Username = user },
				{ "w|password=", "The password required for basic HTTP authentication if one should be required.", (pass) => Password = pass },
				{ "c|configdir=", "The directory where certificates, server configuration, and log files will be stored.", (dir) => ConfigDir = dir },
				{ "l|logs",  "Activate remote log management via the web interface. Usage of authentication recommended.", _ => Logs = true },
				{ "h|help",  "Show help", _ => Help = true }
			};

			try
			{
				extraOpts = opts.Parse(args);
			}
			catch (OptionException e)
			{
				Console.WriteLine(e.Message);
				Help = true;
			}

			if (Help || extraOpts.Count > 0)
			{
				opts.WriteOptionDescriptions(Console.Out);
				Environment.Exit(-1);
			}

			HttpsMitmProxy proxy = null;
			try
			{
				HttpsMitmProxyParams prms = new HttpsMitmProxyParams(Port, Username, Password)
				{
					MitM = new MiddleMan(),
					ConfigDirectory = ConfigDir,
					LogVerbosity = Verbosity,
					MaxLogSize = MaxLogSize,
					Hostname = Hostname,
					LogManagement = Logs
				};
				proxy = new HttpsMitmProxy(prms);
			}
			catch (Exception e)
			{
				Console.WriteLine("Failed to initialize server:\n" + e.Message);
				Environment.Exit(-2);
			}
			proxy.Start();
			Console.WriteLine("Server shut down...");
		}
	}
}
