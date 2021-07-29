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
using System.Linq;
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
		private static string ProxyPass = null;
		private static string ConfigDir = null;
		private static bool Logs = false;
		private static bool IgnoreCerts = false;
		private static int ReadTimeout = -1;
		private static bool Help = false;
		private static bool Version = false;

		/// <summary>
		/// The entry point of the program, where the program control starts and ends.
		/// </summary>
		/// <param name="args">The command-line arguments.</param>
		static void Main(string[] args)
		{
			List<string> extraOpts = new List<string>();
			OptionSet opts = new OptionSet
			{
				{ "d|hostname=", "The hostname of the server, if it has one. If not given, it will default " +
					"to the system IP.", (host) => Hostname = host },
				{ "p|port=", "The port the server will listen on, 8081 by default.", (ushort port) => Port = port },
				{ "v|verbosity=", "The higher this value is, the more information will be logged.", (uint v) => Verbosity = v },
				{ "s|logsize=", "The maximum allowed size of a log in MiB before it is deleted.", (uint s) => MaxLogSize = s },
				{ "u|username=", "The username required for basic HTTP authentication if one should be required. " +
					"Used for both proxy authentication and accessing the admin pages.", (user) => Username = user },
				{ "w|password=", "The password required for accessing the admin pages if one should be required. " +
					"It will be sent securely using HTTPS only.", (pass) => Password = pass },
				{ "x|proxypass=", "The password required for using the proxy if one should be required. " +
					"It will be sent insecurely using HTTP and should not be the same as the admin password.", (pass) => ProxyPass = pass },
				{ "c|configdir=", "The directory where certificates, server configuration, and log files will be stored.", (dir) => ConfigDir = dir },
				{ "l|logs",  "Activate admin remote log management via the web interface. Usage of authentication recommended.", _ => Logs = true },
				{ "i|ignorecerts",  "Ignore invalid certificates when sending HTTPS requests.", _ => IgnoreCerts = true },
				{ "t|timeout=",  "The time in milliseconds to wait on a client request before terminating the connection.", (int t) => ReadTimeout = t },
				{ "h|help",  "Show help", _ => Help = true },
				{ "version",  "Show version and about info", _ => Version = true }
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

			if (Version)
			{
				Console.WriteLine("Tiriryarai " + Resources.Version);
				Console.WriteLine("Copyright (C) 2021 William Stackenäs");
				Console.WriteLine("License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>");
				Console.WriteLine("This is free software: you are free to change and redistribute it."); 
				Console.WriteLine("There is NO WARRANTY, to the extent permitted by law.");
				Environment.Exit(-1);
			}

			// https://stackoverflow.com/questions/699852/how-to-find-all-the-classes-which-implement-a-given-interface
			IEnumerable<IManInTheMiddle> mitms =
			    from t in Resources.Assembly.GetTypes()
			    where t.GetInterfaces().Contains(typeof(IManInTheMiddle))
			          && t.GetConstructor(Type.EmptyTypes) != null
			    select Activator.CreateInstance(t) as IManInTheMiddle;
													  
			HttpsMitmProxy proxy = null;
			try
			{
				if (mitms.Count() == 0)
					throw new Exception(
					    "No man-in-the-middle handler plugins could be found in the assembly." +
					    "Please add a class that inplements the IManInTheMiddle interface."
					);
				if (mitms.Count() != 1)
					throw new NotSupportedException(
						"Multiple man-in-the-middle handler plugins in not supported." +
						"Please only add one class that implements the IManInTheMiddle interface."
					);
				HttpsMitmProxyParams prms = new HttpsMitmProxyParams(mitms.ElementAt(0), Port, Username, Password)
				{
					ProxyPassword = ProxyPass,
					ConfigDirectory = ConfigDir,
					LogVerbosity = Verbosity,
					MaxLogSize = MaxLogSize,
					Hostname = Hostname,
					LogManagement = Logs,
					IgnoreCertificates = IgnoreCerts,
					AllowedLoginAttempts = 5,
					ReadTimeout = ReadTimeout
				};
				proxy = new HttpsMitmProxy(prms);
			}
			catch (Exception e)
			{
				Console.WriteLine("Failed to initialize server:\n" + e.Message);
				Environment.Exit(-2);
			}
			proxy.Start();
			Console.WriteLine("Tiriryarai shut down...");
		}
	}
}
