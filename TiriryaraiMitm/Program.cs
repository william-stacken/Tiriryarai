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
using System.Net;
using System.Net.Sockets;

using Tiriryarai.Server;


namespace TiriryaraiMitm
{
	/// <summary>
	/// The main program run at startup.
	/// </summary>
	class Program
	{
		/// <summary>
		/// The entry point of the program, where the program control starts and ends.
		/// </summary>
		/// <param name="args">The command-line arguments. The program takes two arguments:
		/// The port number where the HTTPS man-in-the-middle proxy will be hosted, <c>8081</c>
		/// by default, and the log verbosity, with a default verbosity if not provided.</param>
		static void Main(string[] args)
		{
			HttpsMitmProxy proxy = null;
			MiddleMan mitm = new MiddleMan();
			ushort port = 8081;
			if (args.Length > 1 && !ushort.TryParse(args[1], out port))
			{
				Console.WriteLine(args[1] + " is not a valid port number!");
				Environment.Exit(-1);
			}
			try
			{
				if (args.Length > 2)
				{
					if (uint.TryParse(args[2], out uint verbosity))
					{
						proxy = new HttpsMitmProxy(mitm, port, verbosity);
					}
					else
					{
						Console.WriteLine(args[2] + " is not a valid log verbosity!");
						Environment.Exit(-2);
					}
				}
				else
				{
					proxy = new HttpsMitmProxy(mitm, port);
				}
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
