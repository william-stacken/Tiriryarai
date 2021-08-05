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
using System.ComponentModel;
using System.Reflection;

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
		/// <summary>
		/// The entry point of the program, where the program control starts and ends.
		/// </summary>
		/// <param name="args">The command-line arguments.</param>
		static void Main(string[] args)
		{
			bool help = false;
			bool version = false;
			HttpsMitmProxy proxy = null;
			List<string> extraOpts = null;
			Dictionary<string, string> props = new Dictionary<string, string>();
			try
			{
				HttpsMitmProxyConfig conf = HttpsMitmProxyConfig.GetSingleton();
				OptionSet opts = new OptionSet
				{
					{ "h|help",  "Show help.", _ => help = true },
					{ "version",  "Show version and about info.", _ => version = true }
				};

				try
				{
					foreach (var p in conf.GetType().GetProperties())
					{
						string cli;
						if (p.GetCustomAttribute(typeof(HttpsMitmProxyAttribute), false) is HttpsMitmProxyAttribute attr &&
							(cli = attr.CliPrototype) != null)
						{
							string description = (p.GetCustomAttribute(typeof(DescriptionAttribute), false)
								as DescriptionAttribute)?.Description;

							opts.Add(cli, description ?? "<no description>", v => {
								props.Add(p.Name.ToLower(), v);
							});
						}
					}
					extraOpts = opts.Parse(args);
					conf.SetProperties(props, init: true); // Ignore return value
				}
				catch (Exception e)
				{
					if (e is TargetInvocationException t)
						e = t.InnerException;
					Console.WriteLine(e.Message);
					help = true;
				}

				if (help || extraOpts?.Count > 0)
				{
					opts.WriteOptionDescriptions(Console.Out);
					Environment.Exit(-1);
				}
				else if (version)
				{
					Console.WriteLine("Tiriryarai " + Resources.Version);
					Console.WriteLine("Copyright (C) 2021 William Stackenäs");
					Console.WriteLine("License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>");
					Console.WriteLine("This is free software: you are free to change and redistribute it.");
					Console.WriteLine("There is NO WARRANTY, to the extent permitted by law.");
					Environment.Exit(-1);
				}

				PrintStartup();
				if (!conf.Authenticate)
				{
					Console.WriteLine("NOTICE: Authentication for accessing admin pages is disabled.");
					Console.WriteLine("Hosting Tiriryarai on the public internet or an untrusted network is strongly discouraged.");
					Console.WriteLine("If this was unintentional, see the help by using the \"-h\" flag.");
					Console.WriteLine();
				}
				Console.Write("Starting server and generating certificates... ");

				proxy = new HttpsMitmProxy(conf);

				Console.WriteLine("Done");
				Console.WriteLine();
				Console.WriteLine("Tiriryarai has started!");
				Console.WriteLine("Configure your client to use host " + conf.Hostname + " and port " + conf.Port + " as a HTTP proxy.");
				Console.WriteLine("Then open http://" + Resources.HOSTNAME + " for more information.");
			}
			catch (Exception e)
			{
				if (e is TargetInvocationException t)
					e = t.InnerException;
				Console.WriteLine("\nFailed to initialize server:");
				Console.WriteLine(e.Message);
				Environment.Exit(-2);
			}
			proxy.Start();
			Console.WriteLine("Tiriryarai shut down...");
		}

		private static void PrintStartup()
		{
			Console.WriteLine("                                                   WWWWWWW                                          ");
			Console.WriteLine("                                        WWNNNXXXKKK0OOkkkkOOO0KKXNNWWWWW                            ");
			Console.WriteLine("                                WWNNNNXXXXXKKKKKKKKK00000OOOOkkkOkkkkxxkkOKXW                       ");
			Console.WriteLine("                          WNNXXXXXXXXNNNNNNNNNNNNKK0OOOKXXXXXXNNXXXXXK0OkkxxxOKNW                   ");
			Console.WriteLine("                     WNXKKKKKXXNNWWWWWWWWWWWWWWWN0xxOkd0XXXXXXXXXNNNNNNNNNXXKOkkOKN                 ");
			Console.WriteLine("              NK0KNNK000KXNWWWWWWWWWWWWWWWWWWWWWXkox0OdONNNNNXXXXXXNNNNNNNNNNNNX0kkO0OkKW           ");
			Console.WriteLine("            WKxdodxxkKNWWWWWWWWWWWWWWWWWWWWWWWWWKdoxkxdkNWWWNNNNXXXXNNNNNNNNNNNNXKx:,,,;l0W         ");
			Console.WriteLine("          WXkoxO00OxdxOXNWWWWNNNWWWWWWWWWWWWWWWW0xk0XOooKWWWWWWNNNNNNNNXKXXNNNXOdc;codl,.,dX        ");
			Console.WriteLine("         W0dokK0OKXXKOxxkKNWN0xx0KXNWWWWWWWWWWWNOk0XN0ocOWWWWWWWWWNNK0kolxKNKkl:coxOOo:;,..:0W      ");
			Console.WriteLine("        N0ddOKXOkKXXXXXKOxx0X0dxOkkkkO0KXNWWWWWXkOXNXOo:dNWWWWX0Oxoooodl:d0klcoxkxdolc:::;'.;OW     ");
			Console.WriteLine("       W0dx0KXXkxOKKKKKXXKOxkxox0KK0OkxdddONWWWKk0XXXOo;cKWNOocccldxkkxl;clcokkdollccccc::;,.;0W    ");
			Console.WriteLine("      WKxk0KKX0ddO0000000KKKOdlokOOOO0K00xdKWWNOOXNNXOd:;kW0lokO00kxddo:,:oxkxdlccccccccc::;,'lX    ");
			Console.WriteLine("      NOk0KKXXOodkOOOOOOOOOO0Oxdxxl:cok0KOd0WWNOOXNXXOdc,oNOoOX0ko:,;clccododxdlccccccccc:::;,:OW   ");
			Console.WriteLine("      N0OKKXNKxoxkkkOOOOOOOkkkkkko;.':x0KKxkNWXOKXKKKOdl,:0koOKOkc'.'ldooooodxxocccccccc:::::;:OW   ");
			Console.WriteLine("      NOOKXXN0ooxOkkkkkkkkkkkkkkkx:''lO0XXxdKWKOKK000Odo;,oll00OOo,.;xxooooooxxolcccccc::::::,;kW   ");
			Console.WriteLine("      XkkKXNNOlokOkkkkkkkkkkkkkkkkxc:x0KXNOo0X0O0OkO0Odc''::dK0OOkl:ldooooooodxolcccc:::::;;;,,xW   ");
			Console.WriteLine("      XkkKXNNkodkOOkkkkkkkkkkkkkkkOo:x00KX0ox0OK0kxk0x:;;,';xK0kkdccooooooolodxolcc::::::;;;;,,dW   ");
			Console.WriteLine("      XkkKXNXxoxOOOOkkkkkkkkkkkkkkOo:dO0KXKolxOXXOxxdc;cl,.;kKOkxd:coooooooloddolcc:::::;;;;;,'dW   ");
			Console.WriteLine("      Xkk0XNKdokOOkkOkkkkkkkkkkkkkOo:dO0KXXxloONXKKOl;clc;.;k0kxdo:cdoooollloddoc::::::;;;;;;''dN   ");
			Console.WriteLine("      Xxx0XN0dxOOOOOOOOOkkkkkkkkkO0o:dOO0KXKxdOXKKKKd:ccc:.,oxdddo:cddooollloddlc:::::;;;;,,,''dW   ");
			Console.WriteLine("      XxokXNKxxO0OOOOOOkkkkkkkkkkkOklldkO0K0xxKX0000d;:c::'.,clllccdxollllllodol:::::;;;,,,,,..xW   ");
			Console.WriteLine("      NxoxKNXkxO00OOOOkkkkkkkkkkkkkkOxlldkOkokXKOOOOl;::::,..,;;:oxxoollllllodol:::;;;,,,,,,'.'xW   ");
			Console.WriteLine("      NOodkXN0xk00OkkkkkkkkkkkkkkkkkkOOxllooo0KOkkkxc,::::;'.';lxdllllllllloddoc:;;;;;,,,,,'..;OW   ");
			Console.WriteLine("      W0xdldO0xddl:;,,;:ldxkkkkkkkkkkkO00xlcd00kkxxd;,::;;;,.,dxc;;clllllllool:,'....'',,''..'cK    ");
			Console.WriteLine("       XOkdlccc;'.........',:loxkkkkkkxkkOxcd0Oxxxxo,,::;;;,..:;,,,;:clc:;,'...........'''',,,dN    ");
			Console.WriteLine("       WN0kkxdl,.':c:;.. ......':ldxxxxxxxdccxOxxddl,,::;;,...',,,,,;;,'..     .,,;;,..,;;;;:xX     ");
			Console.WriteLine("         XOO00kc'cOOkx:..,xOd;.....;ldxxxxxoccdxdddl,,::;,...''''''....';,..   'loodo;..''''oN      ");
			Console.WriteLine("         KxOXXKd:l0NNN0:..:oo:'.    .':oxxxxoccodxkd;'::;'...'''.....'oO0d,.  .o0KKKd:'',,,'oN      ");
			Console.WriteLine("         KxOXXX0dod0NWWKc.  .      .''.'cdxxxoccdkkd,';;'...'''...''..,:;'.  'xNWNKxc;,',,,.lN      ");
			Console.WriteLine("         KxOKXXKdlld0KXNNOl;'''',:cllc;'',;:ccc::odl'';'...'''..':lllc;,,,;cxKNNK0xc;'',,,,.lN      ");
			Console.WriteLine("         KxOKKKklcclllodxkOOOOO00Okxdo:',:c:;;,,,,;;'.'...,,;:;',cdkOOOkkOOOOkxoc;;,,'.',,,.lN      ");
			Console.WriteLine("         Xxk0K0xccllccodxxxxxxxxxxdoollllllllcc::'......,clllc:,';codxxxxddddxxdl;''''.',,,.lN      ");
			Console.WriteLine("         Xkk0KX0oldxxdoodddddddxxdddoddddddool:,,;:;...,,;;;;;;;;;:clloooooloolc:;;;;;,,,,,.oN      ");
			Console.WriteLine("         NkxOKXOlcdxxxxxxxdddddddddxxxxddddddc,';odoc;cc,';;:;;;;;;;;:::::::::clcc:;;;;;,,''xW      ");
			Console.WriteLine("         NOdkKXklcdxxxxxxxxddddolloddxdddddo:,';ldxkkxoc;'',;;::::;;;;;;::::::cclcc:;;;;;,';O       ");
			Console.WriteLine("         W0dxKXkcloodxxxxxxddlc;,,,;codddoc;',:ok000KOxoc;'',;;;::;,,,',,;::::ccll:;;;;;;,'cK       ");
			Console.WriteLine("          XxdOKkllc;cdxxdddoc;,;coool::::,,,:ok0KOxdxO0Oxoc;,,,,,;:loc:,',::ccclll,',;;;;,,xW       ");
			Console.WriteLine("          W0dkKOllc,;lddddlc;,;ldxOKK0kdooxk0KX0dc:cc:oOK0OkdolldkO0koc;'',::cclc;..,;:;,'cK        ");
			Console.WriteLine("           NkdOOoc;;ccclol:,,;ldk0XXNNNNNNNNXOo;;oOOo,.,lkKXXXKKXXKKOxoc:,',:cc:,''.';:;';kW        ");
			Console.WriteLine("            Nkdkxc;,col::;,,:oxOKXNNNNNNNKOdc,',cxKkc,....;okKXXXXXK0Okdoc;,,::;;;'.';;,,dN         ");
			Console.WriteLine("             Nkdxd:,:odxdlcoxOKXNNNNKkdol;'...';clol;'.......,ldxO0KK0OOkxdl::clc:'.,,,;xN          ");
			Console.WriteLine("              WKxdo::oxkKKKKXNNNNNNNKkkkkxdoc;'';:c:,....',:clloodxO000OOkkxxddol:,,,;oKW           ");
			Console.WriteLine("                N0dc:ldkKNNNNNNNNNNNNWNNWWWWNXOd:'''..,cx0KNNNNNXXK000OOOkkxxxdol::cd0W             ");
			Console.WriteLine("                  NK0OkxOKNNNNNNNNWNWWWNWWWWWWWWXxlc:o0NWNNNNNNXXKK000OOkkkxxxdoxO0XW               ");
			Console.WriteLine("                      WXK0KXXNNNWWWWWWWWWWWWWWWWWWNNNNWWWNNNNNXXKK000OOkkkxxoox0W                   ");
			Console.WriteLine("                         WNXKKXXNNNWWWWWWWWWWWWWWWWWWWWWNNNNXXKKK000OOkkxdoox0N                     ");
			Console.WriteLine("                            WWNXXXXXXXXNNNNWWWWWWWWWWNNNNNNXXKKK00Okxdoodx0XW                       ");
			Console.WriteLine("                                 WWNXXXKKK0000000000000OOOOkkxxdddddxkOKNW                          ");
			Console.WriteLine("                                        WWNNXXKKK0000000000OOO00KKXNW                               ");
			Console.WriteLine();
		}
	}
}
