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
using System.Text.RegularExpressions;
using System.Collections.Generic;

using Tiriryarai.Server;
using Tiriryarai.Http;
using Tiriryarai.Util;

using HtmlAgilityPack;

namespace TuxEverywhere
{
	public class TuxEverywhere : IManInTheMiddle
	{
		private static readonly Random rand = new Random();
		private static readonly HashSet<string> imgExts = new HashSet<string>
		{
			"jpg", "png", "svg", "gif", "bmp", "ico", "webp"
		};
		private static readonly HashSet<string> sndExts = new HashSet<string>
		{
			"mp3", "wav", "ogg"
		};
		private static readonly string[] messages = new string[]
		{
			"Tux heard you're still using Windows?",
			"The penguins will take over!",
			"FREEEEEEEEEDOOOOMS!",
			"This page has been seized by the tux.",
			"Do not underestimate the penguins.",
			"I use Arch btw.",
			"Reclaim the desktop!",
			"The tux will release you from the prison of proprietary software.",
			"Windows-tan is shit-tier wifu",
			"Nuh-nuh-NUUUH?"
		};
		private static readonly string[] images = new string[]
		{
			"tux.svg"//, "tux2.png", "tux3.png"
		};
		private static readonly string[] audios = new string[]
		{
			"tux.mp3"
		};

		private HttpsMitmProxyConfig conf;

		public TuxEverywhere()
		{
			conf = HttpsMitmProxyConfig.GetSingleton();
		}

		public bool Block(string host)
		{
			return false;
		}

		public HttpMessage HandleRequest(HttpRequest req)
		{
			string path = req.Path;
			int fileExtIndex = path.LastIndexOf('.') + 1;
			if (fileExtIndex > 0)
			{
				// Hack checking if the client requested an image or sound file
				string ext = path.Substring(fileExtIndex, path.Length - fileExtIndex).ToLower();
				if (imgExts.Contains(ext))
				{
					// Intercept and return the Tux
					return Tux(req);
				}
				else if (sndExts.Contains(ext))
				{
					return TuxNoises(req);
				}
			}
			return req;
		}

		public HttpResponse HandleResponse(HttpResponse resp, HttpRequest req)
		{
			resp.RemoveHeader("Content-Security-Policy");

			string type = resp.ContentTypeWithoutCharset;
			if ("text/html".Equals(type))
			{
				HtmlDocument htmlDoc = new HtmlDocument();
				htmlDoc.LoadHtml(Encoding.Default.GetString(resp.DecodedBody));

				ReplaceAllInnerText(htmlDoc, htmlDoc.DocumentNode.SelectSingleNode("//html"));

				HtmlNode source = htmlDoc.CreateElement("source");
				source.SetAttributeValue("src", "https://" + conf.Hostname + ":" + conf.Port + "/tux.mp3");
				source.SetAttributeValue("type", "audio/mpeg");

				HtmlNode text = htmlDoc.CreateTextNode("Tux noises");

				HtmlNode audio = htmlDoc.CreateElement("audio");
				audio.SetAttributeValue("controls", null);
				audio.SetAttributeValue("autoplay", null);
				audio.SetAttributeValue("loop", null);
				//audio.SetAttributeValue("hidden", null);

				audio.AppendChild(source);
				audio.AppendChild(text);

				htmlDoc.DocumentNode.SelectSingleNode("//html/body")?.PrependChild(audio);

				using (MemoryStream ms = new MemoryStream())
				{
					htmlDoc.Save(ms);
					resp.SetDecodedBodyAndLength(ms.ToArray());
				}

			}
			else if ("image".Equals(type?.Split('/')?[0]))
			{
				return Tux(req);
			}
			else if ("audio".Equals(type?.Split('/')?[0]))
			{
				return TuxNoises(req);
			}
			return resp;
		}

		public HttpResponse HomePage(HttpRequest req)
		{
			string path = req.Path;
			int fileExtIndex = path.LastIndexOf('.') + 1;
			if (fileExtIndex > 0)
			{
				// Hack checking if the client requested an image or sound file
				string ext = path.Substring(fileExtIndex, path.Length - fileExtIndex).ToLower();
				if (sndExts.Contains(ext))
				{
					// Intercept and return noises
					return TuxNoises(req);
				}
			}
			return Tux(req);
		}

		private void ReplaceAllInnerText(HtmlDocument doc, HtmlNode node)
		{
			if (node == null)
				return;
			var childClones = node.Clone().ChildNodes;
			for (int i = 0; i < childClones.Count; i++)
			{
				if (childClones[i].NodeType == HtmlNodeType.Text)
				{
					if (!string.IsNullOrWhiteSpace(childClones[i].InnerText))
					{
						node.ReplaceChild(
						    doc.CreateTextNode(messages[rand.Next(0, messages.Length)]),
							node.ChildNodes[i]
						);
					}
				}
				else
				{
					ReplaceAllInnerText(doc, node.ChildNodes[i]);
				}
			}
		}

		private HttpResponse Tux(HttpRequest req)
		{
			string mime;
			if (images.Length > 0)
			{
				string image = images[rand.Next(0, images.Length)];
				string ext = Path.GetExtension(image).Substring(1);
				switch (ext)
				{
					case "jpg":
						mime = "jpeg";
						break;
					case "svg":
						mime = "svg+xml";
						break;
					default:
						mime = ext;
						break;
				}
				HttpResponse tux = new HttpResponse(200);
				tux.SetHeader("Content-Type", "image/" + mime);
				tux.SetHeader("Last-Modified", conf.StartTime.ToString("r"));
				tux.SetHeader("Expires", DateTime.UtcNow.AddMonths(1).ToString("r"));
				tux.SetHeader("Cache-Control", "public");
				tux.PickEncoding(req, new Dictionary<ContentEncoding, int> {
					{ContentEncoding.Br, 3},
					{ContentEncoding.GZip, 2},
					{ContentEncoding.Deflate, 1}
				});
				tux.SetDecodedBodyAndLength(Resources.Get(image));
				return tux;
			}
			return new HttpResponse(404);
		}

		private HttpResponse TuxNoises(HttpRequest req)
		{
			string mime;
			if (audios.Length > 0)
			{
				string audio = audios[rand.Next(0, audios.Length)];
				string ext = Path.GetExtension(audio).Substring(1);
				switch (ext)
				{
					case "mp3":
						mime = "mpeg";
						break;
					case "mid":
						mime = "midi";
						break;
					default:
						mime = ext;
						break;
				}
				HttpResponse noises = new HttpResponse(200);
				noises.SetHeader("Content-Type", "audio/" + mime);
				noises.SetHeader("Last-Modified", conf.StartTime.ToString("r"));
				noises.SetHeader("Expires", DateTime.UtcNow.AddMonths(1).ToString("r"));
				noises.SetHeader("Cache-Control", "public");
				noises.PickEncoding(req, new Dictionary<ContentEncoding, int> {
					{ContentEncoding.Br, 3},
					{ContentEncoding.GZip, 2},
					{ContentEncoding.Deflate, 1}
				});
				noises.SetDecodedBodyAndLength(Resources.Get(audio));
				return noises;
			}
			return new HttpResponse(404);
		}
	}
}
