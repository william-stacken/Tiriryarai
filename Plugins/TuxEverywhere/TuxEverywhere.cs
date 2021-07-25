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
			"jpg", "png", "svg", "gif", "bmp", "ico"
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
			"Windows-tan is shit-tier wifu"
		};

		public void Initialize(string configDir) { }

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
				// Hack checking if the client requested an image
				if (imgExts.Contains(path.Substring(fileExtIndex, path.Length - fileExtIndex).ToLower()))
				{
					// Intercept and return the Tux
					return Tux(req);
				}
			}
			return req;
		}

		public HttpResponse HandleResponse(HttpResponse resp, HttpRequest req)
		{
			string type = resp.GetHeader("Content-Type")?[0];
			type = type != null ? type.Split(';')[0].ToLower() : null;
			if ("text/html".Equals(type))
			{
				HtmlDocument htmlDoc = new HtmlDocument();
				htmlDoc.LoadHtml(Encoding.Default.GetString(resp.DecodedBody));

				ReplaceAllInnerText(htmlDoc, htmlDoc.DocumentNode.SelectSingleNode("//html"));
				using (MemoryStream ms = new MemoryStream())
				{
					htmlDoc.Save(ms);
					resp.SetDecodedBodyAndLength(ms.ToArray());
				}

			}
			else if ("image".Equals(type?.Split('/')[0]))
			{
				return Tux(req);
			}
			return resp;
		}

		public HttpResponse HomePage(HttpRequest req)
		{
			return Tux(req);
		}

		private HttpResponse Tux(HttpRequest req)
		{
			HttpResponse tux = new HttpResponse(200);
			tux.SetHeader("Content-Type", "image/svg+xml");
			tux.PickEncoding(req, new Dictionary<ContentEncoding, int> {
				{ContentEncoding.Br, 3},
				{ContentEncoding.GZip, 2},
				{ContentEncoding.Deflate, 1}
			});
			tux.SetDecodedBodyAndLength(Resources.Get("tux.svg"));
			return tux;
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
	}
}
