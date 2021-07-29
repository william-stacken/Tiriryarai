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
using System.Reflection;

namespace Tiriryarai.Util
{
	/// <summary>
	/// A class that contains static resources used by Tiriryarai.
	/// </summary>
	static class Resources
	{
		public static readonly Assembly Assembly = typeof(Resources).Assembly;
		public static readonly Version Version = Assembly.GetName().Version;

		public static readonly string HOSTNAME = "tiriryarai";
		public static readonly string CA_ISSUER_PATH = "TiriryaraiCA.crt";
		public static readonly string OCSP_PATH = "ocsp";
		public static readonly string CRL_PATH = "revoked.crl";

		public static readonly string ROOT_CA_SUBJECT_NAME =
			"C=Tiriryarai, ST=Tiriryarai, L=Tiriryarai, O=Tiriryarai, OU=Tiriryarai CA, CN=Tiriryarai CA";
		public static readonly string CERT_SUBJECT_NAME =
			"C=Tiriryarai, O=Tiriryarai, OU=Tiriryarai CA, CN={0}";
		public static readonly string HASH_ALGORITHM = "SHA256";
		public static readonly int KEY_BITS = 2048;
		public static readonly string PFX_PASS = "secret";
		public static readonly byte[] CA_KEY_ID =
		{
			20, 65, 172, 5, 201, 49, 53, 97, 34, 122, 109, 32, 73, 230, 85, 169, 140, 11, 24, 158
		};
		public static string OCSP_CN = "TiriryaraiCA OCSP Responder";

		private static string TEMPLATE_PAGE =
			"<!DOCTYPE html>" +
			"<html>" +
			  "<head>" +
				"<title>Tiriryarai</title>" +
				"<meta charset=\"utf-8\"/>" +
			  "</head>" +
			  "<body>" +
			    "{0}" +
			  "</body>" +
			"</html>";

		public static string WELCOME_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>Welcome to Tiriryarai!</h1>" +
			"<img src=\"/favicon.ico\" alt=\"logo\"/>" +
			"<h3>Options</h3>" +
			"<ul>" +
			  "<li><a href=\"/cert\">CA Certificate</a></li>" +
			  "<li><a href=\"{0}\">Plugin Page</a></li>" +
			  "{1}" +
			"</ul>" +
			"<p>" +
			  "If you're seeing this page, it means that Tiriryarai is up and running! " +
			  "To use Tiriryarai, download the CA Certificate from the options menu, but " +
			  "<strong>PLEASE NOTE</strong> that it is downloaded insecurely using HTTP, " +
			  "(unless you are accessing this page via HTTPS already) so it is recommended " +
			  "that you download it over a trusted network, such as your own LAN. If that is " +
			  "not possible, please be aware of the risks involved with installing the certificate." +
			"</p>" +
			"<p>" +
			  "Once you have installed the certificate in your client and configured it to " +
			  "use the proxy, you can reach the secure custom MitM plugin site from the options menu." +
			"</p>"
		);

		public static string BAD_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>400 Bad Request</h1>" +
			"<p>You should check out rfc7231.</p>"
		);

		public static string AUTH_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>401 Unauthorized</h1>" +
			"<img src=\"https://" + Resources.HOSTNAME + "/favicon.ico\" alt=\"logo\"/>" +
			"<p>Please enter your credentials to access the admin pages.</p>"
		);

		public static string FORBIDDEN_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>403 Forbidden</h1>" +
			"<p>Nope.</p>"
		);

		public static string NON_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>404 Not Found</h1>" +
			"<img src=\"https://" + Resources.HOSTNAME + "/favicon.ico\" alt=\"logo\"/>" +
			"<p>That page was not found.</p>"
		);

		public static string PROXY_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>407 Proxy Authentication Required</h1>" +
			"<p>Please enter your credentials to use the proxy.</p>"
		);

		public static string ERR_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>500 Internal Server Error</h1>" +
			"<img src=\"https://" + Resources.HOSTNAME + "/favicon.ico\" alt=\"logo\"/>" +
			"<p>" +
			  "Unfortunately that which shouldn't happen just happened. " +
			  "For help, please post a description of what you did to cause this error " +
			  "<a href=\"https://github.com/william-stacken/Tiriryarai/issues\">here</a>." +
			"</p>"
		);

		public static string GATE_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>502 Bad Gateway</h1>" +
			"<img src=\"https://" + Resources.HOSTNAME + "/favicon.ico\" alt=\"logo\"/>" +
			"<p>Failed to obtain a reply from the requested host.</p>"
		);

		public static string LOG_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>Log Management</h1>" +
			"<img src=\"/favicon.ico\" alt=\"logo\"/>" +
			"<table style=\"width:100%\">" +
			  "<tr>" +
			    "<th>Host</th>" +
				"<th>Size (kiB)</th>" +
				"<th>Modified</th>" +
			    "<th>Actions</th>" +
			  "</tr>" +
			  "{0}" +
			"</table>"
		);

		public static string LOG_ENTRY =
			"<tr>" +
			  "<td><a href=\"/logs/{0}\">{0}</a></td>" +
			  "<td>{1}</td>" +
			  "<td>{2}</td>" +
			  "<td>" +
				"<form action=\"/logs?delete={0}\" method=\"post\">" +
				  "<input type=\"submit\" value=\"Delete\"/>" +
			    "</form>" +
			  "</td>" +
			"</tr>";

		public static byte[] Get(string name)
		{
			MemoryStream ms = new MemoryStream();
			Assembly.GetManifestResourceStream(name).CopyTo(ms);
			return ms.ToArray();
		}
	}
}