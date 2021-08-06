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
		public static Version Version
		{
			get
			{
				Version v = Assembly.GetName().Version;
				return new Version(v.Major, v.Minor);
			}
		}

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
		public static readonly string HARDCODED_PFX_PASS = "secret";
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
			"<a href=\"/\"><img src=\"/favicon.ico\" alt=\"logo\"/></a>" +
			"<h3>Options</h3>" +
			"<ul>" +
			  "<li><a href=\"/cert\">CA Certificate</a></li>" +
			  "<li><a href=\"{0}\">Plugin Page</a></li>" +
			  "{1}" +
			"</ul>" +
			"<p>" +
			  "If you're seeing this page, it means that you have configured the proxy properly " +
			  "in your client! To use Tiriryarai, download the CA Certificate from the options " +
			  "menu, but <strong>PLEASE NOTE</strong> that it is downloaded insecurely using HTTP, " +
			  "(unless you are accessing this page via HTTPS already) so it is recommended that you " +
			  "download it over a trusted network, such as your own LAN. If that is not possible, " +
			  "please be aware of the risks involved with installing the certificate." +
			"</p>" +
			"<p>" +
			  "Once you have installed the certificate in your client, you can proxy HTTPS requests " +
			  "using Tiriryarai and reach the secure custom MitM plugin site from the options menu." +
			"</p>"
		);

		public static string BAD_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>400 Bad Request</h1>" +
			"<p>You should check out rfc7231.</p>"
		);

		public static string AUTH_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>401 Unauthorized</h1>" +
			"<a href=\"https://" + HOSTNAME + "\"><img src=\"https://" + HOSTNAME + "/favicon.ico\" alt=\"logo\"/></a>" +
			"<p>Please enter your credentials to access the admin pages.</p>"
		);

		public static string FORBIDDEN_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>403 Forbidden</h1>" +
			"<p>Nope.</p>"
		);

		public static string NON_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>404 Not Found</h1>" +
			"<a href=\"https://" + HOSTNAME + "\"><img src=\"https://" + HOSTNAME + "/favicon.ico\" alt=\"logo\"/></a>" +
			"<p>That page was not found.</p>"
		);

		public static string METHOD_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>405 Method Not Allowed</h1>" +
			"<a href=\"https://" + HOSTNAME + "\"><img src=\"https://" + HOSTNAME + "/favicon.ico\" alt=\"logo\"/></a>" +
			"<p>Sorry, you can't do that.</p>"
		);

		public static string PROXY_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>407 Proxy Authentication Required</h1>" +
			"<p>Please enter your credentials to use the proxy.</p>"
		);

		public static string TIMEOUT_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>408 Request Timeout</h1>" +
			"<p>Tiriryarai fell asleep.</p>"
		);

		public static string MEDIA_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>415 Unsupported Media Type</h1>" +
			"<a href=\"https://" + HOSTNAME + "\"><img src=\"https://" + HOSTNAME + "/favicon.ico\" alt=\"logo\"/></a>" +
			"<p>The provided entity body is not short and stout.</p>"
		);

		public static string ERR_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>500 Internal Server Error</h1>" +
			"<a href=\"https://" + HOSTNAME + "\"><img src=\"https://" + HOSTNAME + "/favicon.ico\" alt=\"logo\"/></a>" +
			"<p>{0}</p>"
		);

		public static string GATE_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>502 Bad Gateway</h1>" +
			"<a href=\"https://" + HOSTNAME + "\"><img src=\"https://" + HOSTNAME + "/favicon.ico\" alt=\"logo\"/></a>" +
			"<p>The requested host sent an illegitimate response.</p>"
		);

		public static string DOWN_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>503 Service Unavailable</h1>" +
			"<p>{0}</p>"
		);

		public static string GATE_TIMEOUT_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>504 Gateway Timeout</h1>" +
			"<a href=\"https://" + HOSTNAME + "\"><img src=\"https://" + HOSTNAME + "/favicon.ico\" alt=\"logo\"/></a>" +
			"<p>Failed to obtain a reply from the requested host.</p>"
		);

		public static string GENERIC_ERR_MSG =
			"Unfortunately an error has occured in cyberspace. " +
			"For help, please post a description of what you did to cause this error " +
			"<a href=\"https://github.com/william-stacken/Tiriryarai/issues\">here</a>.";

		public static string LOG_ERR_MSG =
			"The log file could not be read. This may mean that the log is corrupt, or " +
			"that Tiriryarai does not have the correct password required to decrypt it. " +
			"You can attempt to change the configured password and try to view the log again. " +
			"Otherwise you must delete it as there is no other way to recover it.";

		public static string CACHE_CLEAR_MSG =
			"Tiriryarai is currently undergoing maintenance to clear the internal cache. " +
			"Please wait for (hopefully) a few seconds, then go to the <a href=\"http://" +
			Resources.HOSTNAME + "\">welcome page</a> and install the new CA certificate.";

		public static string LOG_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>Log Management</h1>" +
			"<a href=\"/\"><img src=\"/favicon.ico\" alt=\"logo\"/></a>" +
			"<table style=\"width:100%\">" +
			  "<tr>" +
				"<th><strong>Host</strong></th>" +
				"<th><strong>Size (kiB)</strong></th>" +
				"<th><strong>Modified</strong></th>" +
				"<th><strong>Actions</strong></th>" +
			  "</tr>" +
			  "{0}" +
			"</table>" +
			"<div style=\"margin-top:30px\">" +
			  "<form method=\"post\" action=\"/logs\">" +
			    "<input type=\"submit\" name=\"deleteall\" value=\"Delete All\"/>" +
				"<input style=\"margin-left:50px\" type=\"checkbox\" name=\"sure\" id=\"sure\"/>" +
			    "<label for=\"sure\">I am sure</label>" +
			  "</form>" +
			"</div>"
		);

		public static string LOG_ENTRY =
			"<tr>" +
			  "<td><a href=\"/logs/{0}\">{0}</a></td>" +
			  "<td>{1}</td>" +
			  "<td>{2}</td>" +
			  "<td>" +
				"<form action=\"/logs/{0}\" method=\"post\">" +
				  "<input type=\"submit\" name=\"submit\" value=\"Delete\"/>" +
			    "</form>" +
			  "</td>" +
			"</tr>";

		public static string CONFIG_PAGE = string.Format(TEMPLATE_PAGE,
			"<h1>Tiriryarai Configuration</h1>" +
			"<a href=\"/\"><img src=\"/favicon.ico\" alt=\"logo\"/></a>" +
			"{0}" +
			"<p>" +
			  "Here you can update the proxy configuration. Fields that are left empty will " +
			  "be reset to their default value. Note that when the form is submitted, invalid " +
			  "fields will be ignored, but valid fields will still update the configuration." +
			"</p>" +
			"<p><strong>" +
			  "Much of the configuration CANNOT be reverted once updated. Please read through the " +
			  "information carefully before making changes and make sure you know what you are doing." +
			"</strong></p>" +
			"<form method=\"post\" action=\"/config\">" +
			  "<table style=\"width:100%\">" +
				"<tr>" +
				  "<td><strong>Property</strong></td>" +
				  "<td><strong>Value</strong></td>" +
				  "<td><strong>Info</strong></td>" +
			    "</tr>" +
			    "{1}" +
			  "</table>" +
			  "<input type=\"reset\">" +
			  "<input type=\"submit\" name=\"submit\" value=\"Save\"/>" +
			"</form>"
		);

		public static string CONFIG_ENTRY =
			"<tr>" +
			  "<td><label for=\"{0}\">{1}</label></td>" +
			  "<td><input type=\"{2}\" id=\"{0}\" name=\"{0}\" {3}></td>" +
			  "<td>{4}</td>" +
			"</tr>";

		public static byte[] Get(string name)
		{
			MemoryStream ms = new MemoryStream();
			Assembly.GetManifestResourceStream(name).CopyTo(ms);
			return ms.ToArray();
		}
	}
}