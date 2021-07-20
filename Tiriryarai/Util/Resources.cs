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

using System.IO;

namespace Tiriryarai.Util
{
	/// <summary>
	/// A class that contains static resources used by Tiriryarai.
	/// </summary>
	static class Resources
	{
		public static readonly string CA_ISSUER_PATH = "/TiriryaraiCA.crt";
		public static readonly string OCSP_PATH = "/ocsp";
		public static readonly string CRL_PATH = "/revoked.crl";

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

		public static string WELCOME_PAGE =
			"<!DOCTYPE html>" +
			"<html>" +
			  "<head>" +
				"<title>Tiriryarai</title>" +
				"<meta charset=\"utf-8\"/>" +
			  "</head>" +
			  "<body>" +
				"<h1>Welcome to Tiriryarai!</h1>" +
				"<img src=\"/favicon.ico\" alt=\"logo\"/>" +
				"<p>" +
				  "If you're seeing this page, it means that Tiriryarai is up and running! " +
				  "To use Tiriryarai, download the <a href=\"/cert\">CA Certificate</a>, but " +
				  "<strong>PLEASE NOTE</strong> that it is downloaded insecurely using HTTP, so " +
				  "it is recommended that you download it over a trusted network, such as your " +
				  "own LAN. If that is not possible, please be aware of the risks involved with " +
				  "installing the certificate." +
				"</p>" +
				"<p>" +
				  "Once you have installed the certificate in your client and configured it to " +
				  "use the proxy, you can reach the secure custom MitM site <a href=\"https://{0}:{1}\">here</a>." +
				  "(Or if the link doesn't work, try inputting thr URL manually.)" +
				"</p>" +
			  "</body>" +
			"</html>";

		public static byte[] Get(string name)
		{
			MemoryStream ms = new MemoryStream();
			typeof(Resources).Assembly.GetManifestResourceStream(name).CopyTo(ms);
			return ms.ToArray();
		}
	}
}