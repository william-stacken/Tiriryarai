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

namespace Tiriryarai.Util
{
	/// <summary>
	/// Class for containing URLs commonly contained in X509 Certificates.
	/// </summary>
	public class X509CertificateUrls
	{
		public string CAIssuer { get; }
		public string Ocsp { get; }
		public string Crl { get; }

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Util.X509CertificateUrls"/> class.
		/// </summary>
		/// <param name="caIssuer">The URL to the issuer certificate.</param>
		/// <param name="ocsp">The URL to the OCSP server.</param>
		/// <param name="crl">The URL to the certificate revocation list.</param>
		public X509CertificateUrls(string caIssuer, string ocsp, string crl)
		{
			CAIssuer = caIssuer;
			Ocsp = ocsp;
			Crl = crl;
		}
	}
}
