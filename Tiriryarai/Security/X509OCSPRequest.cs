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

using Mono.Security;

namespace Tiriryarai.Crypto
{
	// TODO Very minimal implementation, most fields ignored

	public class X509OCSPRequest
	{
		public X509OCSPCertID CertificateID { get; }

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509OCSPRequest"/> class.
		/// </summary>
		/// <param name="certId">The <see cref="T:Tiriryarai.Crypto.X509OCSPCertID"/> of the OCSP Request.</param>
		public X509OCSPRequest(X509OCSPCertID certId)
		{
			CertificateID = certId ?? throw new ArgumentNullException(nameof(certId));
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509OCSPRequest"/> class.
		/// </summary>
		/// <param name="encoded">The encoded OCSP request to parse.</param>
		public X509OCSPRequest(byte[] encoded)
		{
			ASN1 asn = new ASN1(encoded);
			if (asn.Tag != 0x30)
				throw new ArgumentException("Invalid X509OCSPRequest");

			bool foundSequence = true;

			for (int i = 0; foundSequence && i < 4; i++) // Ignore everything except CertID
			{
				foundSequence = false;
				for (int j = 0; j < asn.Count; j++)
				{
					if (asn[j].Tag == 0x30)
					{
						asn = asn[j];
						foundSequence = true;
						break;
					}
				}
			}
			if (!foundSequence)
				throw new ArgumentException("Invalid X509OCSPRequest");

			CertificateID = new X509OCSPCertID(asn);
		}
	}
}
