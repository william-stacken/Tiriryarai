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
using System.Text;
using System.Globalization;

using Mono.Security;
using Mono.Security.X509;

namespace Tiriryarai.Crypto
{
	/// <summary>
	/// A class representing a single OCSP response, used for
	/// reporting the revocation status of a single certificate.
	/// </summary>
	public class X509OCSPSingleResponse
	{
		/// <summary>
		/// Revocation statuses of certificates used in single OCSP responses.
		/// </summary>
		[Flags]
		public enum CertStatus
		{
			Good = 0,
			Revoked = 1,
			Unknown = 2
		}

		public X509OCSPCertID CertificateID { get; set; }

		public CertStatus CertificateStatus { get; set; }

		public DateTime ThisUpdate { get; set; }

		public DateTime NextUpdate { get; set; }

		public X509ExtensionCollection Extensions { get; }

		/// <summary>
		/// Gets or sets the ASN representation of the Single OCSP Response.
		/// </summary>
		/// <value>The ASN.</value>
		public ASN1 ASN1
		{
			get
			{
				ASN1 seq = new ASN1(0x30);
				seq.Add(CertificateID.ASN1);
				seq.Add(new ASN1((byte)(0x80 + CertificateStatus))); // TODO Add RevokedInfo sequence if cert was revoked
				seq.Add(new ASN1(0x18, Encoding.ASCII.GetBytes(
					ThisUpdate.ToUniversalTime().ToString("yyyyMMddHHmmss",
					CultureInfo.InvariantCulture) + "Z"))); // TODO This should really exist in ASN1Convert already, move this to function somewhere

				ASN1 nextUpd = new ASN1(0xA0);
				nextUpd.Add(new ASN1(0x18, Encoding.ASCII.GetBytes(
					NextUpdate.ToUniversalTime().ToString("yyyyMMddHHmmss",
					CultureInfo.InvariantCulture) + "Z")));
				seq.Add(nextUpd);

				if (Extensions.Count > 0)
					seq.Add(new ASN1(0xA1, Extensions.GetBytes()));

				return seq;
			}
			set
			{
				if (value == null)
					throw new ArgumentNullException(nameof(value));
				if (value.Tag != 0x30 || value.Count < 3 || value[1].Tag < 0x80 || value[1].Tag > 0x82)
					throw new ArgumentException("Invalid OCSP CertID");

				CertificateID = new X509OCSPCertID(value[0]);
				CertificateStatus = (CertStatus)(value[1].Tag - 0x80);
				ThisUpdate = ASN1Convert.ToDateTime(value[2]);

				if (value.Count > 3 && value[3].Count > 0)
				{
					NextUpdate = ASN1Convert.ToDateTime(value[3][0]);

					// TODO Extensions are untested and may not work
					Extensions.Clear();
					if (value.Count > 4)
					{
						value = value[4];
						for (int i = 0; i < value.Count; i++)
						{
							Extensions.Add(new X509Extension(value[i]));
						}
					}
				}
			}
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509OCSPSingleResponse"/> class.
		/// </summary>
		/// <param name="certID">The <see cref="T:Tiriryarai.Crypto.X509OCSPCertID"/> of the single OCSP response.</param>
		/// <param name="status">The status of the certificate identified by the CertID.</param>
		/// <param name="thisUpd">The time at which this single OCSP response became valid.</param>
		/// <param name="nextUpd">The time at which this single OCSP response expires.</param>
		public X509OCSPSingleResponse(X509OCSPCertID certID, CertStatus status, DateTime thisUpd, DateTime nextUpd)
		{
			CertificateID = certID ?? throw new ArgumentNullException(nameof(certID));
			CertificateStatus = status;
			ThisUpdate = thisUpd;
			NextUpdate = nextUpd;
			Extensions = new X509ExtensionCollection();
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509OCSPSingleResponse"/> class.
		/// </summary>
		/// <param name="asn">The raw ASN1 to parse the Single OCSP Response from.</param>
		public X509OCSPSingleResponse(ASN1 asn)
		{
			Extensions = new X509ExtensionCollection();
			ASN1 = asn;
		}
	}
}
