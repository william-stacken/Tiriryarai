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

using Mono.Security;
using Mono.Security.X509;

namespace Tiriryarai.Crypto
{
	/// <summary>
	/// A class representing an X509 Authority Info Access Extension.
	/// </summary>
	public class AuthorityInfoAccessExtension : X509Extension
	{
		private static readonly string OCSP_OID = "1.3.6.1.5.5.7.48.1";
		private static readonly string CAISSUERS_OID = "1.3.6.1.5.5.7.48.2";

		private byte[] ocsp;
		private byte[] caIssuers;

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.AuthorityInfoAccessExtension"/> class.
		/// </summary>
		public AuthorityInfoAccessExtension() : base()
		{
			extnOid = "1.3.6.1.5.5.7.1.1";
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.AuthorityInfoAccessExtension"/> class.
		/// </summary>
		/// <param name="asn1">The raw ASN1 to parse the AIA Extension from.</param>
		public AuthorityInfoAccessExtension(ASN1 asn1) : base(asn1) { }

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.AuthorityInfoAccessExtension"/> class.
		/// </summary>
		/// <param name="extension">An extension to create the AIA Extension from.</param>
		public AuthorityInfoAccessExtension(X509Extension extension) : base(extension) { }

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.AuthorityInfoAccessExtension"/> class.
		/// </summary>
		/// <param name="ocsp">A link to an OCSP server. <example>http://ocsp.example.org:8080</example></param>
		/// <param name="caIssuers">A link to the issuer's certificate. <example>http://example.org/CA.crt</example></param>
		public AuthorityInfoAccessExtension(string ocsp, string caIssuers) : this()
		{
			OCSP = ocsp ?? throw new ArgumentNullException(nameof(ocsp));
			CAIssuers = caIssuers ?? throw new ArgumentNullException(nameof(caIssuers));
		}

		protected override void Decode()
		{
			ASN1 seq = new ASN1(extnValue.Value);
			if (seq.Tag != 0x30 || seq.Count != 2)
				throw new InvalidOperationException("Invalid AuthorityInfoAccess extension");

			ASN1 ocspSeq = seq[0];
			ASN1 caSeq = seq[1];
			if (ocspSeq.Tag != 0x30 || ocspSeq.Count != 2 || !ASN1Convert.ToOid(ocspSeq[0]).Equals(OCSP_OID) ||
				caSeq.Tag != 0x30 || caSeq.Count != 2 || !ASN1Convert.ToOid(caSeq[0]).Equals(CAISSUERS_OID))
				throw new InvalidOperationException("Invalid AuthorityInfoAccess extension");

			ASN1 ocspUrl = ocspSeq[1];
			ASN1 caIssuersUrl = caSeq[1];
			if (ocspUrl.Tag != 0x86 || caIssuersUrl.Tag != 0x86)
				throw new InvalidOperationException("Invalid AuthorityInfoAccess extension");

			ocsp = ocspUrl.Value;
			caIssuers = caIssuersUrl.Value;
		}

		protected override void Encode()
		{
			if (ocsp == null || caIssuers == null)
				throw new InvalidOperationException("Invalid AuthorityInfoAccess extension");

			ASN1 ocspSeq = new ASN1(0x30);
			ocspSeq.Add(ASN1Convert.FromOid(OCSP_OID));
			ocspSeq.Add(new ASN1(0x86, ocsp));

			ASN1 caSeq = new ASN1(0x30);
			caSeq.Add(ASN1Convert.FromOid(CAISSUERS_OID));
			caSeq.Add(new ASN1(0x86, caIssuers));

			ASN1 seq = new ASN1(0x30);
			seq.Add(ocspSeq);
			seq.Add(caSeq);

			extnValue = new ASN1(0x04);
			extnValue.Add(seq);
		}

		public override string Name
		{
			get { return "Authority Info Access"; }
		}

		public string OCSP
		{
			get { return Encoding.ASCII.GetString(ocsp); }
			set { ocsp = Encoding.ASCII.GetBytes(value); }
		}

		public string CAIssuers
		{
			get { return Encoding.ASCII.GetString(caIssuers); }
			set { caIssuers = Encoding.ASCII.GetBytes(value); }
		}

		public override string ToString()
		{
			return "OCSP=" + OCSP + Environment.NewLine + "CAIssuers=" + CAIssuers;
		}
	}
}
