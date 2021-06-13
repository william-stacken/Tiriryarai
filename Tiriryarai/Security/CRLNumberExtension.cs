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
using Mono.Security.X509;

namespace Tiriryarai.Crypto
{
	/// <summary>
	/// A class representing an X509 CRL Number Extension.
	/// </summary>
	public class CRLNumberExtension : X509Extension
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.CRLNumberExtension"/> class.
		/// </summary>
		public CRLNumberExtension() : base()
		{
			extnOid = "2.5.29.20";
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.CRLNumberExtension"/> class.
		/// </summary>
		/// <param name="asn1">The raw ASN1 to parse the CRL Number Extension from.</param>
		public CRLNumberExtension(ASN1 asn1) : base(asn1) { }

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.CRLNumberExtension"/> class.
		/// </summary>
		/// <param name="extension">An Extension to create the CRL Number Extension from.</param>
		public CRLNumberExtension(X509Extension extension) : base(extension) { }

		protected override void Decode()
		{
			ASN1 integer = new ASN1(extnValue.Value);
			if (integer.Tag != 0x02)
				throw new InvalidOperationException("Invalid CrlNumber extension");

			Number = ASN1Convert.ToInt32(integer);
		}

		protected override void Encode()
		{
			if (Number == null)
				throw new InvalidOperationException("Invalid CrlNumber extension");

			extnValue = new ASN1(0x04);
			extnValue.Add(ASN1Convert.FromInt32((int)Number));
		}

		public override string Name
		{
			get { return "Crl Number"; }
		}

		public int? Number { get; set; }

		public override string ToString()
		{
			return "CrlNumber=" + Number;
		}
	}
}
