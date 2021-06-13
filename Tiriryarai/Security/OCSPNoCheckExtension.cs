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
	/// A class representing an X509 OCSP No Check Extension.
	/// </summary>
	public class OCSPNoCheckExtension : X509Extension
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.OCSPNoCheckExtension"/> class.
		/// </summary>
		public OCSPNoCheckExtension() : base()
		{
			extnOid = "1.3.6.1.5.5.7.48.1.5";
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.OCSPNoCheckExtension"/> class.
		/// </summary>
		/// <param name="asn1">The raw ASN1 to parse the OCSP No Check Extension.</param>
		public OCSPNoCheckExtension(ASN1 asn1) : base(asn1) { }

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.OCSPNoCheckExtension"/> class.
		/// </summary>
		/// <param name="extension">An extension to create the OCSP No Check Extension from.</param>
		public OCSPNoCheckExtension(X509Extension extension) : base(extension) { }

		protected override void Decode()
		{
			ASN1 nul = new ASN1(extnValue.Value);
			if (nul.Tag != 0x05)
				throw new InvalidOperationException("Invalid OCSPNoCheck extension");
		}

		protected override void Encode()
		{
			extnValue = new ASN1(0x04);
			extnValue.Add(new ASN1(0x05));
		}

		public override string Name
		{
			get { return "OCSP No Check"; }
		}

		public override string ToString()
		{
			return "OCSPNoCheck";
		}
	}
}
