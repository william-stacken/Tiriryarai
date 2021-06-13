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
	/// A builder class for creating an X509 certificate revocation list.
	/// </summary>
	public class X509CRLBuilder : X509Builder
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509CRLBuilder"/> class
		/// with the default version.
		/// </summary>
		public X509CRLBuilder() : this(1) { }

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509CRLBuilder"/> class.
		/// </summary>
		/// <param name="version">The version of the CRL.</param>
		public X509CRLBuilder(byte version)
		{
			if (version > 1) // TODO what is the max version?
				throw new ArgumentException("Invalid CRL version");
			Version = version;
			Extensions = new X509ExtensionCollection();
		}

		public byte Version { get; set; }

		public string Issuer { get; set; }

		public DateTime ThisUpdate { get; set; }

		public DateTime NextUpdate { get; set; }

		public X509ExtensionCollection Extensions { get; }

		// TODO: Add certificate entries

		protected override ASN1 ToBeSigned(string hashName)
		{
			ASN1 toBeSigned = new ASN1(0x30);
			toBeSigned.Add(ASN1Convert.FromInt32(Version)); // TODO Is this the right way to encode it?
			toBeSigned.Add(PKCS7.AlgorithmIdentifier(hashName));
			toBeSigned.Add(X501.FromString(Issuer));
			toBeSigned.Add(ASN1Convert.FromDateTime(ThisUpdate)); // TODO UTCTime or Generalized Time? 0x17 or 0x18?
			toBeSigned.Add(ASN1Convert.FromDateTime(NextUpdate));
			if (Extensions.Count > 0)
				toBeSigned.Add(new ASN1(0xA0, Extensions.GetBytes()));

			return toBeSigned;
		}
	}
}
