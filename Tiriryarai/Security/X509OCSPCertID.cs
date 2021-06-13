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
	/// A class representing an X509 OCSP CertID used in OCSP
	/// requests and responses.
	/// </summary>
	public class X509OCSPCertID
	{
		public string AlgorithmOid { get; set; }

		public byte[] IssuerNameHash { get; set; }

		public byte[] IssuerKeyHash { get; set; }

		public byte[] SerialNumber { get; set; }

		/// <summary>
		/// Gets or sets the ASN1 representation of the CertID
		/// </summary>
		/// <value>The ASN.</value>
		public ASN1 ASN1
		{
			get
			{
				ASN1 seq = new ASN1(0x30);
				seq.Add(PKCS7.AlgorithmIdentifier(AlgorithmOid));
				seq.Add(new ASN1(0x4, IssuerNameHash));
				seq.Add(new ASN1(0x4, IssuerKeyHash));
				seq.Add(new ASN1(0x2, SerialNumber));
				return seq;
			}
			set
			{
				if (value == null)
					throw new ArgumentNullException(nameof(value));
				if (value.Tag != 0x30 || value.Count < 4 || value[0].Count < 1)
					throw new ArgumentException("Invalid OCSP CertID");

				AlgorithmOid = ASN1Convert.ToOid(value[0][0]);
				IssuerNameHash = value[1].Value;
				IssuerKeyHash = value[2].Value;
				SerialNumber = value[3].Value;
			}
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509OCSPCertID"/> class.
		/// </summary>
		/// <param name="nameHash">The SHA1 hash of the DER encoding of the issuer's name field.</param>
		/// <param name="keyHash">The SHA1 hash of the value of the issuer's public key field.</param>
		/// <param name="sn">The serial number of the certificate whose status is being checked.</param>
		public X509OCSPCertID(byte[] nameHash, byte[] keyHash, byte[] sn) :
			this(nameHash, keyHash, sn, "1.2.840.113549.1.1.5") { } // SHA1 hashoid

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509OCSPCertID"/> class.
		/// </summary>
		/// <param name="nameHash">The hash of the DER encoding of the issuer's name field.</param>
		/// <param name="keyHash">The hash of the value of the issuer's public key field.</param>
		/// <param name="sn">The serial number of the certificate whose status is being checked.</param>
		/// <param name="hashoid">The OID of the hash algorithm used to generate the hashes.</param>
		public X509OCSPCertID(byte[] nameHash, byte[] keyHash, byte[] sn, string hashoid)
		{
			AlgorithmOid = hashoid ?? throw new ArgumentNullException(nameof(hashoid));
			IssuerNameHash = nameHash ?? throw new ArgumentNullException(nameof(nameHash));
			IssuerKeyHash = keyHash ?? throw new ArgumentNullException(nameof(keyHash));
			SerialNumber = sn ?? throw new ArgumentNullException(nameof(sn));
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509OCSPCertID"/> class.
		/// </summary>
		/// <param name="asn">The raw ASN1 to parse the OCSP CertID from.</param>
		public X509OCSPCertID(ASN1 asn)
		{
			ASN1 = asn;
		}

		public X509OCSPCertID(X509Certificate subject, X509Certificate issuer, byte[] sn) =>
			// TODO Calculate the IssuerNameHash from the Issuer filed of the subject
			// and calculate the IssuerKeyHash from the public key of the issuer
			throw new NotImplementedException("TODO");

		/// <summary>
		/// Returns a <see cref="T:System.String"/> that represents the current <see cref="T:Tiriryarai.Crypto.X509OCSPCertID"/>.
		/// </summary>
		/// <returns>A <see cref="T:System.String"/> that represents the current <see cref="T:Tiriryarai.Crypto.X509OCSPCertID"/>.</returns>
		public override string ToString()
		{
			return "HashAlgorithm=" + AlgorithmOid + Environment.NewLine +
				   "IssuerNameHash=" + BitConverter.ToString(IssuerNameHash).Replace("-", " ") + Environment.NewLine +
				   "IssuerKeyHash=" + BitConverter.ToString(IssuerKeyHash).Replace("-", " ") + Environment.NewLine +
				   "SerialNumber=" + BitConverter.ToString(SerialNumber).Replace("-", " ");
		}
	}
}
