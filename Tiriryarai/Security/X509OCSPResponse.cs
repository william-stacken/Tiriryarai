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
using System.Security.Cryptography.X509Certificates;

using Mono.Security;
using Mono.Security.X509;

namespace Tiriryarai.Crypto
{
	/// <summary>
	/// Class representing an OCSP Response.
	/// </summary>
	public class X509OCSPResponse
	{
		private static readonly string TYPE_BASIC_OID = "1.3.6.1.5.5.7.48.1.1";

		/// <summary>
		/// OCSP Response status codes.
		/// </summary>
		[Flags]
		public enum ResponseStatus
		{
			Successful = 0,
			MalformedRequest = 1,
			InternalError = 2,
			TryLater = 3,
			SigRequired = 5,
			Unauthorized = 6
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509OCSPResponse"/> class.
		/// </summary>
		/// <param name="status">The status of the OCSP response.</param>
		public X509OCSPResponse(ResponseStatus status)
		{
			Status = status;
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509OCSPResponse"/> class.
		/// </summary>
		/// <param name="status">The status of the OCSP response.</param>
		/// <param name="resp">A builder object of an OCSP response type. Only the Basic OCSP Response type is supported.</param>
		public X509OCSPResponse(ResponseStatus status, X509Builder resp)
		{
			if (resp is X509BasicOCSPResponseBuilder _)
			{
				Response = resp;
				Type = TYPE_BASIC_OID;
			}
			else
			{
				throw new ArgumentException("Unsupported response type");
			}
			Status = status;
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509OCSPResponse"/> class.
		/// </summary>
		/// <param name="encoded">The signed OCSP Response to instanciate the class from.</param>
		public X509OCSPResponse(byte[] encoded)
		{
			raw = (byte[])encoded.Clone();

			ASN1 asn = new ASN1(encoded);

			if (asn.Tag != 0x30 || asn.Count != 2 ||
				asn[0].Tag != 0x0A || asn[0].Value.Length != 1 ||
				asn[1].Tag != 0xA0 || asn[1].Count < 1 ||
				asn[1][0].Tag != 0x30 || asn[1][0].Count != 2)
				throw new ArgumentException("Invalid X509OCSPResponse");

			Status = (ResponseStatus)asn[0].Value[0];
			ASN1 oid = asn[1][0][0];
			if (oid.Tag != 0x06)
				throw new Exception();
			Type = ASN1Convert.ToOid(oid);
			ASN1 response = asn[1][0][1];
			if (response.Tag != 0x04)
				throw new Exception();

			if (TYPE_BASIC_OID.Equals(Type))
			{
				Response = new X509BasicOCSPResponseBuilder(response.Value);
			}
			else
			{
				throw new ArgumentException("Unsupported response type");
			}
		}

		private byte[] raw;

		/// <summary>
		/// Gets the raw, signed, data of the OCSP Response. May only be
		/// retreived if the OCSP Response has already been signed. Otherwise,
		/// <code>Sign()</code> should be called instead.
		/// </summary>
		/// <value>The raw data.</value>
		public byte[] RawData { get { return raw ?? throw new Exception("No signature found, please call Sign() instead"); } }

		public X509Builder Response { get; }

		public ResponseStatus Status { get; }

		public string Type { get; }

		/// <summary>
		/// Encodes the general header and signs the remaining OCSP response using
		/// the given certificate's private key.
		/// </summary>
		/// <returns>The encoded, signed OCSP response.</returns>
		/// <param name="cert">The certificate whose private key should be used for signing.</param>
		public byte[] Sign(X509Certificate2 cert)
		{
			ASN1 seq = new ASN1(0x30);
			seq.Add(new ASN1(0x0A, new byte[] { (byte)Status }));

			if (Response != null)
			{
				ASN1 response = new ASN1(0x30);
				response.Add(ASN1Convert.FromOid(Type));

				byte[] resp = Response.Sign(cert.PrivateKey);
				response.Add(new ASN1(0x04, resp));

				ASN1 responseBytes = new ASN1(0xA0);
				responseBytes.Add(response);

				seq.Add(responseBytes);
			}

			return seq.GetBytes();
		}
	}
}
