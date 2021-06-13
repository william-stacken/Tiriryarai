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
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Mono.Security;
using Mono.Security.X509;

using X509ExtensionCollection = Mono.Security.X509.X509ExtensionCollection;

namespace Tiriryarai.Crypto
{
	/// <summary>
	/// A builder class for creating an X509 Basic OCSP Response used for
	/// assessing the revocation status of an X509 Certificate.
	/// </summary>
	public class X509BasicOCSPResponseBuilder : X509Builder
	{
		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509BasicOCSPResponseBuilder"/> class
		/// with the default version.
		/// </summary>
		public X509BasicOCSPResponseBuilder() : this(1) { }

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509BasicOCSPResponseBuilder"/> class.
		/// </summary>
		/// <param name="version">The version of the Basic OCSP Response.</param>
		public X509BasicOCSPResponseBuilder(byte version)
		{
			if (version > 1) // TODO what is the max version?
				throw new ArgumentException("Invalid Basic OCSP Response version");
			Version = version;
			Extensions = new X509ExtensionCollection();
			singleResps = new List<X509OCSPSingleResponse>();
			certs = new List<X509Certificate2>();
		}

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Crypto.X509BasicOCSPResponseBuilder"/> class.
		/// </summary>
		/// <param name="encoded">The signed Basic OCSP Response to instanciate the class from.</param>
		public X509BasicOCSPResponseBuilder(byte[] encoded)
		{
			raw = (byte[])encoded.Clone();

			ASN1 asn = new ASN1(encoded);
			if (asn.Tag != 0x30 || asn.Count < 3)
				throw new Exception();

			ASN1 tbs = asn[0];
			if (tbs.Tag != 0x30 || tbs.Count < 3)
				throw new Exception();

			int i = 0;
			if (tbs[i].Tag == 0xA0 && tbs[i].Value.Length > 0)
			{
				Version = tbs[i++].Value[0];
			}
			else
			{
				Version = 1;
			}
			if (tbs[i].Count != 1)
				throw new Exception();
			switch (tbs[i].Tag)
			{
				case 0xA1:
					Name = X501.ToString(tbs[i++][0]);
					break;
				case 0xA2:
					KeyHash = tbs[i++][0].Value;
					break;
				default:
					throw new Exception();
			}
			if (tbs[i].Tag != 0x17 && tbs[i].Tag != 0x18)
				throw new Exception();
			ProducedAt = ASN1Convert.ToDateTime(tbs[i++]);
			Extensions = new X509ExtensionCollection();
			singleResps = new List<X509OCSPSingleResponse>();
			certs = new List<X509Certificate2>();

			if (i < tbs.Count)
			{
				if (tbs[i].Tag != 0x30)
					throw new Exception();
				for (int j = 0; j < tbs[i].Count; j++)
				{
					singleResps.Add(new X509OCSPSingleResponse(tbs[i][j]));
				}
				i++;
				if (i < tbs.Count && tbs[i].Tag == 0xA0 && tbs[i].Count > 0)
				{
					Extensions = new X509ExtensionCollection(tbs[i][0]);
				}
			}
			if (asn.Count > 3 && asn[3].Tag == 0xA0 && asn[3].Count > 0 && asn[3][0].Tag == 0x30)
			{
				ASN1 certList = asn[3][0];
				for (int j = 0; j < certList.Count; j++)
				{
					certs.Add(new X509Certificate2(certList[j].GetBytes()));
				}
			}
		}

		private readonly byte[] raw;

		/// <summary>
		/// Gets the raw, signed, data of the Basic OCSP Response. May only be
		/// retreived if the Basic OCSP Response has already been signed. Otherwise,
		/// <code>Sign()</code> should be called instead.
		/// </summary>
		/// <value>The raw data.</value>
		public byte[] RawData { get { return raw ?? throw new Exception("No signature found, please call Sign() instead"); } }

		public byte Version { get; set; }

		private string name;

		/// <summary>
		/// Gets or sets the name. If the name is set, the <code>KeyHash</code>
		/// will be erased.
		/// </summary>
		/// <value>The name.</value>
		public string Name
		{
			get { return name; }
			set { keyHash = null;  name = value; }
		}

		private byte[] keyHash;

		/// <summary>
		/// Gets or sets the key hash. If the key hash is set, the <code>Name</code>
		/// will be erased.
		/// </summary>
		/// <value>The key hash.</value>
		public byte[] KeyHash
		{
			get { return keyHash; }
			set { name = null; keyHash = value; }
		}

		public DateTime ProducedAt { get; set; }

		private List<X509OCSPSingleResponse> singleResps;

		public IEnumerable<X509OCSPSingleResponse> SingleResponses
		{
			get { return singleResps; }
		}

		public X509ExtensionCollection Extensions { get; }

		public List<X509Certificate2> certs;

		public IEnumerable<X509Certificate2> CertificateChain
		{
			get { return certs; }
		}

		public void AddSingleResponse(X509OCSPSingleResponse singleResp)
		{
			singleResps.Add(singleResp ?? throw new ArgumentNullException(nameof(singleResp)));
		}

		public void AddCertificate(X509Certificate2 cert)
		{
			certs.Add(cert ?? throw new ArgumentNullException(nameof(cert)));
		}

		protected override ASN1 ToBeSigned(string hashName)
		{
			ASN1 toBeSigned = new ASN1(0x30);
			if (Version > 1)
			{
				// TODO How are versions specified?
				toBeSigned.Add(new ASN1(0xA0, new byte[] { Version }));
			}
			ASN1 responder;
			if (Name != null)
			{
				responder = new ASN1(0xA1);
				responder.Add(X501.FromString(Name)); // TODO Is this correct, IDK?
			}
			else
			{
				responder = new ASN1(0xA2);
				responder.Add(new ASN1(0x04, KeyHash));
			}
			toBeSigned.Add(responder);

			toBeSigned.Add(new ASN1(0x18, Encoding.ASCII.GetBytes(
					ProducedAt.ToUniversalTime().ToString("yyyyMMddHHmmss",
					CultureInfo.InvariantCulture) + "Z"))); // TODO This should really exist in ASN1Convert already, move this to a function somewhere

			ASN1 responses = new ASN1(0x30);
			foreach (X509OCSPSingleResponse singleResp in singleResps)
			{
				responses.Add(singleResp.ASN1);
			}
			toBeSigned.Add(responses);

			if (Extensions.Count > 0)
				toBeSigned.Add(new ASN1(0xA0, Extensions.GetBytes()));

			return toBeSigned;
		}

		// The following code is slightly modified from Mono.Security.X509Builder
		// To allow appending a certificate after the signature

		private byte[] Build(ASN1 tbs, string hashoid, byte[] signature)
		{
			ASN1 builder = new ASN1(0x30);
			builder.Add(tbs);
			builder.Add(PKCS7.AlgorithmIdentifier(hashoid));
			// first byte of BITSTRING is the number of unused bits in the first byte
			byte[] bitstring = new byte[signature.Length + 1];
			Buffer.BlockCopy(signature, 0, bitstring, 1, signature.Length);
			builder.Add(new ASN1(0x03, bitstring));

			ASN1 certSeq = new ASN1(0x30);
			foreach (X509Certificate2 cert in certs)
			{
				certSeq.Add(new ASN1(cert.RawData));
			}
			ASN1 certSeq2 = new ASN1(0xA0);
			certSeq2.Add(certSeq);
			builder.Add(certSeq2);

			return builder.GetBytes();
		}

		public override byte[] Sign(AsymmetricAlgorithm aa)
		{
			if (aa is RSA)
				return Sign(aa as RSA);
			else if (aa is DSA)
				return Sign(aa as DSA);
			else
				throw new NotSupportedException("Unknown Asymmetric Algorithm " + aa.ToString());
		}

		public override byte[] Sign(RSA key)
		{
			string oid = GetOid(Hash);
			ASN1 tbs = ToBeSigned(oid);
			HashAlgorithm ha = HashAlgorithm.Create(Hash);
			byte[] hash = ha.ComputeHash(tbs.GetBytes());

			RSAPKCS1SignatureFormatter pkcs1 = new RSAPKCS1SignatureFormatter(key);
			pkcs1.SetHashAlgorithm(Hash);
			byte[] signature = pkcs1.CreateSignature(hash);

			return Build(tbs, oid, signature);
		}

		public override byte[] Sign(DSA key)
		{
			string oid = "1.2.840.10040.4.3";
			ASN1 tbs = ToBeSigned(oid);
			HashAlgorithm ha = HashAlgorithm.Create(Hash);
			if (!(ha is SHA1))
				throw new NotSupportedException("Only SHA-1 is supported for DSA");
			byte[] hash = ha.ComputeHash(tbs.GetBytes());

			DSASignatureFormatter dsa = new DSASignatureFormatter(key);
			dsa.SetHashAlgorithm(Hash);
			byte[] rs = dsa.CreateSignature(hash);

			// split R and S
			byte[] r = new byte[20];
			Buffer.BlockCopy(rs, 0, r, 0, 20);
			byte[] s = new byte[20];
			Buffer.BlockCopy(rs, 20, s, 0, 20);
			ASN1 signature = new ASN1(0x30);
			signature.Add(new ASN1(0x02, r));
			signature.Add(new ASN1(0x02, s));

			// dsaWithSha1 (1 2 840 10040 4 3)
			return Build(tbs, oid, signature.GetBytes());
		}
	}
}
