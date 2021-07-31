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
using System.Net;
using System.IO;
using System.Threading;
using System.Collections;
using System.Collections.Specialized;
using System.Collections.Concurrent;
using System.Runtime.Caching;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Mono.Security.X509;
using Mono.Security.X509.Extensions;

using Tiriryarai.Crypto;

using CRLDistributionPointsExtension = Tiriryarai.Crypto.CRLDistributionPointsExtension;
using KeyUsageExtension = Tiriryarai.Crypto.KeyUsageExtension;
using X509Certificate = Mono.Security.X509.X509Certificate;

namespace Tiriryarai.Util
{
	/// <summary>
	/// A class used for caching certificates, OCSP responses, and other data used by
	/// man-in-the-middle HTTPS proxies. The content will be cached and removed automatically
	/// when expired. The cache is self-mantaining in that it shrinks itself if it
	/// gets too large. The root CA and OCSP CA certificates will be stored on disk instead
	/// of in memory however since they are unlikely to change when restarting Tiriryarai.
	/// </summary>
	public class HttpsMitmProxyCache
	{
		private static readonly Random rng = new Random();

		private Logger logger;
		private MemoryCache cache;
		private readonly string[] mitmHosts;

		private readonly string storeDir;
		private static readonly string rootCA = "-RootCA-.pfx";
		private static readonly string ocspCA = "-OcspCA-.pfx";
		private readonly X509CertificateUrls urls;

		private ConcurrentDictionary<object, byte> mutex;

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Util.HttpsMitmProxyCache"/> class.
		/// </summary>
		/// <param name="mitmHosts">Hostnames of the MitM proxy.</param>
		/// <param name="storeDir">Path to directory where the PKCS12 files will be stored.</param>
		/// <param name="mbMemoryLimit">Memory limit imposed on the cache in megabytes. If this limit
		/// is breached, cache entries will be expelled.</param>
		/// <param name="pollingInterval">The polling interval at which to check that the cache size
		/// has not breached the limit.</param>
		/// <param name="urls">An immutable collection of URLs used when generating certificates.</param>
		public HttpsMitmProxyCache(string[] mitmHosts, string storeDir, int mbMemoryLimit, int pollingInterval, X509CertificateUrls urls)
		{
			this.storeDir = storeDir ?? throw new ArgumentNullException(nameof(storeDir));
			this.urls = urls ?? throw new ArgumentNullException(nameof(urls));
			this.mitmHosts = mitmHosts ?? throw new ArgumentNullException(nameof(mitmHosts));

			logger = Logger.GetSingleton();

			mutex = new ConcurrentDictionary<object, byte>();
			cache = new MemoryCache("HttpsMitmProxyCache", new NameValueCollection {
				{"CacheMemoryLimitMegabytes", "" + mbMemoryLimit},
				{"PollingInterval", TimeSpan.FromMilliseconds(pollingInterval).ToString()},
			});

			InitializePKCS12(rootCA, Path.Combine(storeDir, rootCA), CreateRootCertFile, GetRootCA);
			InitializePKCS12(ocspCA, Path.Combine(storeDir, ocspCA), CreateOCSPCertFile, GetOCSPCA);

			foreach (string mitmHost in mitmHosts)
			{
				InitializePKCS12(mitmHost,
				                 Path.Combine(storeDir, mitmHost + ".pfx"),
				                 CreateCertificate,
				                 () => GetCertificate(mitmHost));
			}

			// Remove PKCS12 files that are no longer in use
			foreach (string pfxFile in Directory.GetFiles(storeDir, "*.pfx"))
			{
				bool isUnused = true;
				string name = Path.GetFileNameWithoutExtension(pfxFile);
				if (!name.Equals("-RootCA-") && !name.Equals("-OcspCA-"))
				{
					for (int i = 0; isUnused && i < mitmHosts.Length; i++)
					{
						isUnused = !name.Equals(mitmHosts[i]);
					}
					if (isUnused)
					{
						File.Delete(pfxFile);
					}
				}
			}
		}

		private void InitializePKCS12(object key, string filepath, Func<object, object> pkcs12Factory, Func<X509Certificate2> pkcs12Get)
		{
			X509Certificate2Collection collection;
			if (!File.Exists(filepath))
			{
				AddOrGetExisting(key, pkcs12Factory, val => (val as X509Certificate2).NotAfter);
			}
			else
			{
				collection = new X509Certificate2Collection();
				collection.Import(filepath, Resources.PFX_PASS, X509KeyStorageFlags.PersistKeySet);
				X509Certificate2 cert = collection[0];
				if (cert.NotAfter < DateTime.Now)
				{
					cert = pkcs12Get();
				}
				AddOrGetExisting(key, path => cert, val => (val as X509Certificate2).NotAfter);
			}
		}

		private object AddOrGetExisting(object key, Func<object, object> valueFactory, Func<object, DateTime> expiry)
		{
			object val = null;

			while (!mutex.TryAdd(key, 0))
				Thread.Sleep(200);

			try
			{
				val = cache.Get(key.ToString());
				if (val == null)
				{
					val = valueFactory(key);
					cache.Add(key.ToString(), val, expiry(val));
				}
			}
			finally
			{
				mutex.TryRemove(key, out _);
			}
			return val ?? throw new Exception("ERROR: Failed to add or get " + key + " from cache.");
		}

		/// <summary>
		/// Gets the root CA. If it has expired, a new one will be created automatically
		/// with a notice that the new root CA must be installed.
		/// </summary>
		/// <returns>The root CA.</returns>
		public X509Certificate2 GetRootCA()
		{
			return AddOrGetExisting(rootCA, certPath => {
				if (!(certPath is string path))
					throw new ArgumentException("certPath must be a string");
				Console.WriteLine("\n--------------------\nNOTICE: The root CA certificate has expired and will be replaced." +
							"Please install the new certificate and remove the old one.");
				// TODO Clear the cache somehow since essentially everything in the cache is now invalid.
				File.Delete(path);
				return CreateRootCertFile(path);
			}, val => (val as X509Certificate2).NotAfter) as X509Certificate2;
		}

		/// <summary>
		/// Gets the OCSP CA. If it has expired, a new one will be created automatically.
		/// Note that all cached OCSP responses will be invalid until they expire and are
		/// regenerated.
		/// </summary>
		/// <returns>The OCSP CA.</returns>
		public X509Certificate2 GetOCSPCA()
		{
			return AddOrGetExisting(ocspCA, certPath => {
				if (!(certPath is string path))
					throw new ArgumentException("certPath must be a string");
				File.Delete(path);
				return CreateOCSPCertFile(path);
			}, val => (val as X509Certificate2).NotAfter) as X509Certificate2;
		}

		/// <summary>
		/// Gets a certificate with the given hostname. If it does not exist or has
		/// expired, a new one will be created and signed by the root CA automatically.
		/// </summary>
		/// <returns>The requested certificate.</returns>
		/// <param name="hostname">The hostname whose certificate is requested.</param>
		public X509Certificate2 GetCertificate(string hostname)
		{
			return AddOrGetExisting(hostname.Split(':')[0], CreateCertificate, val => (
				val as X509Certificate2).NotAfter
			) as X509Certificate2;
		}

		/// <summary>
		/// Gets an empty certificate revocation list. If it does not exist or has
		/// expired, a new one will be created and signed by the root CA automatically.
		/// </summary>
		/// <returns>The empty certificate revocation list.</returns>
		public X509Crl GetCrl()
		{
			return AddOrGetExisting("-crl-", CreateCRL, val => (
				val as X509Crl).NextUpdate
			) as X509Crl;
		}

		/// <summary>
		/// Gets an OCSP response indicating that the certificate contained in the
		/// given OCSP request is valid. If it does not exist or has expired, a
		/// new one will be created and signed by the OCSP CA automatically.
		/// </summary>
		/// <returns>The OCSP Response.</returns>
		/// <param name="ocspReq">An OCSP request whose given certificate
		/// is to be checked for revocation.</param>
		public X509OCSPResponse GetOCSPResponse(X509OCSPRequest ocspReq)
		{
			return AddOrGetExisting(ocspReq.CertificateID, CreateOCSPResponse, val => (
			    val as X509OCSPResponse).ExpiryDate
			) as X509OCSPResponse;
		}

		/// <summary>
		/// Gets the IP client statistics of the given IP.
		/// </summary>
		/// <returns>The IP client statistics.</returns>
		/// <param name="req">The IP whose client statistics to obtain.</param>
		public IpClientStats GetIPStatistics(IPAddress ip)
		{
			// TODO Expire statistics after 14 days, maybe there is a better time frame?
			return AddOrGetExisting("$" + ip, val => new IpClientStats(), val => DateTime.Now.AddDays(14)
			) as IpClientStats;
		}

		private static PKCS12 SaveToPKCS12(string path,
		                                   X509CertificateBuilder cb,
		                                   AsymmetricAlgorithm subjectKey,
		                                   AsymmetricAlgorithm issuerKey)
		{
			PKCS12 p12 = new PKCS12();
			p12.Password = Resources.PFX_PASS;

			ArrayList list = new ArrayList();
			list.Add(new byte[4] { 1, 0, 0, 0 });
			Hashtable attributes = new Hashtable(1);
			attributes.Add(PKCS9.localKeyId, list);

			p12.AddCertificate(new X509Certificate(cb.Sign(issuerKey)), attributes);
			p12.AddPkcs8ShroudedKeyBag(subjectKey, attributes);
			p12.SaveToFile(path);

			return p12;
		}

		private X509Certificate2 CreateRootCertFile(object cert)
		{
			byte[] rootSn = Guid.NewGuid().ToByteArray();
			rootSn[0] &= 0x7F;

			RSACryptoServiceProvider rootKey = new RSACryptoServiceProvider(Resources.KEY_BITS);

			BasicConstraintsExtension bce = new BasicConstraintsExtension();
			bce.CertificateAuthority = true;
			bce.Critical = true;

			KeyUsageExtension kue = new KeyUsageExtension();
			kue.Critical = true;
			kue.KeyUsage = KeyUsages.digitalSignature | KeyUsages.keyCertSign | KeyUsages.cRLSign;

			SubjectKeyIdentifierExtension skie = new SubjectKeyIdentifierExtension();
			skie.Identifier = Resources.CA_KEY_ID;

			AuthorityKeyIdentifierExtension akie = new AuthorityKeyIdentifierExtension();
			akie.Identifier = Resources.CA_KEY_ID;

			X509CertificateBuilder cb = new X509CertificateBuilder(3)
			{
				SerialNumber = rootSn,
				IssuerName = Resources.ROOT_CA_SUBJECT_NAME,
				NotBefore = DateTime.Now.AddYears(-5),
				NotAfter = DateTime.Now.AddYears(20),
				SubjectName = Resources.ROOT_CA_SUBJECT_NAME,
				SubjectPublicKey = rootKey,
				Hash = Resources.HASH_ALGORITHM
			};
			cb.Extensions.Add(bce);
			cb.Extensions.Add(kue);
			cb.Extensions.Add(skie);
			cb.Extensions.Add(akie);

			PKCS12 p12 = SaveToPKCS12(Path.Combine(storeDir, rootCA), cb, rootKey, rootKey);
			return new X509Certificate2(p12.GetBytes(), Resources.PFX_PASS, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
		}

		private X509Certificate2 CreateOCSPCertFile(object cert)
		{
			byte[] ocspSn = Guid.NewGuid().ToByteArray();
			ocspSn[0] &= 0x7F;

			byte[] ocspId = new byte[20];
			rng.NextBytes(ocspId);

			RSACryptoServiceProvider ocspKey = new RSACryptoServiceProvider(Resources.KEY_BITS);

			KeyUsageExtension kue = new KeyUsageExtension();
			kue.Critical = true;
			kue.KeyUsage = KeyUsages.digitalSignature;

			ExtendedKeyUsageExtension ekue = new ExtendedKeyUsageExtension();
			ekue.KeyPurpose.Add("1.3.6.1.5.5.7.3.9"); // OCSP Signing

			OCSPNoCheckExtension once = new OCSPNoCheckExtension();

			SubjectKeyIdentifierExtension skie = new SubjectKeyIdentifierExtension();
			skie.Identifier = ocspId;

			AuthorityKeyIdentifierExtension akie = new AuthorityKeyIdentifierExtension();
			akie.Identifier = Resources.CA_KEY_ID;

			X509CertificateBuilder cb = new X509CertificateBuilder(3)
			{
				SerialNumber = ocspSn,
				IssuerName = Resources.ROOT_CA_SUBJECT_NAME,
				NotBefore = DateTime.Now.AddDays(-2),
				NotAfter = DateTime.Now.AddMonths(3),
				SubjectName = string.Format(Resources.CERT_SUBJECT_NAME, "TiriryaraiCA OCSP Responder"),
				SubjectPublicKey = ocspKey,
				Hash = Resources.HASH_ALGORITHM
			};
			cb.Extensions.Add(kue);
			cb.Extensions.Add(ekue);
			cb.Extensions.Add(once);
			cb.Extensions.Add(skie);
			cb.Extensions.Add(akie);

			PKCS12 p12 = SaveToPKCS12(Path.Combine(storeDir, ocspCA), cb, ocspKey, GetRootCA().PrivateKey);
			return new X509Certificate2(
				p12.GetBytes(),
				Resources.PFX_PASS, 
				X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
			);
		}

		private X509Certificate2 CreateCertificate(object host)
		{
			if (!(host is string hostname))
				throw new ArgumentException("host must be a string");

			byte[] ski = new byte[20];
			rng.NextBytes(ski);
			byte[] sn = Guid.NewGuid().ToByteArray();
			sn[0] &= 0x7F;

			RSACryptoServiceProvider subjectKey = new RSACryptoServiceProvider(Resources.KEY_BITS);

			SubjectAltNameExtension sane;
			if (IPAddress.TryParse(hostname, out _))
				sane = new SubjectAltNameExtension(null, null, new string[] { hostname }, null);
			else
				sane = new SubjectAltNameExtension(null, new string[] { hostname }, null, null);

			ExtendedKeyUsageExtension ekue = new ExtendedKeyUsageExtension();
			ekue.KeyPurpose.Add("1.3.6.1.5.5.7.3.1"); // authenticate server

			SubjectKeyIdentifierExtension skie = new SubjectKeyIdentifierExtension();
			skie.Identifier = ski;

			AuthorityKeyIdentifierExtension akie = new AuthorityKeyIdentifierExtension();
			akie.Identifier = Resources.CA_KEY_ID;

			CRLDistributionPointsExtension cdpe = new CRLDistributionPointsExtension();
			cdpe.AddDistributionPoint(urls.Crl);

			AuthorityInfoAccessExtension aiae = new AuthorityInfoAccessExtension();
			aiae.OCSP = urls.Ocsp;
			aiae.CAIssuers = urls.CAIssuer;

			X509CertificateBuilder cb = new X509CertificateBuilder(3)
			{
				SerialNumber = sn,
				IssuerName = Resources.ROOT_CA_SUBJECT_NAME,
				NotBefore = DateTime.Now.AddDays(-20),
				NotAfter = DateTime.Now.AddYears(1),
				SubjectName = string.Format(Resources.CERT_SUBJECT_NAME, hostname),
				SubjectPublicKey = subjectKey,
				Hash = Resources.HASH_ALGORITHM
			};
			cb.Extensions.Add(sane);
			cb.Extensions.Add(ekue);
			cb.Extensions.Add(skie);
			cb.Extensions.Add(akie);
			cb.Extensions.Add(cdpe);
			cb.Extensions.Add(aiae);

			PKCS12 p12 = new PKCS12();
			p12.Password = Resources.PFX_PASS;

			ArrayList list = new ArrayList();
			list.Add(new byte[4] { 1, 0, 0, 0 });
			Hashtable attributes = new Hashtable(1);
			attributes.Add(PKCS9.localKeyId, list);

			X509Certificate2 root = GetRootCA();
			p12.AddCertificate(new X509Certificate(cb.Sign(root.PrivateKey)), attributes);
			p12.AddPkcs8ShroudedKeyBag(subjectKey, attributes);

			foreach (string mitmHost in mitmHosts)
			{
				if (hostname.Equals(mitmHost))
				{
					p12.SaveToFile(Path.Combine(storeDir, mitmHost + ".pfx"));
				}
			}

			return new X509Certificate2(
				p12.GetBytes(),
				Resources.PFX_PASS,
				X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
			);
		}

		private X509Crl CreateCRL(object key)
		{
			AuthorityKeyIdentifierExtension akie = new AuthorityKeyIdentifierExtension();
			akie.Identifier = Resources.CA_KEY_ID;

			CRLNumberExtension cne = new CRLNumberExtension();
			cne.Number = 39; // TODO What does this number mean in the standard?

			X509CRLBuilder cb = new X509CRLBuilder(1)
			{
				Issuer = Resources.ROOT_CA_SUBJECT_NAME,
				ThisUpdate = DateTime.Now.AddDays(-1),
				NextUpdate = DateTime.Now.AddDays(3),
				Hash = Resources.HASH_ALGORITHM
			};
			cb.Extensions.Add(akie);
			cb.Extensions.Add(cne);

			byte[] rawcrl = cb.Sign(GetRootCA().PrivateKey);

			return new X509Crl(rawcrl);
		}

		private X509OCSPResponse CreateOCSPResponse(object id)
		{
			if (!(id is X509OCSPCertID certId))
				throw new ArgumentException("id must be a X509OCSPCertID");

			X509OCSPResponse ocsp;
			X509Certificate2 ca = GetOCSPCA();
			try
			{
				X509BasicOCSPResponseBuilder builder = new X509BasicOCSPResponseBuilder
				{
					Name = string.Format(Resources.CERT_SUBJECT_NAME, "TiriryaraiCA OCSP Responder"),
					ProducedAt = DateTime.Now,
					Hash = Resources.HASH_ALGORITHM
				};
				builder.AddSingleResponse(new X509OCSPSingleResponse(
					certId,
					X509OCSPSingleResponse.CertStatus.Good,
					DateTime.Now.AddDays(-1),
					DateTime.Now.AddDays(3)
				));
				builder.AddCertificate(ca);
				ocsp = new X509OCSPResponse(X509OCSPResponse.ResponseStatus.Successful, builder);
			}
			catch (Exception e)
			{
				logger.LogException(e, certId);
				ocsp = new X509OCSPResponse(X509OCSPResponse.ResponseStatus.MalformedRequest);
			}
			return new X509OCSPResponse(ocsp.Sign(ca));
		}
	}
}
