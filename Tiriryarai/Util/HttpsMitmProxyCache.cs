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
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Collections.Concurrent;
using System.Runtime.Caching;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Mono.Security.X509;
using Mono.Security.X509.Extensions;

using Tiriryarai.Crypto;
using Tiriryarai.Http;

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
	/// of in memory however since they can be reused when restarting Tiriryarai.
	/// </summary>
	public class HttpsMitmProxyCache
	{
		private static readonly string rootCA = "-RootCA-.pfx";
		private static readonly string ocspCA = "-OcspCA-.pfx";
		private string pkcs12Dir;

		private static HttpsMitmProxyCache singleton;
		private static readonly Random rng = new Random();

		private HttpsMitmProxyConfig conf;
		private Logger logger;
		private MemoryCache cache;

		private HashSet<string> mitmHosts;
		private X509CertificateUrls urls;

		private ConcurrentDictionary<object, byte> mutex;

		private HttpsMitmProxyCache()
		{
			conf = HttpsMitmProxyConfig.GetSingleton();
			logger = Logger.GetSingleton();
			mitmHosts = new HashSet<string> { Resources.HOSTNAME, conf.Hostname };
			mutex = new ConcurrentDictionary<object, byte>();

			urls = new X509CertificateUrls(
				"http://" + Resources.HOSTNAME + "/" + Resources.CA_ISSUER_PATH,
				"http://" + Resources.HOSTNAME + "/" + Resources.OCSP_PATH,
				"http://" + Resources.HOSTNAME + "/" + Resources.CRL_PATH
			);

			pkcs12Dir = Path.Combine(conf.ConfigDirectory, "pkcs12");
			Directory.CreateDirectory(pkcs12Dir);
			Initialize();
		}

		public static HttpsMitmProxyCache GetSingleton()
		{
			if (singleton == null)
				singleton = new HttpsMitmProxyCache();
			return singleton;
		}

		/// <summary>
		/// Clears the entire cache, including the PKCS12 files stored on disk.
		/// This means that a new Root CA is generated that must be installed in
		/// clients.
		/// </summary>
		/// <returns>The new Root CA certificate that was generated after clearing the cache.</returns>
		public X509Certificate2 Clear()
		{
			// Remove all PKCS12 files
			foreach (string pfxFile in Directory.GetFiles(conf.ConfigDirectory, "*.pfx"))
				File.Delete(pfxFile);
			foreach (string pfxFile in Directory.GetFiles(pkcs12Dir, "*.pfx"))
				File.Delete(pfxFile);

			cache.Dispose();
			Initialize();

			logger.LogDebug(1, "NOTICE: The root CA certificate has been deleted and will be replaced." +
			                   "Please install the new certificate and remove the old one.");
			return GetRootCA();
		}

		private void Initialize()
		{
			cache = new MemoryCache("HttpsMitmProxyCache", new NameValueCollection {
				{"CacheMemoryLimitMegabytes", "" + conf.CacheMemoryLimit},
				{"PollingInterval", TimeSpan.FromMilliseconds(conf.CachePollingInterval).ToString()},
			});

			// Populate the cache with fundamental certificates
			GetRootCA();
			GetOCSPCA();
			foreach (string mitmHost in mitmHosts)
			{
				GetCertificate(mitmHost);
			}

			// Add PKCS12 files for sites
			foreach (string pfxFile in Directory.GetFiles(pkcs12Dir, "*.pfx"))
			{
				GetCertificate(Path.GetFileNameWithoutExtension(pfxFile));
			}
		}

		private object InitializePKCS12(object key, string filepath, Func<object, object> pkcs12Factory)
		{
			X509Certificate2Collection collection;
			if (!File.Exists(filepath))
			{
				return pkcs12Factory(key) as X509Certificate2;
			}
			else
			{
				collection = new X509Certificate2Collection();
				try
				{
					collection.Import(
						filepath,
						conf.Authenticate ? Convert.ToBase64String(conf.PassKey) : Resources.HARDCODED_PFX_PASS,
						X509KeyStorageFlags.PersistKeySet
					);
				}
				catch (CryptographicException)
				{
					throw new CryptographicException(
						"The PKCS12 file at " + filepath + " could not be opened, which is likely due " +
						"to Tiriryarai not knowing the password. The configured password should be updated " +
						"or the PKCS12 file should be deleted.");
				}
				X509Certificate2 cert = collection[0];
				if (cert.NotAfter < DateTime.UtcNow)
				{
					cert = pkcs12Factory(key) as X509Certificate2;
				}
				return cert as X509Certificate2;
			}
		}

		private object AddOrGetExisting(object key, Func<object, object> valueFactory, Func<object, DateTime> expiry)
		{
			object val = null;

			while (!mutex.TryAdd(key, 0))
				Thread.Sleep(100);

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
			string rootFile = Path.Combine(conf.ConfigDirectory, rootCA);
			return AddOrGetExisting(rootCA,
				cert => (
					// TODO Is this an appropriate way to clear the cache and not use recursion?
					InitializePKCS12(rootCA,
					                 rootFile,
					                 _ => File.Exists(rootFile) ? Clear() : CreateRootCertFile(cert))
				),
				val => (
					val as X509Certificate2)?.NotAfter ?? DateTime.MinValue
				) as X509Certificate2;
		}

		/// <summary>
		/// Gets the OCSP CA. If it has expired, a new one will be created automatically.
		/// Note that all cached OCSP responses will be invalid until they expire and are
		/// regenerated.
		/// </summary>
		/// <returns>The OCSP CA.</returns>
		public X509Certificate2 GetOCSPCA()
		{
			return AddOrGetExisting(ocspCA,
				cert => (
					InitializePKCS12(ocspCA,
					                 Path.Combine(conf.ConfigDirectory, ocspCA),
					                 CreateOCSPCertFile)
				),
				val => (
					val as X509Certificate2)?.NotAfter ?? DateTime.MinValue
				) as X509Certificate2;
		}

		/// <summary>
		/// Gets a certificate with the given hostname. If it does not exist or has
		/// expired, a new one will be created and signed by the root CA automatically.
		/// </summary>
		/// <returns>The requested certificate.</returns>
		/// <param name="hostname">The hostname whose certificate is requested.</param>
		public X509Certificate2 GetCertificate(string hostname)
		{
			int i;
			string[] subdomains;
			string pfxPath;
			if (hostname == null)
				throw new ArgumentNullException(nameof(hostname));

			hostname = hostname.Split(':')[0];
			UriHostNameType t = Uri.CheckHostName(hostname);
			if (t == UriHostNameType.Unknown)
				throw new ArgumentException("Invalid hostname: " + hostname);

			if (t == UriHostNameType.Dns)
			{
				// Convert www.example.org to example.org such that *.example.org
				// can be used as a subject alternative name, reducing the amount
				// of certificates that must be generated
				subdomains = hostname.Split('.');
				if ((subdomains.Length & 1) != 0)
				{
					i = hostname.IndexOf('.');
					if (i >= 0)
						hostname = hostname.Substring(i + 1, hostname.Length - i - 1);
				}
			}
			if (mitmHosts.Contains(hostname))
				pfxPath = conf.ConfigDirectory;
			else
				pfxPath = pkcs12Dir;
			return AddOrGetExisting(hostname,
				host => (
					InitializePKCS12(host,
					                 Path.Combine(pfxPath, host + ".pfx"),
									 CreateCertificate)
				),
				val => (
					val as X509Certificate2)?.NotAfter ?? DateTime.MinValue
				) as X509Certificate2;
		}

		/// <summary>
		/// Gets a response for the given HTTP request that has previously been cached.
		/// If it has expired or there was no cached response, a response will be obtained
		/// from the given callback.
		/// </summary>
		/// <returns>The cached or generated HTTP response.</returns>
		public HttpResponse GetHttpResponse(HttpRequest req, Func<object, object> valueFactory, DateTime expiry)
		{
			return AddOrGetExisting(req.Host + req.Path, valueFactory, val => expiry) as HttpResponse;
		}

		/// <summary>
		/// Gets an empty certificate revocation list. If it does not exist or has
		/// expired, a new one will be created and signed by the root CA automatically.
		/// </summary>
		/// <returns>The empty certificate revocation list.</returns>
		public X509Crl GetCrl()
		{
			return AddOrGetExisting("-crl-", CreateCRL, val => (
				val as X509Crl)?.NextUpdate ?? DateTime.MinValue
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
			if (ocspReq == null)
				throw new ArgumentNullException(nameof(ocspReq));
			return AddOrGetExisting(ocspReq.CertificateID, CreateOCSPResponse, val => (
			    val as X509OCSPResponse)?.ExpiryDate ?? DateTime.MinValue
			) as X509OCSPResponse;
		}

		/// <summary>
		/// Gets the IP client statistics of the given IP.
		/// </summary>
		/// <returns>The IP client statistics.</returns>
		/// <param name="req">The IP whose client statistics to obtain.</param>
		public IpClientStats GetIPStatistics(IPAddress ip)
		{
			if (ip == null)
				throw new ArgumentNullException(nameof(ip));
			// TODO Expire statistics after 1 day, maybe there is a better time frame? Add to configuration
			return AddOrGetExisting("$" + ip, val => new IpClientStats(), val => DateTime.UtcNow.AddDays(1)
			) as IpClientStats;
		}

		private PKCS12 SaveToPKCS12(string path,
		                            X509CertificateBuilder cb,
		                            AsymmetricAlgorithm subjectKey,
		                            AsymmetricAlgorithm issuerKey)
		{
			PKCS12 p12 = new PKCS12();
			p12.Password = conf.Authenticate ? Convert.ToBase64String(conf.PassKey) : Resources.HARDCODED_PFX_PASS;

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
				NotBefore = DateTime.UtcNow.AddYears(-5),
				NotAfter = DateTime.UtcNow.AddYears(20),
				SubjectName = Resources.ROOT_CA_SUBJECT_NAME,
				SubjectPublicKey = rootKey,
				Hash = Resources.HASH_ALGORITHM
			};
			cb.Extensions.Add(bce);
			cb.Extensions.Add(kue);
			cb.Extensions.Add(skie);
			cb.Extensions.Add(akie);

			PKCS12 p12 = SaveToPKCS12(Path.Combine(conf.ConfigDirectory, rootCA), cb, rootKey, rootKey);
			return new X509Certificate2(
				p12.GetBytes(),
				conf.Authenticate ? Convert.ToBase64String(conf.PassKey) : Resources.HARDCODED_PFX_PASS,
				X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet
			);
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
				NotBefore = DateTime.UtcNow.AddDays(-2),
				NotAfter = DateTime.UtcNow.AddMonths(3),
				SubjectName = string.Format(Resources.CERT_SUBJECT_NAME, "TiriryaraiCA OCSP Responder"),
				SubjectPublicKey = ocspKey,
				Hash = Resources.HASH_ALGORITHM
			};
			cb.Extensions.Add(kue);
			cb.Extensions.Add(ekue);
			cb.Extensions.Add(once);
			cb.Extensions.Add(skie);
			cb.Extensions.Add(akie);

			PKCS12 p12 = SaveToPKCS12(Path.Combine(conf.ConfigDirectory, ocspCA), cb, ocspKey, GetRootCA().PrivateKey);
			return new X509Certificate2(
				p12.GetBytes(),
				conf.Authenticate ? Convert.ToBase64String(conf.PassKey) : Resources.HARDCODED_PFX_PASS,
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
			{
				sane = new SubjectAltNameExtension(null, null, new string[] { hostname }, null);
			}
			else
			{
				if (hostname.IndexOf('.') >= 0)
				{
					sane = new SubjectAltNameExtension(null, new string[] { hostname, "*." + hostname }, null, null);
				}
				else
				{
					sane = new SubjectAltNameExtension(null, new string[] { hostname }, null, null);
				}
			}


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
				NotBefore = DateTime.UtcNow.AddDays(-20),
				NotAfter = DateTime.UtcNow.AddYears(1),
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
			p12.Password = conf.Authenticate ? Convert.ToBase64String(conf.PassKey) : Resources.HARDCODED_PFX_PASS;

			ArrayList list = new ArrayList();
			list.Add(new byte[4] { 1, 0, 0, 0 });
			Hashtable attributes = new Hashtable(1);
			attributes.Add(PKCS9.localKeyId, list);

			X509Certificate2 root = GetRootCA();
			p12.AddCertificate(new X509Certificate(cb.Sign(root.PrivateKey)), attributes);
			p12.AddPkcs8ShroudedKeyBag(subjectKey, attributes);

			// Mitm Host certificates goes into the root configuration, while other sites
			// goes into th pkcs12 directory
			if (mitmHosts.Contains(hostname))
				p12.SaveToFile(Path.Combine(conf.ConfigDirectory, hostname + ".pfx"));
			else
				p12.SaveToFile(Path.Combine(pkcs12Dir, hostname + ".pfx"));

			return new X509Certificate2(
				p12.GetBytes(),
				conf.Authenticate ? Convert.ToBase64String(conf.PassKey) : Resources.HARDCODED_PFX_PASS,
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
				ThisUpdate = DateTime.UtcNow.AddDays(-1),
				NextUpdate = DateTime.UtcNow.AddDays(3),
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
					ProducedAt = DateTime.UtcNow,
					Hash = Resources.HASH_ALGORITHM
				};
				builder.AddSingleResponse(new X509OCSPSingleResponse(
					certId,
					X509OCSPSingleResponse.CertStatus.Good,
					DateTime.UtcNow.AddDays(-1),
					DateTime.UtcNow.AddDays(3)
				));
				builder.AddCertificate(ca);
				ocsp = new X509OCSPResponse(X509OCSPResponse.ResponseStatus.Successful, builder);
			}
			catch (Exception e)
			{
				logger.LogDebug(10, e);
				logger.LogDebug(10, certId);
				ocsp = new X509OCSPResponse(X509OCSPResponse.ResponseStatus.MalformedRequest);
			}
			return new X509OCSPResponse(ocsp.Sign(ca));
		}
	}
}
