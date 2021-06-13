//
// CRLDistributionPointsExtension.cs: Handles X.509 CRLDistributionPoints extensions.
//
// Author:
//	Sebastien Pouliot  <sebastien@ximian.com>
//
// (C) 2004 Novell (http://www.novell.com)
//

//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

// Slightly modified version from mono. Adds method for adding a distribution point.

using System;
using System.Collections.Generic;
using System.Text;

using Mono.Security;
using Mono.Security.X509;

namespace Tiriryarai.Crypto
{
	public class CRLDistributionPointsExtension : X509Extension
	{
		public class DistributionPoint
		{
			public string Name { get; private set; }
			public ReasonFlags Reasons { get; private set; }
			public string CRLIssuer { get; private set; }

			public DistributionPoint(string dp, ReasonFlags reasons, string issuer)
			{
				Name = dp ?? throw new ArgumentNullException(nameof(dp));
				Reasons = reasons;
				CRLIssuer = issuer;
			}

			public DistributionPoint(ASN1 dp)
			{
				for (int i = 0; i < dp.Count; i++)
				{
					ASN1 el = dp[i];
					switch (el.Tag)
					{
						case 0xA0: // DistributionPointName OPTIONAL
							for (int j = 0; j < el.Count; j++)
							{
								ASN1 dpn = el[j];
								// TODO Can dpn[0].Tag be something else than 0x86 or a URI
								// and must dpn.Count really be one?
								if (dpn.Tag == 0xA0 && dpn.Count == 1 && dpn[0].Tag == 0x86)
								{
									Name = Encoding.ASCII.GetString(dpn[0].Value);
								}
							}
							break;
						case 0xA1: // ReasonFlags OPTIONAL
							break;
						case 0xA2: // RelativeDistinguishedName
							break;
					}
				}
			}

			public ASN1 ASN1
			{
				get
				{
					ASN1 seq = new ASN1(0x30);

					if (Name != null)
					{
						ASN1 name2 = new ASN1(0xA0);
						name2.Add(new ASN1(0x86, Encoding.ASCII.GetBytes(Name)));

						ASN1 name = new ASN1(0xA0);
						name.Add(name2);

						seq.Add(name);
					}
					if (Reasons != ReasonFlags.Unused)
					{
						// TODO
					}
					if (CRLIssuer != null)
					{
						// TODO
					}
					return seq;
				}
			}
		}

		[Flags]
		public enum ReasonFlags
		{
			Unused = 0,
			KeyCompromise = 1,
			CACompromise = 2,
			AffiliationChanged = 3,
			Superseded = 4,
			CessationOfOperation = 5,
			CertificateHold = 6,
			PrivilegeWithdrawn = 7,
			AACompromise = 8
		}

		private List<DistributionPoint> dps;

		public CRLDistributionPointsExtension() : base()
		{
			extnOid = "2.5.29.31";
			dps = new List<DistributionPoint>();
		}

		public CRLDistributionPointsExtension(ASN1 asn1)
			: base(asn1)
		{
		}

		public CRLDistributionPointsExtension(X509Extension extension)
			: base(extension)
		{
		}

		protected override void Decode()
		{
			dps = new List<DistributionPoint>();
			ASN1 sequence = new ASN1(extnValue.Value);
			if (sequence.Tag != 0x30)
				throw new ArgumentException("Invalid CRLDistributionPoints extension");
			// for every distribution point
			for (int i = 0; i < sequence.Count; i++)
			{
				dps.Add(new DistributionPoint(sequence[i]));
			}
		}

		protected override void Encode()
		{
			if (dps == null)
				throw new InvalidOperationException("Invalid CRLDistributionPoints extension");

			ASN1 seq = new ASN1(0x30);
			foreach (DistributionPoint dp in dps)
			{
				seq.Add(dp.ASN1);
			}
			extnValue = new ASN1(0x04);
			extnValue.Add(seq);
		}

		public override string Name
		{
			get { return "CRL Distribution Points"; }
		}

		public IEnumerable<DistributionPoint> DistributionPoints
		{
			get { return dps; }
		}

		public void AddDistributionPoint(string name)
		{
			dps.Add(new DistributionPoint(name ?? throw new ArgumentNullException(nameof(name)), ReasonFlags.Unused, null));
		}

		public override string ToString()
		{
			StringBuilder sb = new StringBuilder();
			int i = 1;
			foreach (DistributionPoint dp in dps)
			{
				sb.Append("[");
				sb.Append(i++);
				sb.Append("]CRL Distribution Point");
				sb.Append(Environment.NewLine);
				sb.Append("\tDistribution Point Name:");
				sb.Append("\t\tFull Name:");
				sb.Append(Environment.NewLine);
				sb.Append("\t\t\t");
				sb.Append(dp.Name);
				sb.Append(Environment.NewLine);
			}
			return sb.ToString();
		}
	}
}
