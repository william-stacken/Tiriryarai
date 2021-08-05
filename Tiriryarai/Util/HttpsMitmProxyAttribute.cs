using System;

namespace Tiriryarai.Util
{
	/// <summary>
	/// Enum that determines how of if the property can be updated
	/// remotely using the configuration interface.
	/// </summary>
	public enum HttpsMitmProxyProperty
	{
		/// <summary>
		/// The property should be ignored in the configuration interface.
		/// </summary>
		None = 0,

		/// <summary>
		/// The property cannot be updated remotely.
		/// </summary>
		Static = 1,

		/// <summary>
		/// The property can only be updated remotely if
		/// <see cref="T:Tiriryarai.Util.HttpsMitmProxyConfig.ChangeAuthentication"/>
		/// is <c>true</c>.
		/// </summary>
		Authentication = 2,

		/// <summary>
		/// The property can only be updated remotely if
		/// <see cref="T:Tiriryarai.Util.HttpsMitmProxyConfig.LogManagement"/>
		/// is <c>true</c>.
		/// </summary>
		Log = 4,

		/// <summary>
		/// When this property is updated, the <see cref="T:Tiriryarai.Util.HttpsMitmProxyCache"/>
		/// must be cleared.
		/// </summary>
		Cache = 8,

		/// <summary>
		/// The property can be updated remotely as long as
		/// <see cref="T:Tiriryarai.Util.HttpsMitmProxyConfig.Configuration"/>
		/// is <c>true</c>.
		/// </summary>
		Standard = 16,

		/// <summary>
		/// The property is a username and cannot be empty if any password
		/// are set. Only one property can be of this type.
		/// </summary>
		Username = 32,

		/// <summary>
		/// The property is a password and cannot be set if there is
		/// no username property set.
		/// </summary>
		Password = 64
	}
	/// <summary>
	/// A class representing an attribute for  properties in the configuration used
	/// by the MitM Proxy.
	/// </summary>
	[System.AttributeUsage(System.AttributeTargets.Property)]
	public class HttpsMitmProxyAttribute : Attribute
	{
		/// <summary>
		/// The property type that determines how of if the property can be updated
		/// remotely using the configuration interface.
		/// </summary>
		public HttpsMitmProxyProperty Type { get; }

		/// <summary>
		/// The type of input used in HTML forms that represents the property
		/// </summary>
		public string HtmlInputType { get; }

		/// <summary>
		/// The CLI flag prototype used by Mono.Options to represent the property.
		/// </summary>
		public string CliPrototype { get; }

		public HttpsMitmProxyAttribute(HttpsMitmProxyProperty type, string htmlInputType, string cliPrototype)
		{
			Type = type;
			HtmlInputType = htmlInputType;
			CliPrototype = cliPrototype;
		}
	}
}
