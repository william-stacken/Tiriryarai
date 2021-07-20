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

using Tiriryarai.Http;

namespace Tiriryarai.Server
{
	/// <summary>
	/// An interface for a man-in-the-middle handler that will receive incomming HTTP requests and outgoing HTTP responses
	/// to tamper with them automatically.
	/// </summary>
	interface IManInTheMiddle
	{
		/// <summary>
		/// Returns a <c>bool</c> indicating whether the given host is blocked.
		/// </summary>
		/// <returns><code>true</code> if the host should be blocked; otherwise, <code>false</code>.</returns>
		/// <param name="hostname">The name of the host.</param>
		bool Block(string hostname);

		/// <summary>
		/// Handles a request and returns either a modified request if it is to be proxied, or a response otherwise.
		/// </summary>
		/// <returns>An instance of <see cref="T:Tiriryarai.Http.HttpRequest"/> if the request was modified or ignored.
		/// If the request was handled and intercepted, an instance of <see cref="T:Tiriryarai.Http.HttpResponse"/>.</returns>
		/// <param name="req">The request to handle.</param>
		HttpMessage HandleRequest(HttpRequest req);

		/// <summary>
		/// Handles a response returned by the given request and returns the response to be sent back.
		/// </summary>
		/// <returns>The modified or ignored HTTP response.</returns>
		/// <param name="resp">The response to handle.</param>
		/// <param name="req">The request that resulted in this response.</param>
		HttpResponse HandleResponse(HttpResponse resp, HttpRequest req);

		/// <summary>
		/// Handles a request destined to the man-in-the-middle handler and returns a custom response. All requests
		/// sent to this method were received securely using HTTPS, and were authenticated using HTTP basic
		/// authentication if it was required in the <see cref="T:Tiriryarai.Util.HttpsMitmProxyParams"/>
		/// <example>This response could for example be a configuration GUI.</example>
		/// </summary>
		/// <returns>The custom response.</returns>
		/// <param name="req">The request to handle.</param>
		HttpResponse HomePage(HttpRequest req);
	}
}
