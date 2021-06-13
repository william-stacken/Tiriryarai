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

using System.Text;
using System.Text.RegularExpressions;

using Tiriryarai.Http;
using Tiriryarai.Server;

namespace TiriryaraiMitm
{
    public class MiddleMan : IManInTheMiddle
    {
        public bool Block(string hostname)
        {
            // Block all hostnames containing "example"
            return new Regex("^.*example.*$").IsMatch(hostname);
        }

        public HttpMessage HandleRequest(HttpRequest req)
        {
            // Optionally tamper with request, or intercept it
            // and return a response instead.
            return req;
        }

        public HttpResponse HandleResponse(HttpResponse resp, HttpRequest req)
        {
            // Optionally tamper with response.
            return resp;
        }

        public HttpResponse HomePage(HttpRequest req)
        {
            HttpResponse resp = new HttpResponse(200);
            resp.SetHeader("Content-Type", "text/html");
            resp.SetBodyAndLength(Encoding.Default.GetBytes(
                "<h1>Hello World!</h1><p>This was sent from the proxy!</p>"
            ));
            return resp;
        }
    }
}
