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

namespace Tiriryarai.Util
{
	/// <summary>
	/// A class used for remembering behaviour from a specific client IP address
	/// </summary>
	public class IpClientStats
	{
		private int loginAttempts = 0;

		/// <summary>
		/// Checks if a client is IP banned, meaning that their login attempts has exceeded
		/// the maximum allowed login attempts.
		/// </summary>
		/// <returns><c>true</c> if the client is banned; otherwise <c>false</c>.</returns>
		/// <param name="maxLoginAttempts">The maximum allowed login attempts before the
		/// client should be considered banned.</param>
		public bool IsBanned(int maxLoginAttempts)
		{
			return loginAttempts >= maxLoginAttempts;
		}

		/// <summary>
		/// Increments the login attempt counter of the IP client
		/// </summary>
		public void LoginAttempt()
		{
			loginAttempts++;
		}
	}
}
