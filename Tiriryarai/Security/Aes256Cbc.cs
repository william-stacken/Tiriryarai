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
using System.IO;
using System.Security.Cryptography;

namespace Tiriryarai
{
	/// <summary>
	/// A class for encryption and decryption using AES-256 Cipher block chaining.
	/// </summary>
    class Aes256Cbc
    {
        private readonly byte[] CryptoKey;
        private readonly byte[] Iv;

		/// <summary>
		/// Initializes a new instance of the <see cref="T:Tiriryarai.Aes256Cbc"/> class.
		/// </summary>
		/// <param name="cryptoKey">The 256-bit key to use.</param>
		/// <param name="iv">The 128-bit initialization vector to use.</param>
        public Aes256Cbc(byte[] cryptoKey, byte[] iv)
        {
            if (cryptoKey == null || iv == null)
                throw new ArgumentNullException(nameof(cryptoKey) + " or " + nameof(iv));
            if (cryptoKey.Length != 32 || iv.Length != 16)
                throw new ArgumentException("Bad crypto key or init vector length");
            CryptoKey = cryptoKey;
            Iv = iv;
        }

		/// <summary>
		/// Encrypts a string to a byte array.
		/// </summary>
		/// <returns>The encrypted string as a byte array.</returns>
		/// <param name="plainText">The string to encrypt.</param>
        public byte[] EncryptStringToBytes(string plainText)
        {
            byte[] encrypted;
            
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = CryptoKey;
                aesAlg.IV = Iv;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return encrypted;
        }

		/// <summary>
		/// Decrypts a byte array to a string.
		/// </summary>
		/// <returns>The decrypted byte array as a string.</returns>
		/// <param name="cipherText">The byte array to decrypt.</param>
        public string DecryptBytesToString(byte[] cipherText)
        {
            string plaintext = null;
            
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = CryptoKey;
                aesAlg.IV = Iv;
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }
    }
}