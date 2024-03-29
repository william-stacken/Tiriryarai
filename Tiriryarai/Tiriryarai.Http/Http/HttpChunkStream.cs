﻿//
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
using System.Text;

namespace Tiriryarai.Http
{
	/// <summary>
	/// Enum representing the mode of an <see cref="T:Tiriryarai.Http.HttpChunkStream"/>
	/// </summary>
	public enum ChunkMode
	{
		ReadDecoded,
		WriteEncoded
	}

	/// <summary>
	/// A stream for writing data with the HTTP chunked transfer encoding
	/// </summary>
	public class HttpChunkStream : Stream
	{
		private Stream basestream;
		private readonly ChunkMode mode;
		private readonly bool leaveOpen;
		bool hasFlushed = false;

		public HttpChunkStream(Stream stream, ChunkMode mode)
			:this(stream, mode, false) { }

		public HttpChunkStream(Stream stream, ChunkMode mode, bool leaveOpen)
		{
			this.basestream = stream;
			this.mode = mode;
			this.leaveOpen = leaveOpen;
		}

		public override bool CanRead { get { return mode == ChunkMode.ReadDecoded; } }

		public override bool CanWrite { get { return mode == ChunkMode.WriteEncoded; } }

		public override bool CanSeek { get { return false; } }

		public override long Length => throw new NotSupportedException("Length is not supported");

		public override long Position
		{
			get => throw new NotSupportedException("Position is not supported");
			set => throw new NotImplementedException("Position is not supported");
		}

		public override void Flush()
		{
			ThrowIfDisposed();

			basestream.Flush();
		}

		public void FlushFinal()
		{
			ThrowIfDisposed();

			// Write terminating zero length chunk
			if (!hasFlushed)
			{
				Write(new byte[0], 0, 0);
				hasFlushed = true;
			}
			basestream.Flush();
		}

		public override int Read(byte[] buffer, int offset, int count)
		{
			if (!CanRead)
				throw new InvalidOperationException("ChunkStream is not readable");
			ThrowIfDisposed();
			ThrowIfInvalidParams(buffer, offset, count);

			// TODO: Implement reading from the stream
			throw new NotImplementedException("Reading has not been implemented");
		}

		public override long Seek(long offset, SeekOrigin origin)
		{
			throw new NotSupportedException("Seek is not supported");
		}

		public override void SetLength(long value)
		{
			throw new NotSupportedException("SetLength is not supported");
		}

		public override void Write(byte[] buffer, int offset, int count)
		{
			if (!CanWrite)
				throw new InvalidOperationException("ChunkStream is not writable");
			ThrowIfDisposed();
			ThrowIfInvalidParams(buffer, offset, count);

			byte[] length = Encoding.Default.GetBytes(count.ToString("X"));
			byte[] crlf = Encoding.Default.GetBytes("\r\n");

			basestream.Write(length, 0, length.Length);
			basestream.Write(crlf, 0, crlf.Length);
			basestream.Write(buffer, offset, count);
			basestream.Write(crlf, 0, crlf.Length);
		}

		protected override void Dispose(bool disposing)
		{
			try
			{
				if (disposing && !leaveOpen && basestream != null)
					basestream.Close();
			}
			finally
			{
				basestream = null;
			}
			base.Dispose(disposing);
		}

		private void ThrowIfDisposed()
		{
			if (basestream == null)
				throw new ObjectDisposedException(null, "Stream is disposed.");
		}

		private void ThrowIfInvalidParams(byte[] buffer, int offset, int count)
		{
			if (buffer == null)
				throw new ArgumentNullException(nameof(buffer));
			if (offset < 0)
				throw new ArgumentOutOfRangeException(nameof(offset));
			if (count < 0)
				throw new ArgumentOutOfRangeException(nameof(count));
			if (buffer.Length - offset < count)
				throw new ArgumentException("Invalid offset and count for the given buffer");
		}
	}
}
