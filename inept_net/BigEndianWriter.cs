using System;
using System.Collections.Generic;
using System.IO;

namespace inept_net
{
    public class BigEndianWriter 
    {
        private BinaryWriter inner;

        public BigEndianWriter(BinaryWriter writer)
        {
            inner = writer;
        }

        public static void ReverseArray(byte[] data)
        {
            for (int i = 0, j = data.Length - 1; i < j; ++i, --j)
            {
                byte t = data[i];
                data[i] = data[j];
                data[j] = t;
            }
        }


        public void WriteBigEndian(byte[] data)
        {
            for ( int i=data.Length-1; i>=0; --i )
                inner.Write(data[i]);
        }

        public void Write(UInt32 v)
        {
            WriteBigEndian(BitConverter.GetBytes(v));
        }
        public void Write(UInt16 v)
        {
            WriteBigEndian(BitConverter.GetBytes(v));
        }
        public void Write(byte v)
        {
            inner.Write(v);
        }
    }
}
