using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SmartCardsEncoder
{
    class Record
    {
        public static int URL = 0;
        public static int TEXT_EN = 1;
        public static int TEXT_FR = 2;
        public static int BINARY = 3;

        public int DataType { get; set; }
        public List<byte> Data { get; set; }

        public Record()
        {
            this.DataType = Record.URL;
            this.Data = new List<byte>();
        }

        public Record(int dataType, List<byte> data)
        {
            this.DataType = dataType;
            this.Data = data;
        }

        public Record(int dataType, string data)
        {
            this.DataType = dataType;
            this.Data = new List<byte>(ASCIIEncoding.ASCII.GetBytes(data));
        }
    }
}
