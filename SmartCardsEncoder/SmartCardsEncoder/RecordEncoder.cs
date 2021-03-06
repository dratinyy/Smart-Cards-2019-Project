﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SmartCardsEncoder
{
    class RecordEncoder
    {

        public static byte[] Encode(Record[] records)
        {
            List<byte> encodedRecords = new List<byte>();

            foreach (Record r in records)
            {

                // Set the record header

                byte header = 0x00;
                if (records[0] == r)
                    header += 128; // MB
                if (records[records.Length - 1] == r)
                    header += 64; // ME
                header += 16; // SR
                header += 1; // TNF

                // Set the record type_length and type

                byte type_length = 0x00;
                if (r.DataType == Record.TEXT_EN ||
                    r.DataType == Record.TEXT_FR ||
                    r.DataType == Record.URL)
                    type_length = 0x01;
                else if (r.DataType == Record.BINARY)
                    type_length = 0x00;

                byte type = 0x00;
                if (r.DataType == Record.TEXT_EN ||
                    r.DataType == Record.TEXT_FR)
                    type = 0x54;
                else if (r.DataType == Record.URL)
                    type = 0x55;

                List<byte> payload = new List<byte>();
                if (r.DataType == Record.URL)
                {
                    // Encode an url using the Abbreviation Table
                    // (not all abreviations from the table are available yet)

                    string url = System.Text.Encoding.ASCII.GetString(r.Data.ToArray());
                    if (url.StartsWith("http://www."))
                    {
                        payload.Add(0x01);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url.Substring(11)));
                    }
                    else if (url.StartsWith("https://www."))
                    {
                        payload.Add(0x02);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url.Substring(12)));
                    }
                    else if (url.StartsWith("http://"))
                    {
                        payload.Add(0x03);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url.Substring(7)));
                    }
                    else if (url.StartsWith("https://"))
                    {
                        payload.Add(0x04);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url.Substring(8)));
                    }
                    else if (url.StartsWith("tel:"))
                    {
                        payload.Add(0x05);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url.Substring(4)));
                    }
                    else if (url.StartsWith("mailto:"))
                    {
                        payload.Add(0x06);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url.Substring(7)));
                    }
                    else if (url.StartsWith("ftp://anonymous:anonymous@"))
                    {
                        payload.Add(0x07);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url.Substring(26)));
                    }
                    else if (url.StartsWith("ftp://ftp."))
                    {
                        payload.Add(0x08);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url.Substring(10)));
                    }
                    else if (url.StartsWith("ftps://"))
                    {
                        payload.Add(0x09);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url.Substring(7)));
                    }
                    else if (url.StartsWith("sftp://"))
                    {
                        payload.Add(0x0A);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url.Substring(7)));
                    }
                    else if (url.StartsWith("smb://"))
                    {
                        payload.Add(0x0B);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url.Substring(8)));
                    }
                    else if (url.StartsWith("nfs://"))
                    {
                        payload.Add(0x0C);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url.Substring(6)));
                    }
                    else if (url.StartsWith("ftp://"))
                    {
                        payload.Add(0x0D);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url.Substring(6)));
                    }
                    else
                    {
                        payload.Add(0x00);
                        payload.AddRange(ASCIIEncoding.ASCII.GetBytes(url));
                    }
                }
                else if (r.DataType == Record.TEXT_EN)
                // Encode the text with the correct language code
                {
                    payload.Add(0x02);
                    payload.Add(0x65);
                    payload.Add(0x6E);
                    payload.AddRange(r.Data);
                }
                else if (r.DataType == Record.TEXT_FR)
                {
                    payload.Add(0x02);
                    payload.Add(0x66);
                    payload.Add(0x72);
                    payload.AddRange(r.Data);
                }
                else if (r.DataType == Record.BINARY)
                {
                    payload.AddRange(r.Data);
                }

                byte payload_length = (byte)payload.Count;

                encodedRecords.Add(header);
                encodedRecords.Add(type_length);
                encodedRecords.Add(payload_length);
                if (r.DataType == Record.TEXT_EN ||
                    r.DataType == Record.TEXT_FR ||
                    r.DataType == Record.URL)
                    encodedRecords.Add(type);
                encodedRecords.AddRange(payload);
            }

            // don't forget to specify the data length now !

            int length = encodedRecords.ToArray().Length;
            encodedRecords.Insert(0, (byte) (length % 256));
            encodedRecords.Insert(0, (byte)(length / 256));

            return encodedRecords.ToArray();
        }
    }
}
