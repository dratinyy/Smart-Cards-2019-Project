using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace CSharpNETTestASKCSCDLL
{
	public partial class Form1 : Form
	{
		public Form1()
		{
			InitializeComponent();
		}

		private void Form1_Load(object sender, EventArgs e)
		{

		}

		/**
		 * data1 and data2 used for the id of the file to read
		 * data1 and data2 used for data offset in read binary, data3 used as length
		 * returns a Tuple with the response and its length
		 */
		private Tuple<byte[], int> Send_ISO_Command(int select_command, byte data1, byte data2, byte data3, byte[] extra_data = null)
		{
			byte[] command;
			string command_name;
			switch (select_command)
			{
				//Select application
				case 1:
					command = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00 };
					command_name = "SELECT APPLICATION";
					break;
				//Select file
				case 2:
					command = new byte[] { 0x00, 0xA4, 0x00, 0x0C, 0x02, data1, data2 };
					command_name = "SELECT  FILE";
					break;
                //Read binary
                case 3:
                    command = new byte[] { 0x00, 0xB0, data1, data2, data3 };
                    command_name = "READ BINARY";
                    break;
                //Write binary
                case 4:
                    command = new byte[5 + extra_data.Length];
                    new byte[] { 0x00, 0xD6, data1, data2, data3 }.CopyTo(command, 0);
                    extra_data.CopyTo(command, 5);
                    command_name = "WRITE BINARY";
                    break;
                default:
					return null;
			}

			int command_length = command.Length;
			byte[] response = new byte[200];
			int response_length = response.Length;

			int result = AskReaderLib.CSC.CSC_ISOCommand(command, command_length, response, ref response_length);

			if (result != AskReaderLib.CSC.RCSC_Ok)
			{
				Console.WriteLine("Bad return code from " + command_name + " command : " + result);
				return null;
			}
			byte[] temp = new byte[response_length];
			Array.Copy(response, 0, temp, 0, response_length);
			String resp = BitConverter.ToString(temp);

			Console.WriteLine("[" + command_name + "] Response from card (" + response_length + " bytes) : " + resp);
			if (response_length < 2 || !response[response_length - 2].Equals(0x90) || !response[response_length - 1].Equals(0x00))
			{
				return null;
			}

			return Tuple.Create(response, response_length);
		}

		private string URI_identifier_code(byte id_code)
		{
			string res;
			switch (id_code)
			{
				case 0x00:
					res = ""; break;
				case 0x01:
					res = "http://www."; break;
				case 0x02:
					res = "https://www."; break;
				case 0x03:
					res = "http://"; break;
				case 0x04:
					res = "https://"; break;
				case 0x05:
					res = "tel:"; break;
				case 0x06:
					res = "mailto:"; break;
				case 0x07:
					res = "ftp://anonymous:anonymous@"; break;
				case 0x08:
					res = "ftp://ftp."; break;
				case 0x09:
					res = "ftps://"; break;
				case 0x0A:
					res = "sftp://"; break;
				case 0x0B:
					res = "smb://"; break;
				case 0x0C:
					res = "nfs://"; break;
				case 0x0D:
					res = "ftp://"; break;
				case 0x0E:
					res = "dav://"; break;
				case 0x0F:
					res = "news:"; break;
				case 0x10:
					res = "telnet://"; break;
				case 0x11:
					res = "imap:"; break;
				case 0x12:
					res = "rtsp://"; break;
				case 0x13:
					res = "urn:"; break;
				case 0x14:
					res = "pop:"; break;
				case 0x15:
					res = "sip:"; break;
				case 0x16:
					res = "sips:"; break;
				case 0x17:
					res = "tftp:"; break;
				case 0x18:
					res = "btspp://"; break;
				case 0x19:
					res = "btl2cap://"; break;
				case 0x1A:
					res = "btgoep://"; break;
				case 0x1B:
					res = "tcpobex://"; break;
				case 0x1C:
					res = "irdaobex://"; break;
				case 0x1D:
					res = "file://"; break;
				case 0x1E:
					res = "urn:epc:id:"; break;
				case 0x1F:
					res = "urn:epc:tag:"; break;
				case 0x20:
					res = "urn:epc:pat:"; break;
				case 0x21:
					res = "urn:epc:raw:"; break;
				case 0x22:
					res = "urn:epc:"; break;
				case 0x23:
					res = "urn:nfc:"; break;
				default:
					res = "RFU"; break;
			}
			return res;
		}

		private void Decode_Text(byte[] payload, int payload_len)
		{
			int offset = 0;

			int status = payload[offset++];
			int encoding = (status & 0b10000000) >> 7;
			int iana_lang_code_len = status & 0b00111111;

			if (encoding == 1) Console.WriteLine("utf-16"); else Console.WriteLine("utf-8");

			byte[] iana_lang_code = new byte[iana_lang_code_len];
			Array.Copy(payload, offset, iana_lang_code, 0, iana_lang_code_len);
			Console.WriteLine("IANA Code: " + BitConverter.ToString(iana_lang_code));
			Console.WriteLine("IANA Code: " + System.Text.Encoding.ASCII.GetString(iana_lang_code));
			offset += iana_lang_code_len;

			byte[] rest_of_payload = new byte[payload_len - iana_lang_code_len - 1];
			Array.Copy(payload, offset, rest_of_payload, 0, payload_len - iana_lang_code_len - 1);

			Console.WriteLine("PAYLOAD = " + BitConverter.ToString(rest_of_payload));
			Console.WriteLine("PAYLOAD = " + System.Text.Encoding.ASCII.GetString(rest_of_payload));
		}

		private void Decode_URI(byte[] payload, int payload_len)
		{
			Console.WriteLine("PAYLOAD = " + BitConverter.ToString(payload));
			string uri_prefix = URI_identifier_code(payload[0]);
			byte[] rest_of_payload = new byte[payload_len - 1];
			Array.Copy(payload, 1, rest_of_payload, 0, payload_len - 1);
			Console.WriteLine("PAYLOAD = " + uri_prefix + System.Text.Encoding.ASCII.GetString(payload));
		}

		private int Decode_NDEF(byte[] ndef)
		{
			Console.WriteLine("DECODING : " + BitConverter.ToString(ndef));
			int offset = 0;
			int me;

			do
			{
				// Parsing of the header (1st byte)
				byte header = ndef[offset++];
				int mb = (0b10000000 & header) >> 7;
				me = (0b01000000 & header) >> 6;
				int cf = (0b00100000 & header) >> 5;
				int sr = (0b00010000 & header) >> 4;
				int il = (0b00001000 & header) >> 3;
				int tnf = 0b00000111 & header;

				Console.WriteLine("mb = " + mb);
				Console.WriteLine("me = " + me);
				Console.WriteLine("cf = " + cf);
				Console.WriteLine("sr = " + sr);
				Console.WriteLine("il = " + il);
				Console.WriteLine("tnf = " + tnf);

				byte type_len = ndef[offset++];
				Console.WriteLine("type length = " + type_len);

				// Parsing of the payload length, different according to sr
				int payload_len;
				if (sr == 1)
				{
					payload_len = ndef[offset++];
				}
				else
				{
					payload_len = (ndef[offset] << 3 * 8) + (ndef[offset + 1] << 2 * 8) + (ndef[offset + 2] << 8) + ndef[offset + 3];
					offset += 4;
				}
				Console.WriteLine("Payload length = " + payload_len);

				// Parsing of the id length
				int id_len = 0;
				if (il == 1)
				{
					id_len = ndef[offset++];
				} // else id_len = 0
				Console.WriteLine("Id length = " + id_len);

				// Parsing of the type, on type_len bytes
				byte[] type = new byte[type_len];
				for (int i = 0; i < type_len; i++)
				{
					type[i] = ndef[offset++];
				}

				if(type[0] == 0x54)
				{
					Console.WriteLine("Type is text");
				}
				else if(type[0] == 0x55)
				{
					Console.WriteLine("Type is URI");
				}
				else if(type[0] == 0x53 && type[1] == 0x70)
				{
					Console.WriteLine("Type is smart poster");
				}
				else
				{
					Console.WriteLine("Type is: " + System.Text.Encoding.ASCII.GetString(type) + " (not supported)");
				}

				// Parsing of the id, on id_len bytes
				int id = 0;
				for (int i = 0; i < id_len; i++)
				{
					id += ndef[offset++] << (id_len - i - 1);
				}
				Console.WriteLine("Id = " + id);

				// We store the payload
				byte[] payload = new byte[payload_len];
				Array.Copy(ndef, offset, payload, 0, payload_len);
				offset += payload_len;

				// Different processing of the payload depending on the type
				if (type[0] == 0x54)
				{
					Decode_Text(payload, payload_len);
				}
				else if (type[0] == 0x55)
				{
					Decode_URI(payload, payload_len);
				}
				else if (type[0] == 0x53 && type[1] == 0x70)
				{
					Decode_NDEF(payload);
				}
				else //Unsupported type, we print it as ASCII
				{
					Console.WriteLine("PAYLOAD = " + BitConverter.ToString(payload));
					Console.WriteLine("PAYLOAD = " + System.Text.Encoding.ASCII.GetString(payload));
				}
			} while (me != 1);

			return offset;
		}

		private void Button1_Click(object sender, EventArgs e)
		{
			AskReaderLib.CSC.sCARD_SearchExtTag SearchExtender;
			int Status;
			byte[] ATR;
			ATR = new byte[200];
			int lgATR;
			lgATR = 200;
			int Com = 0;
			int SearchMask;

			txtCom.Text = "";
			txtCard.Text = "";

			try
			{
				AskReaderLib.CSC.SearchCSC();
				// user can also use line below to speed up coupler connection
				//AskReaderLib.CSC.Open ("COM2");

				// Define type of card to be detected: number of occurence for each loop
				SearchExtender.CONT = 0;
				SearchExtender.ISOB = 2;
				SearchExtender.ISOA = 2;
				SearchExtender.TICK = 1;
				SearchExtender.INNO = 2;
				SearchExtender.MIFARE = 0;
				SearchExtender.MV4k = 0;
				SearchExtender.MV5k = 0;
				SearchExtender.MONO = 0;

				if (AskReaderLib.CSC.EHP_PARAMS_EXT(1, 1, 0, 0, 0, 0, 0, 0, null, 0, 0) != AskReaderLib.CSC.RCSC_Ok)
				{
					Console.WriteLine("Unable to set AutoSelect to 0");
					return;
				}

				// Define type of card to be detected
				SearchMask = AskReaderLib.CSC.SEARCH_MASK_INNO | AskReaderLib.CSC.SEARCH_MASK_ISOB | AskReaderLib.CSC.SEARCH_MASK_ISOA | AskReaderLib.CSC.SEARCH_MASK_TICK;
				Status = AskReaderLib.CSC.SearchCardExt(ref SearchExtender, SearchMask, 1, 20, ref Com, ref lgATR, ATR);

				if (Status != AskReaderLib.CSC.RCSC_Ok)
					txtCom.Text = "Error :" + Status.ToString("X");
				else
					txtCom.Text = Com.ToString("X");

				if (Com == 2)
					txtCard.Text = "ISO14443A-4 no Calypso";
				else if (Com == 3)
					txtCard.Text = "INNOVATRON";
				else if (Com == 4)
					txtCard.Text = "ISOB14443B-4 Calypso";
				else if (Com == 5)
					txtCard.Text = "Mifare";
				else if (Com == 6)
					txtCard.Text = "CTS or CTM";
				else if (Com == 8)
					txtCard.Text = "ISO14443A-3 ";
				else if (Com == 9)
					txtCard.Text = "ISOB14443B-4 Calypso";
				else if (Com == 12)
					txtCard.Text = "ISO14443A-4 Calypso";
				else if (Com == 0x6F)
					txtCard.Text = "Card not found";
				else
					txtCard.Text = "";

				if (Com == 2 || Com == 4 || Com == 8 || Com == 9 || Com == 12)
				{
					byte[] response;
					int response_length;
					int result;
					byte[] temp;
					string resp;
					byte data_offset_P1, data_offset_P2;

					//Select application
					Send_ISO_Command(1, 0x00, 0x00, 0x00);

					//Select file
					Send_ISO_Command(2, 0xE1, 0x03, 0x00);

					//Read binary
					response = Send_ISO_Command(3, 0x00, 0x00, 0x0F).Item1;

					int MaxLe = (response[4] << 8) + response[5];
					int MaxLc = (response[6] << 8) + response[7];
					int file_id = (response[10] << 8) + response[11];
					int file_size = (response[12] << 8) + response[13];

					Console.WriteLine("[READ BINARY] Parsed data: Le=" + MaxLe + ", Lc=" + MaxLc + ", fileid=" + file_id + ", filesz=" + file_size);

					//Select file
					Send_ISO_Command(2, response[10], response[11], 0x00);

					data_offset_P1 = 0x00;
					data_offset_P2 = 0x00;
					byte length = (byte)MaxLe;

					byte[] file_content = new byte[file_size];

					// Lecture of NDEF
					while (file_size > (data_offset_P1 << 8) + data_offset_P2)
					{
						// length is MaxLe is there's enough to read or the remaining data
						length = (byte)Math.Min(MaxLe, (file_size - (data_offset_P1 << 8) - data_offset_P2));

						// Get the next chunk of data
						Tuple<byte[], int> response_tuple = Send_ISO_Command(3, data_offset_P1, data_offset_P2, length);
						response = response_tuple.Item1;
						response_length = response_tuple.Item2;

						// Stocking the chunk
						temp = new byte[response_length];
						Array.Copy(response, 0, temp, 0, response_length);
						resp = BitConverter.ToString(temp);

						Array.Copy(response, 1, file_content, ((data_offset_P1 << 8) + data_offset_P2), response_length - 3);

						// Updating the offset
						int tempint = (data_offset_P1 << 8) + data_offset_P2 + length;
						data_offset_P1 = (byte)(tempint >> 8);
						data_offset_P2 = (byte)(tempint);
					}

					//resp = BitConverter.ToString(file_content);
					Console.WriteLine("[READ BINARY] Full file content: " + BitConverter.ToString(file_content));

					int nlen = (file_content[0] << 8) + file_content[1];
					Console.WriteLine("nlen = {0}", nlen);
					byte[] actual_file_content = new byte[nlen];
					Array.Copy(file_content, 2, actual_file_content, 0, nlen);

					int offset = Decode_NDEF(actual_file_content);
					Console.WriteLine("offset = {0}, nlen = {1}", offset, nlen);
					if(offset != nlen)
					{
						Console.WriteLine("We didn't read everything, check if there's an early me set at 1");
					}

				}
			}
			catch
			{
				MessageBox.Show("Error on trying do deal with reader");
			}
			AskReaderLib.CSC.Close();
		}

        private static byte[] fromString(string data)
        {
            string converter = "0123456789ABCDEF";
            Regex.Match(data, "[0-9A-F](-[0-9A-F]{2})*");

            int offset = 0;
            List<byte> result = new List<byte>();
            char[] dataArr = data.ToCharArray();

            while (offset < data.Length)
            {
                result.Add((byte) (converter.IndexOf(dataArr[offset]) * 16 + converter.IndexOf(dataArr[offset + 1])));
                offset += 3;
            }

            Console.WriteLine(result.ToArray().ToString());
            return result.ToArray();
        }

        private void write(object sender, EventArgs e)
        {
            AskReaderLib.CSC.sCARD_SearchExtTag SearchExtender;
            int Status;
            byte[] ATR;
            ATR = new byte[200];
            int lgATR;
            lgATR = 200;
            int Com = 0;
            int SearchMask;

            txtCom.Text = "";
            txtCard.Text = "";

            try
            {
                AskReaderLib.CSC.SearchCSC();
                // user can also use line below to speed up coupler connection
                //AskReaderLib.CSC.Open ("COM2");

                // Define type of card to be detected: number of occurence for each loop
                SearchExtender.CONT = 0;
                SearchExtender.ISOB = 2;
                SearchExtender.ISOA = 2;
                SearchExtender.TICK = 1;
                SearchExtender.INNO = 2;
                SearchExtender.MIFARE = 0;
                SearchExtender.MV4k = 0;
                SearchExtender.MV5k = 0;
                SearchExtender.MONO = 0;

                if (AskReaderLib.CSC.EHP_PARAMS_EXT(1, 1, 0, 0, 0, 0, 0, 0, null, 0, 0) != AskReaderLib.CSC.RCSC_Ok)
                {
                    Console.WriteLine("Unable to set AutoSelect to 0");
                    return;
                }

                // Define type of card to be detected
                SearchMask = AskReaderLib.CSC.SEARCH_MASK_INNO | AskReaderLib.CSC.SEARCH_MASK_ISOB | AskReaderLib.CSC.SEARCH_MASK_ISOA | AskReaderLib.CSC.SEARCH_MASK_TICK;
                Status = AskReaderLib.CSC.SearchCardExt(ref SearchExtender, SearchMask, 1, 20, ref Com, ref lgATR, ATR);

                if (Status != AskReaderLib.CSC.RCSC_Ok)
                    txtCom.Text = "Error :" + Status.ToString("X");
                else
                    txtCom.Text = Com.ToString("X");

                if (Com == 2)
                    txtCard.Text = "ISO14443A-4 no Calypso";
                else if (Com == 3)
                    txtCard.Text = "INNOVATRON";
                else if (Com == 4)
                    txtCard.Text = "ISOB14443B-4 Calypso";
                else if (Com == 5)
                    txtCard.Text = "Mifare";
                else if (Com == 6)
                    txtCard.Text = "CTS or CTM";
                else if (Com == 8)
                    txtCard.Text = "ISO14443A-3 ";
                else if (Com == 9)
                    txtCard.Text = "ISOB14443B-4 Calypso";
                else if (Com == 12)
                    txtCard.Text = "ISO14443A-4 Calypso";
                else if (Com == 0x6F)
                    txtCard.Text = "Card not found";
                else
                    txtCard.Text = "";

                if (Com == 2 || Com == 4 || Com == 8 || Com == 9 || Com == 12)
                {
                    byte[] recordData = fromString(textBox1.Text);

                    // Select Application
                    Send_ISO_Command(1, 0x00, 0x00, 0x00);

                    // Select CC File
                    Send_ISO_Command(2, 0xE1, 0x03, 0x00);

                    // Read CC File
                    byte[] response = Send_ISO_Command(3, 0x00, 0x00, 0x0F).Item1;
                    int MaxLe = (response[4] << 8) + response[5];
                    int MaxLc = (response[6] << 8) + response[7];
                    int file_id = (response[10] << 8) + response[11];
                    int file_size = (response[12] << 8) + response[13];

                    // Select NDEF File
                    Send_ISO_Command(2, response[10], response[11], 0x00);
                    byte data_offset_P1 = 0x00;
                    byte data_offset_P2 = 0x00;
                    byte length;

                    // Write on NDEF File
                    while (recordData.Length > (data_offset_P1 << 8) + data_offset_P2)
                    {
                        length = (byte)Math.Min(MaxLc, (recordData.Length - (data_offset_P1 << 8) - data_offset_P2));

                        byte[] subArray = new byte[length];
                        Array.Copy(recordData, ((data_offset_P1 << 8) + data_offset_P2), subArray, 0, length);
                        Send_ISO_Command(4, data_offset_P1, data_offset_P2, length, subArray);

                        // Updating the offset
                        int tempint = (data_offset_P1 << 8) + data_offset_P2 + length;
                        data_offset_P1 = (byte)(tempint >> 8);
                        data_offset_P2 = (byte)(tempint);
                    }
                }
            }
            catch
            {
                MessageBox.Show("Error on trying do deal with reader");
            }
            AskReaderLib.CSC.Close();
        }
    }
}