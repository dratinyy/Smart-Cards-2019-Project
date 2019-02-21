using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
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

        private void Button1_Click(object sender, EventArgs e)
        {
            AskReaderLib.CSC.sCARD_SearchExtTag SearchExtender;
            int Status;
            byte[] ATR;
            ATR = new byte[200];
            int lgATR;
            lgATR = 200;
            int Com=0;
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
                    txtCom.Text =  "Error :" + Status.ToString ("X");
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

                    byte[] command = { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00 };
                    int command_length = command.Length;
                    byte[] response = new byte[200];
                    int response_length = response.Length;

                    int result = AskReaderLib.CSC.CSC_ISOCommand(command, command_length, response, ref response_length);

                    if (result != AskReaderLib.CSC.RCSC_Ok)
                    {
                        Console.WriteLine("Bad return code from SELECT APPLICATION command : " + result);
                        return;
                    }
                        byte[] temp = new byte[response_length];
                        Array.Copy(response, 0, temp, 0, response_length);
                        String resp = BitConverter.ToString(temp);

                    Console.WriteLine("[SELECT APPLICATION] Response from card (" + response_length + " bytes) : " + resp);
                    if (response_length < 2 || !response[response_length - 2].Equals(0x90) || !response[response_length - 1].Equals(0x00))
                    {
                        return;
                    }

                    byte[] command2 = { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03 };
                    int command2_length = command2.Length;
                    response = new byte[200];
                    response_length = response.Length;

                    result = AskReaderLib.CSC.CSC_ISOCommand(command2, command2_length, response, ref response_length);

                    if (result != AskReaderLib.CSC.RCSC_Ok)
                    {
                        Console.WriteLine("Bad return code from SELECT FILE command : " + result);
                        return;
                    }

                    temp = new byte[response_length];
                    Array.Copy(response, 0, temp, 0, response_length);
                    resp = BitConverter.ToString(temp);

                    Console.WriteLine("[SELECT FILE] Response from card (" + response_length + " bytes) : " + resp);
                    if (response_length < 2 || !response[response_length - 2].Equals(0x90) || !response[response_length - 1].Equals(0x00))
                    {
                        return;
                    }

                    byte data_offset_P1 = 0x00, data_offset_P2 = 0x00;
                    byte[] command3 = { 0x00, 0xB0, data_offset_P1, data_offset_P2, 0x0F };
                    int command3_length = command3.Length;
                    response = new byte[200];
                    response_length = response.Length;

                    result = AskReaderLib.CSC.CSC_ISOCommand(command3, command3_length, response, ref response_length);

                    if (result != AskReaderLib.CSC.RCSC_Ok)
                    {
                        Console.WriteLine("Bad return code from READ BINARY command : " + result);
                        return;
                    }

                    temp = new byte[response_length];
                    Array.Copy(response, 0, temp, 0, response_length);
                    resp = BitConverter.ToString(temp);

                    Console.WriteLine("[READ BINARY] Response from card (" + response_length + " bytes) : " + resp);
                    if (response_length < 2 || !response[response_length - 2].Equals(0x90) || !response[response_length - 1].Equals(0x00))
                    {
                        return;
                    }

                    int MaxLe = (response[4] << 8) + response[5];
                    int MaxLc = (response[6] << 8) + response[7];
                    int file_id = (response[10] << 8) + response[11];
                    int file_size = (response[12] << 8) + response[13];

                    Console.WriteLine("[READ BINARY] Parsed data: Le=" + MaxLe + ", Lc=" + MaxLc + ", fileid=" + file_id + ", filesz=" + file_size);

                    byte[] command4 = { 0x00, 0xA4, 0x00, 0x0C, 0x02, response[10], response[11] };
                    int command4_length = command4.Length;
                    response = new byte[200];
                    response_length = response.Length;

                    result = AskReaderLib.CSC.CSC_ISOCommand(command4, command4_length, response, ref response_length);

                    if (result != AskReaderLib.CSC.RCSC_Ok)
                    {
                        Console.WriteLine("Bad return code from SELECT FILE command : " + result);
                        return;
                    }

                    temp = new byte[response_length];
                    Array.Copy(response, 0, temp, 0, response_length);
                    resp = BitConverter.ToString(temp);

                    Console.WriteLine("[SELECT FILE] Response from card (" + response_length + " bytes) : " + resp);
                    if (response_length < 2 || !response[response_length - 2].Equals(0x90) || !response[response_length - 1].Equals(0x00))
                    {
                        return;
                    }

                    data_offset_P1 = 0x00;
                    data_offset_P2 = 0x00;
                    byte length = (byte)MaxLe;

                    byte[] file_content = new byte[file_size];

                    while (file_size > (data_offset_P1 << 8) + data_offset_P2)
                    {
                        length = (byte)Math.Min(MaxLe, (file_size - (data_offset_P1 << 8) - data_offset_P2));

                        byte[] command5 = { 0x00, 0xB0, data_offset_P1, data_offset_P2, length };
                        int command5_length = command5.Length;
                        response = new byte[200];
                        response_length = response.Length;

                        result = AskReaderLib.CSC.CSC_ISOCommand(command5, command5_length, response, ref response_length);

                        if (result != AskReaderLib.CSC.RCSC_Ok)
                        {
                            Console.WriteLine("Bad return code from READ BINARY command : " + result);
                            return;
                        }

                        temp = new byte[response_length];
                        Array.Copy(response, 0, temp, 0, response_length);
                        Array.Copy(response, 1, file_content, ((data_offset_P1 << 8) + data_offset_P2), response_length - 3);
                        resp = BitConverter.ToString(temp);
                        Console.WriteLine("[READ BINARY] Response from card (" + response_length + " bytes) : " + resp);

                        if (response_length < 2 || !response[response_length - 2].Equals(0x90) || !response[response_length - 1].Equals(0x00))
                        {
                            return;
                        }

                        int tempint = (data_offset_P1 << 8) + data_offset_P2 + length;
                        data_offset_P1 = (byte)(tempint >> 8);
                        data_offset_P2 = (byte)(tempint);
                    }

                    resp = BitConverter.ToString(file_content);
                    Console.WriteLine("[READ BINARY] Full file content: " + resp);

                    int offset = 0;

                    while (offset < file_size)  
                    {

                        int message_size = (file_content[offset] << 8) + file_content[offset + 1];
                        byte type_length = file_content[offset + 3];
                        byte payload_length = file_content[offset + 4];
                        Console.WriteLine("Type length is " + type_length + ", Payload length is " + payload_length);
                        byte[] type = new byte[type_length];
                        Array.Copy(file_content, 5, type, 0, type_length);
                        byte[] payload = new byte[payload_length];
                        Array.Copy(file_content, 5 + type_length, payload, 0, payload_length);
                        resp = BitConverter.ToString(type);
                        Console.WriteLine("TYPE IS: " + resp);
                        resp = BitConverter.ToString(payload);
                        Console.WriteLine("PAYLOAD IS: " + resp);
                        Console.WriteLine("PAYLOAD IS: " + System.Text.Encoding.ASCII.GetString(payload));
                        //offset += message_size;
                        offset += file_size;
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