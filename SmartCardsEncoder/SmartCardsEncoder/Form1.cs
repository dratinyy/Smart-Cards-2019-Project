using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SmartCardsEncoder
{
    public partial class Form1 : Form
    {
        List<Record> recordList = new List<Record>();
        int currentIndex;

        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            Record record = new Record();
            recordListView.Items.Add("Record");
            recordList.Add(record);
            datatTypeComboBox.SelectedIndex = 0;
            dataContentRichBox.Text = "";
            currentIndex = recordList.Count - 1;
        }

        private void listView1_SelectedIndexChanged(object sender, EventArgs e)
        {
            ListView.SelectedIndexCollection indices = recordListView.SelectedIndices;
            if (indices.Count > 0)
            {
                currentIndex = indices[0];
                Record selectedRecord = recordList.ElementAt(currentIndex);
                dataContentRichBox.Text = ASCIIEncoding.ASCII.GetString(selectedRecord.Data.ToArray(), 0, selectedRecord.Data.Count);
                datatTypeComboBox.SelectedIndex = selectedRecord.DataType;
            }
        }

        private void saveRecordButton_Click(object sender, EventArgs e)
        {
            if (currentIndex > -1 && currentIndex < recordList.Count)
            {
                Record selectedRecord = recordList.ElementAt(currentIndex);
                selectedRecord.DataType = datatTypeComboBox.SelectedIndex;
                selectedRecord.Data = new List<byte>(ASCIIEncoding.ASCII.GetBytes(dataContentRichBox.Text));
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            byte[] recordData = RecordEncoder.Encode(recordList.ToArray());
            richTextBox1.Text = BitConverter.ToString(recordData);

            byte[] command = new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01, 0x00 };
            byte[] response = new byte[200];
            int response_length = response.Length;
            int result = AskReaderLib.CSC.CSC_ISOCommand(command, command.Length, response, ref response_length);

            if (result != AskReaderLib.CSC.RCSC_Ok)
            {
                Console.WriteLine("Bad return code from SELECT APPLICATION: " + result);
                return;
            }

            command = new byte[] { 0x00, 0xA4, 0x00, 0x0C, 0x02, 0xE1, 0x03 };
            response = new byte[200];
            response_length = response.Length;
            result = AskReaderLib.CSC.CSC_ISOCommand(command, command.Length, response, ref response_length);

            if (result != AskReaderLib.CSC.RCSC_Ok)
            {
                Console.WriteLine("Bad return code from SELECT CC FILE: " + result);
                return;
            }


            command = new byte[] { 0x00, 0xB0, 0x00, 0x00, 0x0F};
            response = new byte[200];
            response_length = response.Length;
            result = AskReaderLib.CSC.CSC_ISOCommand(command, command.Length, response, ref response_length);

            if (result != AskReaderLib.CSC.RCSC_Ok)
            {
                Console.WriteLine("Bad return code from READ CC FILE: " + result);
                return;
            }

            int MaxLe = (response[4] << 8) + response[5];
            int MaxLc = (response[6] << 8) + response[7];
            int file_id = (response[10] << 8) + response[11];
            int file_size = (response[12] << 8) + response[13];

            command = new byte[] { 0x00, 0xA4, 0x00, 0x0C, 0x02, response[10], response[11] };
            response = new byte[200];
            response_length = response.Length;
            result = AskReaderLib.CSC.CSC_ISOCommand(command, command.Length, response, ref response_length);

            if (result != AskReaderLib.CSC.RCSC_Ok)
            {
                Console.WriteLine("Bad return code from SELECT NDEF FILE: " + result);
                return;
            }
            
            byte data_offset_P1 = 0x00;
            byte data_offset_P2 = 0x00;
            byte length;

            // Lecture of NDEF
            while (recordData.Length > (data_offset_P1 << 8) + data_offset_P2)
            {
                length = (byte)Math.Min(MaxLc, (recordData.Length - (data_offset_P1 << 8) - data_offset_P2));

                command = new byte[length + 5];
                Array.Copy(new byte[] { 0x00, 0xB0, data_offset_P1, data_offset_P2, length }, 0, command, 0, 5);
                Array.Copy(recordData, ((data_offset_P1 << 8) + data_offset_P2), command, 5, length);
                response = new byte[length];
                response_length = response.Length;
                result = AskReaderLib.CSC.CSC_ISOCommand(command, command.Length, response, ref response_length);

                if (result != AskReaderLib.CSC.RCSC_Ok)
                {
                    Console.WriteLine("Bad return code from WRITE NDEF FILE: " + result);
                    return;
                }

                // Updating the offset
                int tempint = (data_offset_P1 << 8) + data_offset_P2 + length;
                data_offset_P1 = (byte)(tempint >> 8);
                data_offset_P2 = (byte)(tempint);
            }

        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (currentIndex > -1 && currentIndex < recordList.Count)
            {
                recordList.RemoveAt(currentIndex);
                datatTypeComboBox.SelectedIndex = 0;
                dataContentRichBox.Text = "";
                currentIndex = -1;
                recordListView.Items.RemoveAt(0);
            }
        }
    }
}