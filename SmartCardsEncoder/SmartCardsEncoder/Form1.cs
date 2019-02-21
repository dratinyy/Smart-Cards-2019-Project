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
            richTextBox1.Text = BitConverter.ToString(RecordEncoder.Encode(recordList.ToArray()));
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