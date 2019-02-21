namespace SmartCardsEncoder
{
    partial class Form1
    {
        /// <summary>
        /// Variable nécessaire au concepteur.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Nettoyage des ressources utilisées.
        /// </summary>
        /// <param name="disposing">true si les ressources managées doivent être supprimées ; sinon, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Code généré par le Concepteur Windows Form

        /// <summary>
        /// Méthode requise pour la prise en charge du concepteur - ne modifiez pas
        /// le contenu de cette méthode avec l'éditeur de code.
        /// </summary>
        private void InitializeComponent()
        {
            this.recordListView = new System.Windows.Forms.ListView();
            this.label1 = new System.Windows.Forms.Label();
            this.button1 = new System.Windows.Forms.Button();
            this.datatTypeComboBox = new System.Windows.Forms.ComboBox();
            this.dataContentRichBox = new System.Windows.Forms.RichTextBox();
            this.saveRecordButton = new System.Windows.Forms.Button();
            this.button2 = new System.Windows.Forms.Button();
            this.richTextBox1 = new System.Windows.Forms.RichTextBox();
            this.button3 = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // recordListView
            // 
            this.recordListView.Location = new System.Drawing.Point(12, 25);
            this.recordListView.Name = "recordListView";
            this.recordListView.Size = new System.Drawing.Size(149, 168);
            this.recordListView.TabIndex = 0;
            this.recordListView.UseCompatibleStateImageBehavior = false;
            this.recordListView.SelectedIndexChanged += new System.EventHandler(this.listView1_SelectedIndexChanged);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(12, 9);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(72, 13);
            this.label1.TabIndex = 1;
            this.label1.Text = "NFD Records";
            // 
            // button1
            // 
            this.button1.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.button1.Location = new System.Drawing.Point(12, 199);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(149, 23);
            this.button1.TabIndex = 2;
            this.button1.Text = "Add Record";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // datatTypeComboBox
            // 
            this.datatTypeComboBox.FormattingEnabled = true;
            this.datatTypeComboBox.Items.AddRange(new object[] {
            "URL",
            "TEXT-EN",
            "TEXT-FR",
            "BINARY"});
            this.datatTypeComboBox.Location = new System.Drawing.Point(167, 25);
            this.datatTypeComboBox.Name = "datatTypeComboBox";
            this.datatTypeComboBox.Size = new System.Drawing.Size(169, 21);
            this.datatTypeComboBox.TabIndex = 3;
            // 
            // dataContentRichBox
            // 
            this.dataContentRichBox.Location = new System.Drawing.Point(167, 52);
            this.dataContentRichBox.Name = "dataContentRichBox";
            this.dataContentRichBox.Size = new System.Drawing.Size(169, 141);
            this.dataContentRichBox.TabIndex = 4;
            this.dataContentRichBox.Text = "";
            // 
            // saveRecordButton
            // 
            this.saveRecordButton.BackColor = System.Drawing.Color.Transparent;
            this.saveRecordButton.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.saveRecordButton.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F);
            this.saveRecordButton.ForeColor = System.Drawing.Color.Black;
            this.saveRecordButton.Location = new System.Drawing.Point(167, 199);
            this.saveRecordButton.Name = "saveRecordButton";
            this.saveRecordButton.Size = new System.Drawing.Size(169, 23);
            this.saveRecordButton.TabIndex = 5;
            this.saveRecordButton.Text = "Save record";
            this.saveRecordButton.UseVisualStyleBackColor = false;
            this.saveRecordButton.Click += new System.EventHandler(this.saveRecordButton_Click);
            // 
            // button2
            // 
            this.button2.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.button2.Location = new System.Drawing.Point(12, 228);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(149, 23);
            this.button2.TabIndex = 6;
            this.button2.Text = "Encode";
            this.button2.UseVisualStyleBackColor = true;
            this.button2.Click += new System.EventHandler(this.button2_Click);
            // 
            // richTextBox1
            // 
            this.richTextBox1.Location = new System.Drawing.Point(12, 257);
            this.richTextBox1.Name = "richTextBox1";
            this.richTextBox1.Size = new System.Drawing.Size(324, 194);
            this.richTextBox1.TabIndex = 7;
            this.richTextBox1.Text = "";
            // 
            // button3
            // 
            this.button3.BackColor = System.Drawing.Color.Transparent;
            this.button3.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.button3.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F);
            this.button3.ForeColor = System.Drawing.Color.Black;
            this.button3.Location = new System.Drawing.Point(167, 228);
            this.button3.Name = "button3";
            this.button3.Size = new System.Drawing.Size(169, 23);
            this.button3.TabIndex = 8;
            this.button3.Text = "Delete record";
            this.button3.UseVisualStyleBackColor = false;
            this.button3.Click += new System.EventHandler(this.button3_Click);
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(348, 461);
            this.Controls.Add(this.button3);
            this.Controls.Add(this.richTextBox1);
            this.Controls.Add(this.button2);
            this.Controls.Add(this.saveRecordButton);
            this.Controls.Add(this.dataContentRichBox);
            this.Controls.Add(this.datatTypeComboBox);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.recordListView);
            this.Cursor = System.Windows.Forms.Cursors.Default;
            this.Name = "Form1";
            this.Text = "Form1";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ListView recordListView;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.ComboBox datatTypeComboBox;
        private System.Windows.Forms.RichTextBox dataContentRichBox;
        private System.Windows.Forms.Button saveRecordButton;
        private System.Windows.Forms.Button button2;
        private System.Windows.Forms.RichTextBox richTextBox1;
        private System.Windows.Forms.Button button3;
    }
}

