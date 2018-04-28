namespace Aika_Crypter
{
    partial class Form1
    {
        /// <summary>
        /// Обязательная переменная конструктора.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Освободить все используемые ресурсы.
        /// </summary>
        /// <param name="disposing">истинно, если управляемый ресурс должен быть удален; иначе ложно.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Код, автоматически созданный конструктором форм Windows

        /// <summary>
        /// Требуемый метод для поддержки конструктора — не изменяйте 
        /// содержимое этого метода с помощью редактора кода.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Form1));
            this.pi = new System.Windows.Forms.CheckBox();
            this.native = new System.Windows.Forms.CheckBox();
            this.startup = new System.Windows.Forms.CheckBox();
            this.obf = new System.Windows.Forms.CheckBox();
            this.punp = new System.Windows.Forms.CheckBox();
            this.antivm = new System.Windows.Forms.CheckBox();
            this.key = new System.Windows.Forms.TextBox();
            this.button1 = new System.Windows.Forms.Button();
            this.label2 = new System.Windows.Forms.Label();
            this.button2 = new System.Windows.Forms.Button();
            this.encrypt = new System.Windows.Forms.Button();
            this.openFileDialog1 = new System.Windows.Forms.OpenFileDialog();
            this.fpath = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.managed = new System.Windows.Forms.CheckBox();
            this.si = new System.Windows.Forms.CheckBox();
            this.openFileDialog2 = new System.Windows.Forms.OpenFileDialog();
            this.pictureBox2 = new System.Windows.Forms.PictureBox();
            this.label4 = new System.Windows.Forms.Label();
            this.button3 = new System.Windows.Forms.Button();
            this.icopath = new System.Windows.Forms.TextBox();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox2)).BeginInit();
            this.SuspendLayout();
            // 
            // pi
            // 
            this.pi.AutoSize = true;
            this.pi.Enabled = false;
            this.pi.Font = new System.Drawing.Font("Rockwell", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.pi.Location = new System.Drawing.Point(556, 318);
            this.pi.Name = "pi";
            this.pi.Size = new System.Drawing.Size(123, 20);
            this.pi.TabIndex = 1;
            this.pi.Text = "Process injection";
            this.pi.UseVisualStyleBackColor = true;
            this.pi.CheckedChanged += new System.EventHandler(this.checkBox1_CheckedChanged);
            // 
            // native
            // 
            this.native.AutoSize = true;
            this.native.Font = new System.Drawing.Font("Rockwell", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.native.Location = new System.Drawing.Point(556, 406);
            this.native.Name = "native";
            this.native.Size = new System.Drawing.Size(64, 20);
            this.native.TabIndex = 2;
            this.native.Text = "Native";
            this.native.UseVisualStyleBackColor = true;
            this.native.CheckedChanged += new System.EventHandler(this.checkBox2_CheckedChanged);
            // 
            // startup
            // 
            this.startup.AutoSize = true;
            this.startup.BackColor = System.Drawing.Color.Transparent;
            this.startup.Font = new System.Drawing.Font("Rockwell", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.startup.Location = new System.Drawing.Point(388, 318);
            this.startup.Name = "startup";
            this.startup.Size = new System.Drawing.Size(69, 20);
            this.startup.TabIndex = 3;
            this.startup.Text = "Startup";
            this.startup.UseVisualStyleBackColor = false;
            this.startup.CheckedChanged += new System.EventHandler(this.checkBox3_CheckedChanged);
            // 
            // obf
            // 
            this.obf.AutoSize = true;
            this.obf.Font = new System.Drawing.Font("Rockwell", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.obf.Location = new System.Drawing.Point(388, 345);
            this.obf.Name = "obf";
            this.obf.Size = new System.Drawing.Size(87, 20);
            this.obf.TabIndex = 4;
            this.obf.Text = "Obfuscate";
            this.obf.UseVisualStyleBackColor = true;
            this.obf.CheckedChanged += new System.EventHandler(this.checkBox4_CheckedChanged);
            // 
            // punp
            // 
            this.punp.AutoSize = true;
            this.punp.Font = new System.Drawing.Font("Rockwell", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.punp.Location = new System.Drawing.Point(388, 380);
            this.punp.Name = "punp";
            this.punp.Size = new System.Drawing.Size(60, 20);
            this.punp.TabIndex = 5;
            this.punp.Text = "Pump";
            this.punp.UseVisualStyleBackColor = true;
            this.punp.CheckedChanged += new System.EventHandler(this.checkBox5_CheckedChanged);
            // 
            // antivm
            // 
            this.antivm.AutoSize = true;
            this.antivm.Font = new System.Drawing.Font("Rockwell", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.antivm.Location = new System.Drawing.Point(388, 406);
            this.antivm.Name = "antivm";
            this.antivm.Size = new System.Drawing.Size(73, 20);
            this.antivm.TabIndex = 6;
            this.antivm.Text = "Anti VM";
            this.antivm.UseVisualStyleBackColor = true;
            this.antivm.CheckedChanged += new System.EventHandler(this.checkBox6_CheckedChanged);
            // 
            // key
            // 
            this.key.Location = new System.Drawing.Point(60, 321);
            this.key.Name = "key";
            this.key.Size = new System.Drawing.Size(173, 20);
            this.key.TabIndex = 7;
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(249, 321);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(58, 19);
            this.button1.TabIndex = 8;
            this.button1.Text = "...";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Rockwell", 11.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label2.Location = new System.Drawing.Point(12, 321);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(34, 17);
            this.label2.TabIndex = 9;
            this.label2.Text = "Key";
            // 
            // button2
            // 
            this.button2.Location = new System.Drawing.Point(249, 362);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(58, 20);
            this.button2.TabIndex = 10;
            this.button2.Text = "...";
            this.button2.UseVisualStyleBackColor = true;
            this.button2.Click += new System.EventHandler(this.button2_Click);
            // 
            // encrypt
            // 
            this.encrypt.BackColor = System.Drawing.Color.Violet;
            this.encrypt.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.encrypt.Font = new System.Drawing.Font("Rockwell", 14.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.encrypt.ForeColor = System.Drawing.Color.Indigo;
            this.encrypt.Location = new System.Drawing.Point(249, 446);
            this.encrypt.Name = "encrypt";
            this.encrypt.Size = new System.Drawing.Size(193, 55);
            this.encrypt.TabIndex = 11;
            this.encrypt.Text = "Encrypt";
            this.encrypt.UseVisualStyleBackColor = false;
            this.encrypt.Click += new System.EventHandler(this.button3_Click);
            // 
            // openFileDialog1
            // 
            this.openFileDialog1.FileName = "openFileDialog1";
            // 
            // fpath
            // 
            this.fpath.Location = new System.Drawing.Point(60, 362);
            this.fpath.Name = "fpath";
            this.fpath.Size = new System.Drawing.Size(173, 20);
            this.fpath.TabIndex = 12;
            this.fpath.TextChanged += new System.EventHandler(this.textBox2_TextChanged);
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Rockwell", 11.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label3.Location = new System.Drawing.Point(12, 362);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(35, 17);
            this.label3.TabIndex = 13;
            this.label3.Text = "File";
            // 
            // managed
            // 
            this.managed.AutoSize = true;
            this.managed.Font = new System.Drawing.Font("Rockwell", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.managed.Location = new System.Drawing.Point(556, 380);
            this.managed.Name = "managed";
            this.managed.Size = new System.Drawing.Size(82, 20);
            this.managed.TabIndex = 17;
            this.managed.Text = "Managed";
            this.managed.UseVisualStyleBackColor = true;
            this.managed.CheckedChanged += new System.EventHandler(this.checkBox1_CheckedChanged_1);
            // 
            // si
            // 
            this.si.AutoSize = true;
            this.si.Font = new System.Drawing.Font("Rockwell", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.si.Location = new System.Drawing.Point(556, 345);
            this.si.Name = "si";
            this.si.Size = new System.Drawing.Size(99, 20);
            this.si.TabIndex = 18;
            this.si.Text = "Self injection";
            this.si.UseVisualStyleBackColor = true;
            this.si.CheckedChanged += new System.EventHandler(this.si_CheckedChanged);
            // 
            // openFileDialog2
            // 
            this.openFileDialog2.FileName = "openFileDialog2";
            // 
            // pictureBox2
            // 
            this.pictureBox2.Image = global::Aika_Crypter.Properties.Resources.ezgif_6_2c461c68d1;
            this.pictureBox2.Location = new System.Drawing.Point(0, 0);
            this.pictureBox2.Name = "pictureBox2";
            this.pictureBox2.Size = new System.Drawing.Size(694, 298);
            this.pictureBox2.TabIndex = 20;
            this.pictureBox2.TabStop = false;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Rockwell", 11.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label4.Location = new System.Drawing.Point(12, 404);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(39, 17);
            this.label4.TabIndex = 16;
            this.label4.Text = "Icon";
            // 
            // button3
            // 
            this.button3.Location = new System.Drawing.Point(249, 400);
            this.button3.Name = "button3";
            this.button3.Size = new System.Drawing.Size(58, 20);
            this.button3.TabIndex = 15;
            this.button3.Text = "...";
            this.button3.UseVisualStyleBackColor = true;
            this.button3.Click += new System.EventHandler(this.button3_Click_1);
            // 
            // icopath
            // 
            this.icopath.Location = new System.Drawing.Point(60, 401);
            this.icopath.Name = "icopath";
            this.icopath.Size = new System.Drawing.Size(173, 20);
            this.icopath.TabIndex = 14;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.AutoSize = true;
            this.BackColor = System.Drawing.Color.Lavender;
            this.ClientSize = new System.Drawing.Size(685, 513);
            this.Controls.Add(this.pictureBox2);
            this.Controls.Add(this.si);
            this.Controls.Add(this.managed);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.button3);
            this.Controls.Add(this.icopath);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.fpath);
            this.Controls.Add(this.encrypt);
            this.Controls.Add(this.button2);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.button1);
            this.Controls.Add(this.key);
            this.Controls.Add(this.antivm);
            this.Controls.Add(this.punp);
            this.Controls.Add(this.obf);
            this.Controls.Add(this.startup);
            this.Controls.Add(this.native);
            this.Controls.Add(this.pi);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedToolWindow;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "Form1";
            this.Text = "Aika Crypter";
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox2)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.CheckBox pi;
        private System.Windows.Forms.CheckBox native;
        private System.Windows.Forms.CheckBox startup;
        private System.Windows.Forms.CheckBox obf;
        private System.Windows.Forms.CheckBox punp;
        private System.Windows.Forms.CheckBox antivm;
        private System.Windows.Forms.TextBox key;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Button button2;
        private System.Windows.Forms.Button encrypt;
        private System.Windows.Forms.OpenFileDialog openFileDialog1;
        private System.Windows.Forms.TextBox fpath;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.CheckBox managed;
        private System.Windows.Forms.CheckBox si;
        private System.Windows.Forms.PictureBox pictureBox2;
        private System.Windows.Forms.OpenFileDialog openFileDialog2;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Button button3;
        private System.Windows.Forms.TextBox icopath;
    }
}

