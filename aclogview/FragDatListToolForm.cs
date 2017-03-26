using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Windows.Forms;

using aclogview.Properties;

namespace aclogview
{
    public partial class FragDatListToolForm : Form
    {
        public FragDatListToolForm()
        {
            InitializeComponent();
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            txtOutputFolder.Text = Settings.Default.FragDatFileOutputFolder;
            txtSearchPathRoot.Text = Settings.Default.FindOpcodeInFilesRoot;
            txtFileToProcess.Text = Settings.Default.FragDatFileToProcess;

            // Center to our owner, if we have one
            if (Owner != null)
                Location = new Point(Owner.Location.X + Owner.Width / 2 - Width / 2, Owner.Location.Y + Owner.Height / 2 - Height / 2);
        }

        protected override void OnClosing(CancelEventArgs e)
        {
            searchAborted = true;

            Settings.Default.FragDatFileOutputFolder = txtOutputFolder.Text;
            Settings.Default.FindOpcodeInFilesRoot = txtSearchPathRoot.Text;
            Settings.Default.FragDatFileToProcess = txtFileToProcess.Text;

            base.OnClosing(e);
        }

        private void btnChangeOutputFolder_Click(object sender, EventArgs e)
        {
            using (FolderBrowserDialog openFolder = new FolderBrowserDialog())
            {
                if (openFolder.ShowDialog() == DialogResult.OK)
                    txtOutputFolder.Text = openFolder.SelectedPath;
            }
        }

        private void btnChangeSearchPathRoot_Click(object sender, EventArgs e)
        {
            using (FolderBrowserDialog openFolder = new FolderBrowserDialog())
            {
                if (openFolder.ShowDialog() == DialogResult.OK)
                    txtSearchPathRoot.Text = openFolder.SelectedPath;
            }
        }

        private void btnChangeFileToProcess_Click(object sender, EventArgs e)
        {
            using (OpenFileDialog openFile = new OpenFileDialog())
            {
                openFile.Filter = "Frag Dat List (*.frags)|*.frags";
                openFile.DefaultExt = ".frags";

                if (openFile.ShowDialog() == DialogResult.OK)
                    txtFileToProcess.Text = openFile.FileName;
            }
        }


        private readonly List<string> filesToProcess = new List<string>();
        private int filesProcessed;
        private int fragmentsProcessed;
        private int totalHits;
        private int totalExceptions;
        private bool searchAborted;

        private void ResetVariables()
        {
            filesToProcess.Clear();
            filesProcessed = 0;
            fragmentsProcessed = 0;
            totalHits = 0;
            totalExceptions = 0;
            searchAborted = false;
        }


        private void btnStartBuild_Click(object sender, EventArgs e)
        {
            if (!Directory.Exists(txtOutputFolder.Text))
            {
                MessageBox.Show("Output folder does not exist.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            try
            {
                btnStartBuild.Enabled = false;
                groupBoxGeneralSettings.Enabled = false;
                groupBoxProcessFragDatListFile.Enabled = false;

                ResetVariables();

                filesToProcess.AddRange(Directory.GetFiles(txtSearchPathRoot.Text, "*.pcap", SearchOption.AllDirectories));
                filesToProcess.AddRange(Directory.GetFiles(txtSearchPathRoot.Text, "*.pcapng", SearchOption.AllDirectories));

                txtSearchPathRoot.Enabled = false;
                btnChangeSearchPathRoot.Enabled = false;
                chkCompressOutput.Enabled = false;
                chkIncludeFullPathAndFileName.Enabled = false;
                btnStopBuild.Enabled = true;

                timer1.Start();

                new Thread(() =>
                {
                    // Do the actual work here
                    DoBuild();

                    if (!Disposing && !IsDisposed)
                        btnStopBuild.BeginInvoke((Action)(() => btnStopBuild_Click(null, null)));
                }).Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());

                btnStopBuild_Click(null, null);
            }
        }

        private void btnStopBuild_Click(object sender, EventArgs e)
        {
            searchAborted = true;

            timer1.Stop();

            timer1_Tick(null, null);

            txtSearchPathRoot.Enabled = true;
            btnChangeSearchPathRoot.Enabled = true;
            chkCompressOutput.Enabled = true;
            chkIncludeFullPathAndFileName.Enabled = true;
            btnStartBuild.Enabled = true;
            btnStopBuild.Enabled = false;

            groupBoxGeneralSettings.Enabled = true;
            groupBoxProcessFragDatListFile.Enabled = true;
        }


        // ********************************************************************
        // *************************** Sample Files *************************** 
        // ********************************************************************
        private readonly FragDatListFile allFragDatFile = new FragDatListFile();
        private readonly FragDatListFile createObjectFragDatFile = new FragDatListFile();

        private void DoBuild()
        {
            // ********************************************************************
            // ************************ Adjust These Paths ************************ 
            // ********************************************************************
            allFragDatFile.CreateFile(Path.Combine(txtOutputFolder.Text, "All.frags"), chkCompressOutput.Checked ? FragDatListFile.CompressionType.DeflateStream : FragDatListFile.CompressionType.None);
            createObjectFragDatFile.CreateFile(Path.Combine(txtOutputFolder.Text, "CreateObject.frags"), chkCompressOutput.Checked ? FragDatListFile.CompressionType.DeflateStream : FragDatListFile.CompressionType.None);

            // Do not parallel this search
            foreach (var currentFile in filesToProcess)
            {
                if (searchAborted || Disposing || IsDisposed)
                    break;

                try
                {
                    ProcessFileForBuild(currentFile);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("File failed to process with exception: " + Environment.NewLine + ex, "Exception", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }

            // ********************************************************************
            // ****************************** Cleanup ***************************** 
            // ********************************************************************
            allFragDatFile.CloseFile();
            createObjectFragDatFile.CloseFile();
        }

        private void ProcessFileForBuild(string fileName)
        {
            var records = PCapReader.LoadPcap(fileName, ref searchAborted);

            // Temperorary objects
            var allFrags = new List<FragDatListFile.FragDatInfo>();
            var createObjectFrags = new List<FragDatListFile.FragDatInfo>();

            foreach (var record in records)
            {
                if (searchAborted || Disposing || IsDisposed)
                    return;

                // ********************************************************************
                // ************************ Custom Search Code ************************ 
                // ********************************************************************
                foreach (BlobFrag frag in record.netPacket.fragList_)
                {
                    try
                    {
                        if (frag.dat_.Length <= 4)
                            continue;

                        Interlocked.Increment(ref fragmentsProcessed);

                        FragDatListFile.PacketDirection packetDirection = (record.isSend ? FragDatListFile.PacketDirection.ClientToServer : FragDatListFile.PacketDirection.ServerToClient);

                        // Write to emperorary object
                        allFrags.Add(new FragDatListFile.FragDatInfo(packetDirection, record.index, frag.dat_));

                        BinaryReader fragDataReader = new BinaryReader(new MemoryStream(frag.dat_));

                        var messageCode = fragDataReader.ReadUInt32();

                        // Write to emperorary object
                        if (messageCode == 0xF745) // Create Object
                        {
                            Interlocked.Increment(ref totalHits);

                            createObjectFrags.Add(new FragDatListFile.FragDatInfo(packetDirection, record.index, frag.dat_));
                        }
                    }
                    catch
                    {
                        // Do something with the exception maybe
                        Interlocked.Increment(ref totalExceptions);
                    }
                }
            }

            string outputFileName = (chkIncludeFullPathAndFileName.Checked ? fileName : (Path.GetFileName(fileName)));

            // ********************************************************************
            // ************************* Write The Output ************************* 
            // ********************************************************************
            allFragDatFile.Write(new KeyValuePair<string, IList<FragDatListFile.FragDatInfo>>(outputFileName, allFrags));
            createObjectFragDatFile.Write(new KeyValuePair<string, IList<FragDatListFile.FragDatInfo>>(outputFileName, createObjectFrags));

            Interlocked.Increment(ref filesProcessed);
        }


        private void btnStartProcess_Click(object sender, EventArgs e)
        {
            try
            {
                btnStartProcess.Enabled = false;
                groupBoxGeneralSettings.Enabled = false;
                groupBoxFragDatListFileBuilder.Enabled = false;

                ResetVariables();

                filesToProcess.Add(txtFileToProcess.Text);

                txtFileToProcess.Enabled = false;
                btnChangeFileToProcess.Enabled = false;
                btnStopProcess.Enabled = true;

                timer1.Start();

                new Thread(() =>
                {
                    // Do the actual work here
                    DoProcess();

                    if (!Disposing && !IsDisposed)
                        btnStopProcess.BeginInvoke((Action)(() => btnStopProcess_Click(null, null)));
                }).Start();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());

                btnStopProcess_Click(null, null);
            }
        }

        private void btnStopProcess_Click(object sender, EventArgs e)
        {
            searchAborted = true;

            timer1.Stop();

            timer1_Tick(null, null);

            txtFileToProcess.Enabled = true;
            btnChangeFileToProcess.Enabled = true;
            btnStartProcess.Enabled = true;
            btnStopProcess.Enabled = false;

            groupBoxGeneralSettings.Enabled = true;
            groupBoxFragDatListFileBuilder.Enabled = true;
        }

        private void DoProcess()
        {
            // Do not parallel this search
            foreach (var currentFile in filesToProcess)
            {
                if (searchAborted || Disposing || IsDisposed)
                    break;

                try
                {
                    ProcessFileForExamination(currentFile);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("File failed to process with exception: " + Environment.NewLine + ex, "Exception", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void ProcessFileForExamination(string fileName)
        {
            var fragDatListFile = new FragDatListFile();
            DateTime start = DateTime.Now;

            if (!fragDatListFile.OpenFile(fileName))
                return;

            var itemTypesToParse = new List<ITEM_TYPE>();

            var itemTypeKeys = new Dictionary<ITEM_TYPE, List<string>>();
            // var itemTypeStreamWriters = new Dictionary<ITEM_TYPE, StreamWriter>();

            // If you only want to output a single item_type, you can change this code
            foreach (ITEM_TYPE itemType in Enum.GetValues(typeof(ITEM_TYPE)))
            {
                itemTypesToParse.Add(itemType);
                itemTypeKeys[itemType] = new List<string>();
                //itemTypeStreamWriters[itemType] = new StreamWriter(Path.Combine(txtOutputFolder.Text, itemType + ".csv.temp"));
            }

            try
            {
                TreeView treeView = new TreeView();

                Dictionary<uint, CM_Physics.CreateObject> weenies = new Dictionary<uint, CM_Physics.CreateObject>();
                List<CM_Physics.CreateObject> staticObjects = new List<CM_Physics.CreateObject>();
                Dictionary<ITEM_TYPE, List<Position>> processedPositions = new Dictionary<ITEM_TYPE, List<Position>>();


                while (true)
                {
                    if (searchAborted || Disposing || IsDisposed)
                        return;

                    KeyValuePair<string, List<FragDatListFile.FragDatInfo>> kvp;

                    if (!fragDatListFile.TryReadNext(out kvp))
                        break;

                    foreach (var frag in kvp.Value)
                    {
                        fragmentsProcessed++;

                        try
                        {
                            // ********************************************************************
                            // ********************** CUSTOM PROCESSING CODE ********************** 
                            // ********************************************************************
                            if (frag.Data.Length <= 4)
                                continue;

                            BinaryReader fragDataReader = new BinaryReader(new MemoryStream(frag.Data));

                            var messageCode = fragDataReader.ReadUInt32();

                            if (messageCode == 0xF745) // Create Object
                            {
                                var parsed = CM_Physics.CreateObject.read(fragDataReader);

                                // WriteUniqueTypes(parsed, itemTypeStreamWriters[parsed.wdesc._type], itemTypesToParse, itemTypeKeys);

                                CreateStaticObjectsList(parsed, staticObjects, weenies, processedPositions);

                            }
                        }
                        catch (EndOfStreamException) // This can happen when a frag is incomplete and we try to parse it
                        {
                            totalExceptions++;
                        }
                    }
                }

                WriteWeenieData(weenies, txtOutputFolder.Text);

                WriteStaticObjectData(staticObjects, txtOutputFolder.Text);

                MessageBox.Show($"Export completed at {DateTime.Now.ToString()} and took {(DateTime.Now - start).TotalMinutes} minutes.");
            }
            finally
            {
                //foreach (var streamWriter in itemTypeStreamWriters.Values)
                //    streamWriter.Close();

                fragDatListFile.CloseFile();

                Interlocked.Increment(ref filesProcessed);
            }

            // Read in the temp file and save it to a new file with the column headers
            foreach (var kvp in itemTypeKeys)
            {
                if (kvp.Value.Count > 0)
                {
                    using (var writer = new StreamWriter(Path.Combine(txtOutputFolder.Text, kvp.Key + ".csv")))
                    {
                        var sb = new StringBuilder();

                        for (int i = 0; i < kvp.Value.Count; i++)
                        {
                            if (i > 0)
                                sb.Append(',');

                            sb.Append(kvp.Value[i] ?? String.Empty);
                        }

                        writer.WriteLine(sb.ToString());

                        using (var reader = new StreamReader(Path.Combine(txtOutputFolder.Text, kvp.Key + ".csv.temp")))
                        {
                            string line;
                            while ((line = reader.ReadLine()) != null)
                                writer.WriteLine(line);
                        }
                    }
                }

                File.Delete(Path.Combine(txtOutputFolder.Text, kvp.Key + ".csv.temp"));
            }
        }

        private void CreateStaticObjectsList(CM_Physics.CreateObject parsed, List<CM_Physics.CreateObject> staticObjects, Dictionary<uint, CM_Physics.CreateObject> weenies, Dictionary<ITEM_TYPE, List<Position>> processedPositions)
        {
            try
            {
                // don't need undefined crap or players
                if (parsed.wdesc._type == ITEM_TYPE.TYPE_UNDEF || parsed.wdesc._wcid == 1)
                    return;

                if (!weenies.ContainsKey(parsed.wdesc._wcid))
                    weenies.Add(parsed.wdesc._wcid, parsed);

                if (!processedPositions.ContainsKey(parsed.wdesc._type))
                    processedPositions.Add(parsed.wdesc._type, new List<Position>());

                bool addIt = false;

                switch (parsed.wdesc._type)
                {
                    case ITEM_TYPE.TYPE_MISC:
                        if (parsed.wdesc._name.m_buffer == "Door" ||
                            parsed.wdesc._wcid == 9704 || // added per Ripley
                            parsed.physicsdesc.setup_id == 33556205 || // town signs, maybe?
                            parsed.wdesc._iconID == 100668115) // town signs, also maybe?
                            addIt = true;
                        break;
                    case ITEM_TYPE.TYPE_CREATURE:
                        if (parsed.wdesc._blipColor == 8) // NPC
                            addIt = true;
                        break;
                    case ITEM_TYPE.TYPE_LIFESTONE:
                    case ITEM_TYPE.TYPE_VENDOR_SHOPKEEP:
                    case ITEM_TYPE.TYPE_VENDOR_GROCER:
                        addIt = true;
                        break;
                    case ITEM_TYPE.TYPE_PORTAL:
                        if (parsed.wdesc._blipColor != 3) // white/temporary portals
                            addIt = true;
                        break;
                    case ITEM_TYPE.TYPE_CONTAINER:
                        //if (parsed.wdesc._wcid == 11697 || // floor hooks
                        //    parsed.wdesc._wcid == 9686 || // wall hooks
                        //    parsed.wdesc._wcid == 11698 || // ceiling hooks
                        //    parsed.wdesc._wcid == 9687) // house storage
                        //    addIt = true;
                        break;
                    default:
                        return;
                }

                // de-dupe based on position.
                if (addIt && !PositionRecorded(processedPositions[parsed.wdesc._type], parsed.physicsdesc.pos))
                {
                    staticObjects.Add(parsed);
                    processedPositions[parsed.wdesc._type].Add(parsed.physicsdesc.pos);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        private void WriteStaticObjectData(List<CM_Physics.CreateObject> staticObjects, string outputFolder)
        {
            string staticFolder = Path.Combine(outputFolder, "statics");
            if (Directory.Exists(staticFolder))
                Directory.Delete(staticFolder, true);

            Directory.CreateDirectory(staticFolder);

            Dictionary<ITEM_TYPE, int> fileCount = new Dictionary<ITEM_TYPE, int>();

            foreach (var parsed in staticObjects)
            {
                if (!fileCount.ContainsKey(parsed.wdesc._type))
                    fileCount.Add(parsed.wdesc._type, 0);

                try
                {
                    string fullFile = Path.Combine(staticFolder, $"{parsed.wdesc._type}_{fileCount[parsed.wdesc._type]}.sql");

                    if (File.Exists(fullFile))
                    {
                        FileInfo fi = new FileInfo(fullFile);

                        // go to the next file if it's bigger than a MB
                        if (fi.Length > (1048576))
                        {
                            fileCount[parsed.wdesc._type]++;
                            fullFile = Path.Combine(staticFolder, $"{parsed.wdesc._type}_{fileCount[parsed.wdesc._type]}.sql");
                        }
                    }

                    using (FileStream fs = new FileStream(fullFile, FileMode.Append))
                    {
                        using (StreamWriter writer = new StreamWriter(fs))
                        {
                            string line = "INSERT INTO `base_ace_object` (`baseAceObjectId`, `name`, `typeId`, `paletteId`, " +

                            // wdesc data
                            "`ammoType`, `blipColor`, `bitField`, `burden`, `combatUse`, `cooldownDuration`, " +
                            "`cooldownId`, `effects`, `containersCapacity`, `header`, `hookTypeId`, `iconId`, `iconOverlayId`, " +
                            "`iconUnderlayId`, `hookItemTypes`, `itemsCapacity`, `location`, `materialType`, " +
                            "`maxStackSize`, `maxStructure`, `radar`, `pscript`, `spellId`, `stackSize`, " +
                            "`structure`, `targetTypeId`, `usability`, `useRadius`, `validLocations`, `value`, " +
                            "`workmanship`, " +

                            // physics data
                            "`animationFrameId`, `defaultScript`, `defaultScriptIntensity`, `elasticity`, " +
                            "`friction`, `locationId`, `modelTableId`, `objectScale`, `physicsBitField`, " +
                            "`physicsTableId`, `motionTableId`, `soundTableId`, `physicsState`, `translucency`)" + Environment.NewLine + "VALUES (" +

                            // shove the wcid in here so we can tell the difference between weenie classes and real objects for analysis
                            $"{parsed.object_id}, '{parsed.wdesc._name.m_buffer.Replace("'", "''")}', {(int)parsed.wdesc._type}, {parsed.objdesc.paletteID}, " +

                            // wdesc data
                            $"{(int)parsed.wdesc._ammoType}, {parsed.wdesc._blipColor}, {parsed.wdesc._bitfield}, {parsed.wdesc._burden}, {parsed.wdesc._combatUse}, {parsed.wdesc._cooldown_duration}, " +
                            $"{parsed.wdesc._cooldown_id}, {parsed.wdesc._effects}, {parsed.wdesc._containersCapacity}, {parsed.wdesc.header}, {(int)parsed.wdesc._hook_type}, {parsed.wdesc._iconID}, {parsed.wdesc._iconOverlayID}, " +
                            $"{parsed.wdesc._iconUnderlayID}, {parsed.wdesc._hook_item_types}, {parsed.wdesc._itemsCapacity}, {parsed.wdesc._location}, {(int)parsed.wdesc._material_type}, " +
                            $"{parsed.wdesc._maxStackSize}, {parsed.wdesc._maxStructure}, {(int)parsed.wdesc._radar_enum}, {parsed.wdesc._pscript}, {parsed.wdesc._spellID}, {parsed.wdesc._stackSize}, " +
                            $"{parsed.wdesc._structure}, {(int)parsed.wdesc._targetType}, {(int)parsed.wdesc._useability}, {parsed.wdesc._useRadius}, {parsed.wdesc._valid_locations}, {parsed.wdesc._value}, " +
                            $"{parsed.wdesc._workmanship}, " +

                            // physics data.  note, model table is mis-parsed as setup_id.  the setup_id is actually "mtable", which is presumably motion table id.
                            $"{parsed.physicsdesc.animframe_id}, {(int)parsed.physicsdesc.default_script}, {parsed.physicsdesc.default_script_intensity}, {parsed.physicsdesc.elasticity}, " +
                            $"{parsed.physicsdesc.friction}, {parsed.physicsdesc.location_id}, {parsed.physicsdesc.setup_id}, {parsed.physicsdesc.object_scale}, {parsed.physicsdesc.bitfield}, " +
                            $"{parsed.physicsdesc.phstable_id}, {parsed.physicsdesc.mtable_id}, {parsed.physicsdesc.stable_id}, {parsed.physicsdesc.state}, {parsed.physicsdesc.translucency});" + Environment.NewLine;

                            // creates the weenieClass record
                            writer.WriteLine(line);

                            line = "INSERT INTO `ace_object` (`baseAceObjectId`, `weenieClassId`, `landblock`, `cell`, `posX`, `posY`, `posZ`, `qW`, `qX`, `qY`, `qZ`)" + Environment.NewLine +
                                $"VALUES ({parsed.object_id}, {parsed.wdesc._wcid}, {parsed.physicsdesc.pos.objcell_id >> 16}, {parsed.physicsdesc.pos.objcell_id & 0xFFFF}, " +
                                $"{parsed.physicsdesc.pos.frame.m_fOrigin.x}, {parsed.physicsdesc.pos.frame.m_fOrigin.y}, {parsed.physicsdesc.pos.frame.m_fOrigin.z}, " +
                                $"{parsed.physicsdesc.pos.frame.qw}, {parsed.physicsdesc.pos.frame.qx}, {parsed.physicsdesc.pos.frame.qy}, {parsed.physicsdesc.pos.frame.qz});" + Environment.NewLine;

                            writer.WriteLine(line);

                            bool once = false;
                            if (parsed.objdesc.subpalettes.Count > 0)
                            {
                                line = "INSERT INTO `ace_object_palette_changes` (`baseAceObjectId`, `subPaletteId`, `offset`, `length`)" + Environment.NewLine;

                                foreach (var subPalette in parsed.objdesc.subpalettes)
                                {
                                    if (once)
                                    {
                                        line += $"     , ({parsed.object_id}, {subPalette.subID}, {subPalette.offset}, {subPalette.numcolors})" + Environment.NewLine;
                                    }
                                    else
                                    {
                                        line += $"VALUES ({parsed.object_id}, {subPalette.subID}, {subPalette.offset}, {subPalette.numcolors})" + Environment.NewLine;
                                        once = true;
                                    }
                                }

                                line = line.TrimEnd(Environment.NewLine.ToCharArray()) + ";" + Environment.NewLine;
                                writer.WriteLine(line);
                            }

                            once = false;
                            if (parsed.objdesc.tmChanges.Count > 0)
                            {
                                line = "INSERT INTO `ace_object_texture_map_changes` (`baseAceObjectId`, `index`, `oldId`, `newId`)" + Environment.NewLine;

                                foreach (var texture in parsed.objdesc.tmChanges)
                                {
                                    if (once)
                                    {
                                        line += $"     , ({parsed.object_id}, {texture.part_index}, {texture.old_tex_id}, {texture.new_tex_id})" + Environment.NewLine;
                                    }
                                    else
                                    {
                                        line += $"VALUES ({parsed.object_id}, {texture.part_index}, {texture.old_tex_id}, {texture.new_tex_id})" + Environment.NewLine;
                                        once = true;
                                    }
                                }

                                line = line.TrimEnd(Environment.NewLine.ToCharArray()) + ";" + Environment.NewLine;
                                writer.WriteLine(line);
                            }

                            once = false;
                            if (parsed.objdesc.apChanges.Count > 0)
                            {
                                line = "INSERT INTO `ace_object_animation_changes` (`baseAceObjectId`, `index`, `animationId`)" + Environment.NewLine;

                                foreach (var animation in parsed.objdesc.apChanges)
                                {
                                    if (once)
                                    {
                                        line += $"     , ({parsed.object_id}, {animation.part_index}, {animation.part_id})" + Environment.NewLine;
                                    }
                                    else
                                    {
                                        line += $"VALUES ({parsed.object_id}, {animation.part_index}, {animation.part_id})" + Environment.NewLine;
                                        once = true;
                                    }
                                }

                                line = line.TrimEnd(Environment.NewLine.ToCharArray()) + ";" + Environment.NewLine;
                                writer.WriteLine(line);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine("Unable to export object " + parsed.object_id + ". Exception:" + Environment.NewLine + ex.ToString());
                }
            }
        }

        private void WriteWeenieData(Dictionary<uint, CM_Physics.CreateObject> weenies, string outputFolder)
        {
            string templateFolder = Path.Combine(outputFolder, "templates");
            if (Directory.Exists(templateFolder))
                Directory.Delete(templateFolder, true);

            Directory.CreateDirectory(templateFolder);

            Dictionary<ITEM_TYPE, int> fileCount = new Dictionary<ITEM_TYPE, int>();

            foreach (var parsed in weenies.Values)
            {
                if (!fileCount.ContainsKey(parsed.wdesc._type))
                    fileCount.Add(parsed.wdesc._type, 0);

                string filename = Path.Combine(templateFolder, $"{parsed.wdesc._type}_{fileCount[parsed.wdesc._type]}.sql");
                if (File.Exists(filename))
                {
                    FileInfo fi = new FileInfo(filename);

                    // go to the next file if it's bigger than a MB
                    if (fi.Length > (1048576))
                    {
                        fileCount[parsed.wdesc._type]++;
                        filename = Path.Combine(templateFolder, $"{parsed.wdesc._type}_{fileCount[parsed.wdesc._type]}.sql");
                    }
                }

                bool once = false;
                using (FileStream fs = new FileStream(filename, FileMode.Append))
                {
                    using (StreamWriter writer = new StreamWriter(fs))
                    {
                        string line = "INSERT INTO `base_ace_object` (`baseAceObjectId`, `name`, `typeId`, `paletteId`, " +

                        // wdesc data
                        "`ammoType`, `blipColor`, `bitField`, `burden`, `combatUse`, `cooldownDuration`, " +
                        "`cooldownId`, `effects`, `containersCapacity`, `header`, `hookTypeId`, `iconId`, `iconOverlayId`, " +
                        "`iconUnderlayId`, `hookItemTypes`, `itemsCapacity`, `location`, `materialType`, " +
                        "`maxStackSize`, `maxStructure`, `radar`, `pscript`, `spellId`, `stackSize`, " +
                        "`structure`, `targetTypeId`, `usability`, `useRadius`, `validLocations`, `value`, " +
                        "`workmanship`, " +

                        // physics data
                        "`animationFrameId`, `defaultScript`, `defaultScriptIntensity`, `elasticity`, " +
                        "`friction`, `locationId`, `modelTableId`, `objectScale`, `physicsBitField`, " +
                        "`physicsTableId`, `motionTableId`, `soundTableId`, `physicsState`, `translucency`)" + Environment.NewLine + "VALUES (" +

                        // shove the wcid in here so we can tell the difference between weenie classes and real objects for analysis
                        $"{parsed.wdesc._wcid}, '{parsed.wdesc._name.m_buffer.Replace("'", "''")}', {(int)parsed.wdesc._type}, {parsed.objdesc.paletteID}, " +

                        // wdesc data
                        $"{(int)parsed.wdesc._ammoType}, {parsed.wdesc._blipColor}, {parsed.wdesc._bitfield}, {parsed.wdesc._burden}, {parsed.wdesc._combatUse}, {parsed.wdesc._cooldown_duration}, " +
                        $"{parsed.wdesc._cooldown_id}, {parsed.wdesc._effects}, {parsed.wdesc._containersCapacity}, {parsed.wdesc.header}, {(int)parsed.wdesc._hook_type}, {parsed.wdesc._iconID}, {parsed.wdesc._iconOverlayID}, " +
                        $"{parsed.wdesc._iconUnderlayID}, {parsed.wdesc._hook_item_types}, {parsed.wdesc._itemsCapacity}, {parsed.wdesc._location}, {(int)parsed.wdesc._material_type}, " +
                        $"{parsed.wdesc._maxStackSize}, {parsed.wdesc._maxStructure}, {(int)parsed.wdesc._radar_enum}, {parsed.wdesc._pscript}, {parsed.wdesc._spellID}, {parsed.wdesc._stackSize}, " +
                        $"{parsed.wdesc._structure}, {(int)parsed.wdesc._targetType}, {(int)parsed.wdesc._useability}, {parsed.wdesc._useRadius}, {parsed.wdesc._valid_locations}, {parsed.wdesc._value}, " +
                        $"{parsed.wdesc._workmanship}, " +

                        // physics data.  note, model table is mis-parsed as setup_id.  the setup_id is actually "mtable", which is presumably motion table id.
                        $"{parsed.physicsdesc.animframe_id}, {(int)parsed.physicsdesc.default_script}, {parsed.physicsdesc.default_script_intensity}, {parsed.physicsdesc.elasticity}, " +
                        $"{parsed.physicsdesc.friction}, {parsed.physicsdesc.location_id}, {parsed.physicsdesc.setup_id}, {parsed.physicsdesc.object_scale}, {parsed.physicsdesc.bitfield}, " +
                        $"{parsed.physicsdesc.phstable_id}, {parsed.physicsdesc.mtable_id}, {parsed.physicsdesc.stable_id}, {parsed.physicsdesc.state}, {parsed.physicsdesc.translucency});" + Environment.NewLine;

                        // creates the base ace object record
                        writer.WriteLine(line);

                        line = "INSERT INTO weenie_class (`weenieClassId`, `baseAceObjectId`)" + Environment.NewLine +
                            $"VALUES ({parsed.wdesc._wcid}, {parsed.wdesc._wcid});" + Environment.NewLine;
                        writer.WriteLine(line);

                        once = false;
                        if (parsed.objdesc.subpalettes.Count > 0)
                        {
                            line = "INSERT INTO `weenie_palette_changes` (`weenieClassId`, `subPaletteId`, `offset`, `length`)" + Environment.NewLine;

                            foreach (var subPalette in parsed.objdesc.subpalettes)
                            {
                                if (once)
                                {
                                    line += $"     , ({parsed.wdesc._wcid}, {subPalette.subID}, {subPalette.offset}, {subPalette.numcolors})" + Environment.NewLine;
                                }
                                else
                                {
                                    line += $"VALUES ({parsed.wdesc._wcid}, {subPalette.subID}, {subPalette.offset}, {subPalette.numcolors})" + Environment.NewLine;
                                    once = true;
                                }
                            }

                            line = line.TrimEnd(Environment.NewLine.ToCharArray()) + ";" + Environment.NewLine;
                            writer.WriteLine(line);
                        }

                        once = false;
                        if (parsed.objdesc.tmChanges.Count > 0)
                        {
                            line = "INSERT INTO `weenie_texture_map_changes` (`weenieClassId`, `index`, `oldId`, `newId`)" + Environment.NewLine;

                            foreach (var texture in parsed.objdesc.tmChanges)
                            {
                                if (once)
                                {
                                    line += $"     , ({parsed.wdesc._wcid}, {texture.part_index}, {texture.old_tex_id}, {texture.new_tex_id})" + Environment.NewLine;
                                }
                                else
                                {
                                    line += $"VALUES ({parsed.wdesc._wcid}, {texture.part_index}, {texture.old_tex_id}, {texture.new_tex_id})" + Environment.NewLine;
                                    once = true;
                                }
                            }

                            line = line.TrimEnd(Environment.NewLine.ToCharArray()) + ";" + Environment.NewLine;
                            writer.WriteLine(line);
                        }

                        once = false;
                        if (parsed.objdesc.apChanges.Count > 0)
                        {
                            line = "INSERT INTO `weenie_animation_changes` (`weenieClassId`, `index`, `animationId`)" + Environment.NewLine;

                            foreach (var animation in parsed.objdesc.apChanges)
                            {
                                if (once)
                                {
                                    line += $"     , ({parsed.wdesc._wcid}, {animation.part_index}, {animation.part_id})" + Environment.NewLine;
                                }
                                else
                                {
                                    line += $"VALUES ({parsed.wdesc._wcid}, {animation.part_index}, {animation.part_id})" + Environment.NewLine;
                                    once = true;
                                }
                            }

                            line = line.TrimEnd(Environment.NewLine.ToCharArray()) + ";" + Environment.NewLine;
                            writer.WriteLine(line);
                        }
                    }
                }
            }
        }

        private bool PositionRecorded(List<Position> positions, Position newPosition)
        {
            if (newPosition?.frame?.m_fOrigin == null)
                return true; // can't dedupe this

            return positions.Any(p => p.objcell_id == newPosition.objcell_id
                                && Math.Abs(p.frame.m_fOrigin.x - newPosition.frame.m_fOrigin.x) < 0.02
                                && Math.Abs(p.frame.m_fOrigin.y - newPosition.frame.m_fOrigin.y) < 0.02
                                && Math.Abs(p.frame.m_fOrigin.z - newPosition.frame.m_fOrigin.z) < 0.02);
        }

        private void WriteUniqueTypes(CM_Physics.CreateObject parsed, StreamWriter writer, List<ITEM_TYPE> itemTypesToParse, Dictionary<ITEM_TYPE, List<string>> itemTypeKeys)
        {
            TreeView treeView = new TreeView();

            if (!itemTypesToParse.Contains(parsed.wdesc._type))
                return;

            totalHits++;

            // This bit of trickery uses the existing tree view parser code to create readable output, which we can then convert to csv
            treeView.Nodes.Clear();
            parsed.contributeToTreeView(treeView);
            if (treeView.Nodes.Count == 1)
            {
                var lineItems = new string[256];
                int lineItemCount = 0;

                ProcessNode(treeView.Nodes[0], itemTypeKeys[parsed.wdesc._type], null, lineItems, ref lineItemCount);

                var sb = new StringBuilder();

                for (int i = 0; i < lineItemCount; i++)
                {
                    if (i > 0)
                        sb.Append(',');

                    var output = lineItems[i];

                    // Format the value for CSV output, if needed.
                    // We only do this for certain columns. This is very time consuming
                    if (output != null && itemTypeKeys[parsed.wdesc._type][i].EndsWith("name"))
                    {
                        if (output.Contains(",") || output.Contains("\"") || output.Contains("\r") || output.Contains("\n"))
                        {
                            var sb2 = new StringBuilder();
                            sb2.Append("\"");
                            foreach (char nextChar in output)
                            {
                                sb2.Append(nextChar);
                                if (nextChar == '"')
                                    sb2.Append("\"");
                            }
                            sb2.Append("\"");
                            output = sb2.ToString();
                        }

                    }

                    if (output != null)
                        sb.Append(output);
                }

                writer.WriteLine(sb.ToString());
            }
        }

        private void ProcessNode(TreeNode node, List<string> keys, string prefix, string[] lineItems, ref int lineItemCount)
        {
            var kvp = ConvertNodeTextToKVP(node.Text);

            var nodeKey = (prefix == null ? kvp.Key : (prefix + "." + kvp.Key));

            // ********************************************************************
            // ***************** YOU CAN OMIT CERTAIN NODES HERE ****************** 
            // ********************************************************************
            //if (nodeKey.StartsWith("physicsdesc.timestamps")) return;

            if (node.Nodes.Count == 0)
            {
                if (!keys.Contains(nodeKey))
                    keys.Add(nodeKey);

                var keyIndex = keys.IndexOf(nodeKey);

                if (keyIndex >= lineItems.Length)
                    MessageBox.Show("Increase the lineItems array size");

                lineItems[keyIndex] = kvp.Value;

                if (keyIndex + 1 > lineItemCount)
                    lineItemCount = keyIndex + 1;
            }
            else
            {
                foreach (TreeNode child in node.Nodes)
                    ProcessNode(child, keys, nodeKey, lineItems, ref lineItemCount);
            }
        }

        private static KeyValuePair<string, string> ConvertNodeTextToKVP(string nodeText)
        {
            string key = null;
            string value = null;

            var indexOfEquals = nodeText.IndexOf('=');

            if (indexOfEquals == -1)
                value = nodeText;
            else
            {
                key = nodeText.Substring(0, indexOfEquals).Trim();

                if (nodeText.Length > indexOfEquals + 1)
                    value = nodeText.Substring(indexOfEquals + 1, nodeText.Length - indexOfEquals - 1).Trim();
            }

            return new KeyValuePair<string, string>(key, value);
        }


        private void timer1_Tick(object sender, EventArgs e)
        {
            toolStripStatusLabel1.Text = "Files Processed: " + filesProcessed.ToString("N0") + " of " + filesToProcess.Count.ToString("N0");

            toolStripStatusLabel2.Text = "Fragments Processed: " + fragmentsProcessed.ToString("N0");

            toolStripStatusLabel3.Text = "Total Hits: " + totalHits.ToString("N0");

            toolStripStatusLabel4.Text = "Frag Exceptions: " + totalExceptions.ToString("N0");
        }
    }
}
