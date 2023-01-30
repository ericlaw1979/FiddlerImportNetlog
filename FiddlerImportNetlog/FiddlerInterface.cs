using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using Fiddler;
using System.IO.Compression;

namespace FiddlerImportNetlog
{
    [ProfferFormat("NetLog JSON",
                   "Chromium's JSON-based event log format (v1.3.4.4). See https://textslashplain.com/2020/01/17/capture-network-logs-from-edge-and-chrome/ for more info.",
                   // We handle import of JSON files, whether uncompressed, or compressed with ZIP or GZ. I'm not completely sure I remember the implications
                   // of declaring .gz here, nor why .zip isn't mentioned. Is this about the drag/drop import feature?
                   ".json;.gz"
                  )]
    public class NetLogFormatImport : ISessionImporter
    {
        public Session[] ImportSessions(string sFormat, Dictionary<string, object> dictOptions, EventHandler<Fiddler.ProgressCallbackEventArgs> evtProgressNotifications)
        {
            if ((sFormat != "NetLog JSON")) { Debug.Assert(false); return null; }

            MemoryStream strmContent = null;
            string sFilename = null;
            if (null != dictOptions)
            {
                if (dictOptions.ContainsKey("Filename"))
                {
                    sFilename = dictOptions["Filename"] as string;
                }
                else if (dictOptions.ContainsKey("Content"))
                {
                    strmContent = new MemoryStream(Encoding.UTF8.GetBytes(dictOptions["Content"] as string));
                }
            }

            if ((null == strmContent) && string.IsNullOrEmpty(sFilename))
            {
                sFilename = Fiddler.Utilities.ObtainOpenFilename("Import " + sFormat, "NetLog JSON (*.json[.gz], *.zip)|*.json;*.json.gz;*.zip");
            }

            if ((null != strmContent) || !String.IsNullOrEmpty(sFilename))
            {
                try
                {
                    List<Session> listSessions = new List<Session>();
                    StreamReader oSR;

                    if (null != strmContent)
                    {
                        oSR = new StreamReader(strmContent);
                    }
                    else
                    {
                        Stream oFS = File.OpenRead(sFilename);
                        FiddlerApplication.Log.LogFormat("!NetLog Importer is loading {0}", sFilename);
                        // Check to see if this file data was GZIP'd or PKZIP'd.
                        bool bWasGZIP = false;
                        bool bWasPKZIP = false;
                        int bFirst = oFS.ReadByte();
                        if (bFirst == 0x1f && oFS.ReadByte() == 0x8b)
                        {
                            bWasGZIP = true;
                            evtProgressNotifications?.Invoke(null, new ProgressCallbackEventArgs(0, "Import file was compressed using gzip/DEFLATE."));
                        }
                        else if (bFirst == 0x50 && oFS.ReadByte() == 0x4b) {
                            bWasPKZIP = true;
                            evtProgressNotifications?.Invoke(null, new ProgressCallbackEventArgs(0, "Import file was a ZIP archive."));
                        }

                        oFS.Position = 0;
                        if (bWasGZIP)
                        {
                            oFS = GetUnzippedBytes(oFS);
                        }
                        else if (bWasPKZIP)
                        {
                            // Open the first JSON file.
                            ZipArchive oZA = new ZipArchive(oFS, ZipArchiveMode.Read, false, Encoding.UTF8);
                            foreach (ZipArchiveEntry oZE in oZA.Entries)
                            {
                                if (oZE.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                                {
                                    oFS = oZE.Open();
                                    break;
                                }
                            }
                        }

                        oSR = new StreamReader(oFS, Encoding.UTF8);
                    }

                    using (oSR)
                    {
                        new NetlogImporter(oSR, listSessions, evtProgressNotifications);
                    }
                    return listSessions.ToArray();
                }
                catch (Exception eX)
                {
                    FiddlerApplication.ReportException(eX, "Failed to import NetLog");
                    return null;
                }
            }
            return null;
        }

        /// <summary>
        /// Read the all bytes of the supplied DEFLATE-compressed file and return a memorystream containing the expanded bytes.
        /// </summary>
        private MemoryStream GetUnzippedBytes(Stream oFS)
        {
            long fileLength = oFS.Length;
            if (fileLength > Int32.MaxValue)
                throw new IOException("file over 2gb");

            int index = 0;
            int count = (int)fileLength;
            byte[] bytes = new byte[count];

            while (count > 0)
            {
                int n = oFS.Read(bytes, index, count);
                index += n;
                count -= n;
            }

            return new MemoryStream(Utilities.GzipExpand(bytes));
        }

        public void Dispose() { }
    }
}
