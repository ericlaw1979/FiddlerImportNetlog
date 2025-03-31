using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Fiddler;
using FiddlerImportNetlog.WebFormats;

namespace FiddlerImportNetlog
{
    class NetlogImporter
    {
        /// <summary>
        /// The NetLog file itself contains the mapping between string constants and the magic numbers used in the event entries.
        /// </summary>
        struct Magics
        {
            // Sources
            public int SRC_NONE;
            public int SRC_URL_REQUEST;
            public int SRC_SOCKET;
            public int SRC_HOST_RESOLVER_IMPL_JOB;

            // Events
            public int REQUEST_ALIVE;
            public int URL_REQUEST_START_JOB;
            public int SEND_HEADERS;
            public int SEND_QUIC_HEADERS;
            public int SEND_HTTP2_HEADERS;
            public int READ_HEADERS;
            public int FAKE_RESPONSE_HEADERS_CREATED;
            public int READ_EARLY_HINTS_RESPONSE_HEADERS;
            public int COOKIE_INCLUSION_STATUS;
            public int FILTERED_BYTES_READ;
            public int SEND_BODY;
            public int SEND_REQUEST;
            public int SSL_CERTIFICATES_RECEIVED;
            public int SSL_HANDSHAKE_MESSAGE_SENT;
            public int SSL_HANDSHAKE_MESSAGE_RECEIVED;
            public int TCP_CONNECT;
            public int SOCKET_BYTES_SENT;
            public int HOST_RESOLVER_IMPL_REQUEST;
            public int HOST_RESOLVER_IMPL_JOB;
            public int HOST_RESOLVER_IMPL_PROC_TASK;
        }

        internal static string DescribeExceptionWithStack(Exception eX)
        {
            StringBuilder oSB = new StringBuilder(512);
            oSB.AppendLine(eX.Message);
            oSB.AppendLine(eX.StackTrace);
            if (null != eX.InnerException)
            {
                oSB.AppendFormat(" < {0}", eX.InnerException.Message);
            }
            return oSB.ToString();
        }

        /// <summary>
        /// Remove disabled extensions, and any name/value pairs where the value is empty.
        /// </summary>
        private static ArrayList FilterExtensions(ArrayList al)
        {
            ArrayList alOut = new ArrayList();
            if (null != al)
            {
                foreach (Hashtable htItem in al)
                {
                    if ((bool)htItem["enabled"])
                    {
                        List<string> keysToDrop = new List<string> { "enabled", "kioskOnly", "kioskEnabled", "offlineEnabled" };
                        foreach (DictionaryEntry kvp in htItem)
                        {
                            if ((kvp.Value is string) && String.IsNullOrWhiteSpace(kvp.Value as string)) keysToDrop.Add(kvp.Key as string);
                        }
                        foreach (string key in keysToDrop) htItem.Remove(key);
                        alOut.Add(htItem);
                    }
                }
            }
            return alOut;
        }

        private static DateTime GetTimeStamp(object o, long baseTime)
        {
            // TODO: Something reasonable if o is null?
            long t = baseTime;
            if (null != o)
            {
                if (o is string)
                {
                    t += Int64.Parse(o as string);
                }
                else
                {
                    t += (long)(double)o;
                }
            }
            return DateTimeOffset.FromUnixTimeMilliseconds(t).DateTime.ToLocalTime();
        }

        #region Fields
        List<Session> _listSessions;
        readonly EventHandler<ProgressCallbackEventArgs> _evtProgressNotifications;
        Magics NetLogMagics;

        string _sClient;
        long _baseTime;
        DateTimeOffset _dtBaseTime;
        Dictionary<int, string> dictEventTypes;
        Dictionary<int, string> dictNetErrors;
        #endregion Fields

        internal NetlogImporter(StreamReader oSR, List<Session> listSessions, EventHandler<ProgressCallbackEventArgs> evtProgressNotifications)
        {
            _listSessions = listSessions;
            _evtProgressNotifications = evtProgressNotifications;
            Stopwatch oSW = Stopwatch.StartNew();
            string sJSONData = oSR.ReadToEnd();
            Hashtable htFile = JSON.JsonDecode(sJSONData, out _) as Hashtable;

            // If JSON-parsing failed, it's possible that the file was truncated either during capture or transfer.
            // Try repairing the end of file by replacing the last (incomplete) line.
            // This strategy is borrowed from the online "Catapult" netlog viewer app.
            if (null == htFile)
            {
                int iEnd = Math.Max(sJSONData.LastIndexOf(",\n"), sJSONData.LastIndexOf(",\r"));
                if (iEnd > 0) {
                    sJSONData = sJSONData.Substring(0, iEnd) + "]}";
                    htFile = JSON.JsonDecode(sJSONData, out _) as Hashtable;
                }
                if (null == htFile) {
                    NotifyProgress(1.00f, "Aborting; file is not properly-formatted NetLog JSON.");
                    FiddlerApplication.DoNotifyUser("This file is not properly-formatted NetLog JSON.", "Import aborted");
                    return;
                }
                else { FiddlerApplication.DoNotifyUser("This file was truncated and may be missing data.\nParsing any readable data.", "Warning"); }
            }

            NotifyProgress(0.25f, "Finished parsing JSON file; took " + oSW.ElapsedMilliseconds + "ms.");
            if (!ExtractSessionsFromJSON(htFile))
            {
                if (!(htFile["traceEvents"] is ArrayList alTraceEvents))
                {
                    FiddlerApplication.DoNotifyUser("This JSON file does not seem to contain NetLog data.", "Unexpected Data");
                    Session sessFile = Session.BuildFromData(false,
                            new HTTPRequestHeaders(
                                String.Format("/file.json"),
                                new[] { "Host: IMPORTED", "Date: " + DateTime.UtcNow.ToString() }),
                            Utilities.emptyByteArray,
                            new HTTPResponseHeaders(200, "File Data", new[] { "Content-Type: application/json; charset=utf-8" }),
                            Encoding.UTF8.GetBytes(JSON.JsonEncode(htFile)),
                            SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache);
                    listSessions.Insert(0, sessFile);
                }
                else
                {
                    ExtractSessionsFromTraceJSON(alTraceEvents);
                }
            }
        }

        private void ExtractSessionsFromTraceJSON(ArrayList alTraceEvents)
        {
            // Sources
            NetLogMagics.SRC_NONE = 0;
            NetLogMagics.SRC_URL_REQUEST = 1;
            NetLogMagics.SRC_SOCKET = 2;
            NetLogMagics.SRC_HOST_RESOLVER_IMPL_JOB = 3;

            // Events
            NetLogMagics.REQUEST_ALIVE = 10;
            NetLogMagics.URL_REQUEST_START_JOB = 11;
            NetLogMagics.SEND_HEADERS = 12;
            NetLogMagics.SEND_QUIC_HEADERS = 13;
            NetLogMagics.SEND_HTTP2_HEADERS = 14;
            NetLogMagics.READ_HEADERS = 15;
            NetLogMagics.FAKE_RESPONSE_HEADERS_CREATED = 16;
            NetLogMagics.READ_EARLY_HINTS_RESPONSE_HEADERS = 17;
            NetLogMagics.COOKIE_INCLUSION_STATUS = 18;
            NetLogMagics.FILTERED_BYTES_READ = 19;
            NetLogMagics.SEND_BODY = 20;
            NetLogMagics.SEND_REQUEST = 21;
            NetLogMagics.SSL_CERTIFICATES_RECEIVED = 22;
            NetLogMagics.SSL_HANDSHAKE_MESSAGE_SENT = 23;
            NetLogMagics.SSL_HANDSHAKE_MESSAGE_RECEIVED = 24;
            NetLogMagics.TCP_CONNECT = 25;
            NetLogMagics.SOCKET_BYTES_SENT = 26;

            NetLogMagics.HOST_RESOLVER_IMPL_REQUEST = 30;
            NetLogMagics.HOST_RESOLVER_IMPL_JOB = 31;
            NetLogMagics.HOST_RESOLVER_IMPL_PROC_TASK = 32;

            List<Hashtable> listEvents = new List<Hashtable>();
            foreach (Hashtable htItem in alTraceEvents)
            {
                if ((htItem["scope"] as string) =="netlog")
                {
                    listEvents.Add(htItem);
                }
            }
            int iEvent = 0;
            int iLastPct = 25;
            var dictURLRequests = new Dictionary<int, List<Hashtable>>();
            int cEvents = listEvents.Count;
            foreach (Hashtable htEvent in listEvents)
            {
                ++iEvent;
                var htArgs = htEvent["args"] as Hashtable;
                if (null == htArgs) continue;
                //var htParams = htArgs["params"] as Hashtable;
                //if (null == htParams) continue;


                #region ParseCertificateRequestMessagesAndDumpToLog
                /*
                if (iSourceType == NetLogMagics.SOCKET)
                {
                    try
                    {
                        // All events we care about should have parameters.
                        if (!(htEvent["params"] is Hashtable htParams)) continue;
                        int iType = getIntValue(htEvent["type"], -1);

                        List<Hashtable> events;
                        int iSocketID = getIntValue(htSource["id"], -1);

                        if (iType != NetLogMagics.SSL_CERTIFICATES_RECEIVED &&
                            iType != NetLogMagics.SSL_HANDSHAKE_MESSAGE_RECEIVED) continue;

                        // Get (or create) the List of entries for this SOCKET.
                        if (!dictSockets.ContainsKey(iSocketID))
                        {
                            events = new List<Hashtable>();
                            dictSockets.Add(iSocketID, events);
                        }
                        else
                        {
                            events = dictSockets[iSocketID];
                        }
                        // Add this event to the SOCKET's list.
                        events.Add(htEvent);
                    }
                    catch { }

                    continue;
                }
                */
                #endregion ParseCertificateRequestMessagesAndDumpToLog

                var sSourceType = htArgs["source_type"] as string;
                if (null == sSourceType) continue;
                
                // Collect only events related to URL_REQUESTS.
                if (sSourceType != "URL_REQUEST") continue;

                var sName = htEvent["name"] as string;
                if (null == sName) continue;

                int iURLRequestID = getHexValue(htEvent["id"], -1);
                {
                    List<Hashtable> events;

                    // Get (or create) the List of entries for this URLRequest.
                    if (!dictURLRequests.ContainsKey(iURLRequestID))
                    {
                        events = new List<Hashtable>();
                        dictURLRequests.Add(iURLRequestID, events);
                    }
                    else
                    {
                        events = dictURLRequests[iURLRequestID];
                    }

                    // Add this event to the URLRequest's list.
                    events.Add(htEvent);
                }
                int iPct = (int)(100 * (0.25f + 0.50f * (iEvent / (float)cEvents)));
                if (iPct != iLastPct)
                {
                    NotifyProgress(iPct / 100f, "Parsed an event for a URLRequest");
                    iLastPct = iPct;
                }
            }

            int cURLRequests = dictURLRequests.Count;

            NotifyProgress(0.75f, "Finished reading event entries, saw " + cURLRequests.ToString() + " URLRequests");

            GenerateSessionsFromURLRequests(dictURLRequests);

            //GenerateDebugTreeSession(dictURLRequests);
            //GenerateSocketListSession(dictSockets);

            NotifyProgress(1, "Import Completed.");
        }

        private void NotifyProgress(float fPct, string sMessage)
        {
            _evtProgressNotifications?.Invoke(null, new ProgressCallbackEventArgs(fPct, sMessage));
        }

        private int getIntValue(object oValue, int iDefault)
        {
            if (null == oValue) return iDefault;
            if (!(oValue is Double)) return iDefault;
            return (int)(double)oValue;
        }
        private int getHexValue(object oValue, int iDefault)
        {
            if (null == oValue) return iDefault;
            string sHexValue = oValue as String;
            if (String.IsNullOrEmpty(sHexValue)) return iDefault;
            try
            {
                int result = Convert.ToInt32(sHexValue, 16);
                return result;
            } 
            catch
            {
                return iDefault;
            }
        }

        public bool ExtractSessionsFromJSON(Hashtable htFile)
        {
            if (!(htFile["constants"] is Hashtable htConstants)) return false;
            if (!(htConstants["clientInfo"] is Hashtable htClientInfo)) return false;
            this._sClient = htClientInfo["name"] as string;

            #region LookupConstants
            Hashtable htEventTypes = htConstants["logEventTypes"] as Hashtable;
            Hashtable htNetErrors = htConstants["netError"] as Hashtable;
            Hashtable htSourceTypes = htConstants["logSourceType"] as Hashtable;
            string sDetailLevel = htConstants["logCaptureMode"] as string;

            // TODO: These should probably use a convenient wrapper for GetHashtableInt

            // Sources
            NetLogMagics.SRC_NONE = getIntValue(htSourceTypes["NONE"], 0);
            NetLogMagics.SRC_URL_REQUEST = getIntValue(htSourceTypes["URL_REQUEST"], -9999);
            NetLogMagics.SRC_SOCKET = getIntValue(htSourceTypes["SOCKET"], -9998);
            NetLogMagics.SRC_HOST_RESOLVER_IMPL_JOB = getIntValue(htSourceTypes["HOST_RESOLVER_IMPL_JOB"], -9997);

            #region GetEventTypes
            // HTTP-level Events
            NetLogMagics.REQUEST_ALIVE = getIntValue(htEventTypes["REQUEST_ALIVE"], -999);
            NetLogMagics.URL_REQUEST_START_JOB = getIntValue(htEventTypes["URL_REQUEST_START_JOB"], -998);
            NetLogMagics.SEND_HEADERS = getIntValue(htEventTypes["HTTP_TRANSACTION_SEND_REQUEST_HEADERS"], -997);
            NetLogMagics.SEND_QUIC_HEADERS = getIntValue(htEventTypes["HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS"], -996);
            NetLogMagics.SEND_HTTP2_HEADERS = getIntValue(htEventTypes["HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS"], -995);
            NetLogMagics.READ_HEADERS = getIntValue(htEventTypes["HTTP_TRANSACTION_READ_RESPONSE_HEADERS"], -994);
            NetLogMagics.READ_EARLY_HINTS_RESPONSE_HEADERS = getIntValue(htEventTypes["HTTP_TRANSACTION_READ_EARLY_HINTS_RESPONSE_HEADERS"], -993);
            NetLogMagics.FAKE_RESPONSE_HEADERS_CREATED = getIntValue(htEventTypes["URL_REQUEST_FAKE_RESPONSE_HEADERS_CREATED"], -992);
            NetLogMagics.FILTERED_BYTES_READ = getIntValue(htEventTypes["URL_REQUEST_JOB_FILTERED_BYTES_READ"], -991);
            NetLogMagics.COOKIE_INCLUSION_STATUS = getIntValue(htEventTypes["COOKIE_INCLUSION_STATUS"], -990);
            NetLogMagics.SEND_BODY = getIntValue(htEventTypes["HTTP_TRANSACTION_SEND_REQUEST_BODY"], -989);
            NetLogMagics.SEND_REQUEST = getIntValue(htEventTypes["HTTP_TRANSACTION_SEND_REQUEST"], -988);

            // Socket-level Events
            NetLogMagics.SSL_CERTIFICATES_RECEIVED = getIntValue(htEventTypes["SSL_CERTIFICATES_RECEIVED"], -899);
            NetLogMagics.SSL_HANDSHAKE_MESSAGE_SENT = getIntValue(htEventTypes["SSL_HANDSHAKE_MESSAGE_SENT"], -898);
            NetLogMagics.SSL_HANDSHAKE_MESSAGE_RECEIVED = getIntValue(htEventTypes["SSL_HANDSHAKE_MESSAGE_RECEIVED"], -897);
            NetLogMagics.TCP_CONNECT = getIntValue(htEventTypes["TCP_CONNECT"], -896);
            NetLogMagics.SOCKET_BYTES_SENT = getIntValue(htEventTypes["SOCKET_BYTES_SENT"], -895);

            // DNS
            NetLogMagics.HOST_RESOLVER_IMPL_REQUEST = getIntValue(htEventTypes["HOST_RESOLVER_IMPL_REQUEST"], -799);
            NetLogMagics.HOST_RESOLVER_IMPL_JOB = getIntValue(htEventTypes["HOST_RESOLVER_IMPL_JOB"], -798);
            NetLogMagics.HOST_RESOLVER_IMPL_PROC_TASK = getIntValue(htEventTypes["HOST_RESOLVER_IMPL_PROC_TASK"], -797);

            // Get ALL event type names as strings for pretty print view
            dictEventTypes = new Dictionary<int, string>();
            foreach (DictionaryEntry de in htEventTypes)
            {
                dictEventTypes.Add((int)(double)de.Value, de.Key as String);
            }
            #endregion

            #region GetNetErrors
            dictNetErrors = new Dictionary<int, string>();
            foreach (DictionaryEntry de in htNetErrors)
            {
                dictNetErrors.Add((int)(double)de.Value, de.Key as String);
            }
            #endregion

            int iLogVersion = getIntValue(htConstants["logFormatVersion"], 0);
            NotifyProgress(0, "Found NetLog v" + iLogVersion + ".");
            #endregion LookupConstants

            #region GetBaseTime
            // Base time for all events' relative timestamps.
            object o = htConstants["timeTickOffset"];
            if (o is string)
            {
                _baseTime = Int64.Parse(o as string);
            }
            else
            {
                _baseTime = (long)(double)o;
            }
            _dtBaseTime = TimeZoneInfo.ConvertTime(DateTimeOffset.FromUnixTimeMilliseconds(_baseTime), TimeZoneInfo.Local);
            FiddlerApplication.Log.LogFormat("Base capture time is {0} aka {1}", _baseTime, _dtBaseTime);
            #endregion

            // Create a Summary Session, the response body of which we'll fill in later.
            Session sessSummary = Session.BuildFromData(false,
                    new HTTPRequestHeaders(
                        String.Format("/CAPTURE_INFO"),
                        new[] { "Host: NETLOG" /* TODO: Put something useful here */, "Date: " + _dtBaseTime.ToString("r") }),
                    Utilities.emptyByteArray,
                    new HTTPResponseHeaders(200, "Analyzed Data", new[] { "Content-Type: text/plain; charset=utf-8" }),
                    Utilities.emptyByteArray,
                    SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache);
            setAllTimers(sessSummary, _baseTime);
            _listSessions.Add(sessSummary);

            { // Create a RAW data session with all of the JSON text for debugging purposes.
                Session sessRaw = Session.BuildFromData(false,
                        new HTTPRequestHeaders(
                            String.Format("/RAW_JSON"),
                            new[] { "Host: NETLOG" }),
                        Utilities.emptyByteArray,
                        new HTTPResponseHeaders(200, "Analyzed Data", new[] { "Content-Type: application/json; charset=utf-8" }),
                        Encoding.UTF8.GetBytes(JSON.JsonEncode(htFile)),
                        SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache);
                setAllTimers(sessRaw, _baseTime);
                _listSessions.Add(sessRaw);
            }

            Hashtable htPolledData = htFile["polledData"] as Hashtable;
            if (null != htPolledData)
            {
                ArrayList alExtensions = FilterExtensions(htPolledData["extensionInfo"] as ArrayList);

                Session sessExtensions = Session.BuildFromData(false,
                        new HTTPRequestHeaders(
                            String.Format("/ENABLED_EXTENSIONS"),
                            new[] { "Host: NETLOG" }),
                        Utilities.emptyByteArray,
                        new HTTPResponseHeaders(200, "Analyzed Data", new[] { "Content-Type: application/json; charset=utf-8" }),
                        Encoding.UTF8.GetBytes(JSON.JsonEncode(alExtensions)),
                        SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache);
                setAllTimers(sessExtensions, _baseTime);
                _listSessions.Add(sessExtensions);
            }

            int iEvent = -1;
            int iLastPct = 25;
            var dictURLRequests = new Dictionary<int, List<Hashtable>>();
            var dictSockets = new Dictionary<int, List<Hashtable>>();
            var dictDNSResolutions = new Dictionary<int, List<Hashtable>>();

            // Loop over events; bucket those associated to URLRequests by the source request's ID.
            ArrayList alEvents = htFile["events"] as ArrayList;
            int cEvents = alEvents.Count;
            foreach (Hashtable htEvent in alEvents)
            {
                ++iEvent;
                var htSource = htEvent["source"] as Hashtable;
                if (null == htSource) continue;
                int iSourceType = getIntValue(htSource["type"], -1);

                #region ParseCertificateRequestMessagesAndDumpToLog
                if (NetLogMagics.SRC_SOCKET == iSourceType)
                {
                    try
                    {
                        // All events we care about should have parameters.
                        if (!(htEvent["params"] is Hashtable htParams)) continue;
                        int iType = getIntValue(htEvent["type"], -1);

                        List<Hashtable> events;
                        int iSocketID = getIntValue(htSource["id"], -1);

                        /*if (iType == NetLogMagics.SOCKET_BYTES_SENT)
                        {
                            FiddlerApplication.Log.LogFormat("!!!! IT WORKED!!!!");
                             //htParams["bytes"]
                        }*/

                        if (iType != NetLogMagics.SSL_CERTIFICATES_RECEIVED &&
                            iType != NetLogMagics.SSL_HANDSHAKE_MESSAGE_SENT &&
                            iType != NetLogMagics.SSL_HANDSHAKE_MESSAGE_RECEIVED &&
                            iType != NetLogMagics.TCP_CONNECT) continue;

                        // Get (or create) the List of entries for this SOCKET.
                        if (!dictSockets.ContainsKey(iSocketID))
                        {
                            events = new List<Hashtable>();
                            dictSockets.Add(iSocketID, events);
                        }
                        else
                        {
                            events = dictSockets[iSocketID];
                        }
                        // Add this event to the SOCKET's list.
                        events.Add(htEvent);
                    }
                    catch { }

                    continue;
                }
                #endregion ParseCertificateRequestMessagesAndDumpToLog

                // DNS lookup
                if (NetLogMagics.SRC_NONE == iSourceType)
                {
                    int iType = getIntValue(htEvent["type"], -1);
                    if (iType == NetLogMagics.HOST_RESOLVER_IMPL_REQUEST)
                    {
                        // TODO: Do we actually care about any of the flags here?
                       // FiddlerApplication.Log.LogString("!!0" + JSON.JsonEncode(htEvent));
                        /*
                         "source":{"type":0, "start_time":"817048", "id":3246}, 
                         "params":{"network_isolation_key":"null null", "dns_query_type":0, "allow_cached_response":true, "is_speculative":false, 
                                   "host":"ragnsells.crm4.dynamics.com:443"}, "time":"817048",
                                   "type":3, "phase":1}
                        */
                     }
                }

                if (NetLogMagics.SRC_HOST_RESOLVER_IMPL_JOB == iSourceType)
                {
                    // All events we care about should have parameters.
                    if (!(htEvent["params"] is Hashtable htParams)) continue;
                    int iType = getIntValue(htEvent["type"], -1);

                    // Two DNS-related events have all the data we care about.
                    if ((iType == NetLogMagics.HOST_RESOLVER_IMPL_JOB) || (iType == NetLogMagics.HOST_RESOLVER_IMPL_PROC_TASK))
                    {
                        int iResolutionID = getIntValue(htSource["id"], -1);
                        List<Hashtable> events;
                        // Get (or create) the List of entries for this sDNSHost.
                        if (!dictDNSResolutions.ContainsKey(iResolutionID))
                        {
                            events = new List<Hashtable>();
                            dictDNSResolutions.Add(iResolutionID, events);
                        }
                        else
                        {
                            events = dictDNSResolutions[iResolutionID];
                        }
                        // Add this event to the sDNSHost's list.
                        events.Add(htEvent);
                        continue;
                    }
                }

                // Collect only events related to URL_REQUESTS.
                if (NetLogMagics.SRC_URL_REQUEST != iSourceType) continue;

                int iURLRequestID = getIntValue(htSource["id"], -1);

                {
                    List<Hashtable> events;

                    // Get (or create) the List of entries for this URLRequest.
                    if (!dictURLRequests.ContainsKey(iURLRequestID))
                    {
                        events = new List<Hashtable>();
                        dictURLRequests.Add(iURLRequestID, events);
                    }
                    else
                    {
                        events = dictURLRequests[iURLRequestID];
                    }

                    // Add this event to the URLRequest's list.
                    events.Add(htEvent);
                }
                int iPct = (int)(100 * (0.25f + 0.50f * (iEvent / (float)cEvents)));
                if (iPct != iLastPct)
                {
                    NotifyProgress(iPct / 100f, "Parsed an event for a URLRequest");
                    iLastPct = iPct;
                }
            }

            int cURLRequests = dictURLRequests.Count;

            NotifyProgress(0.75f, "Finished reading event entries, saw " + cURLRequests.ToString() + " URLRequests");

            GenerateSessionsFromURLRequests(dictURLRequests);

            StringBuilder sbClientInfo = new StringBuilder();
            sbClientInfo.AppendFormat("Sensitivity:\t{0}\n", sDetailLevel);
            sbClientInfo.AppendFormat("Client:\t\t{0} v{1}\n", _sClient, htClientInfo["version"]);
            sbClientInfo.AppendFormat("Channel:\t\t{0}\n", htClientInfo["version_mod"]);
            sbClientInfo.AppendFormat("Commit Hash:\t{0}\n", htClientInfo["cl"]);
            sbClientInfo.AppendFormat("OS:\t\t{0}\n", htClientInfo["os_type"]);

            sbClientInfo.AppendFormat("\nCommandLine:\t{0}\n\n", htClientInfo["command_line"]);
            sbClientInfo.AppendFormat("Capture started:\t{0}\n", _dtBaseTime);
            sbClientInfo.AppendFormat("URLRequests:\t\t{0} found.\n", cURLRequests);

            sessSummary.utilSetResponseBody(sbClientInfo.ToString());

            GenerateDebugTreeSession(dictURLRequests);
            GenerateSocketListSession(dictSockets);
            GenerateDNSResolutionListSession(dictDNSResolutions);

            NotifyProgress(1, "Import Completed.");
            return true;
        }

        /// <summary>
        /// Add a JSON session of the URL_REQUEST buckets for diagnostic purposes.
        /// WARNING: LOSSY. MANGLES TREE. DO THIS LAST.
        /// </summary>
        /// <param name="dictEventTypes"></param>
        /// <param name="dictNetErrors"></param>
        /// <param name="dictURLRequests"></param>
        private void GenerateDebugTreeSession(Dictionary<int, List<Hashtable>> dictURLRequests)
        {
            try
            {
                Hashtable htDebug = new Hashtable();

                foreach (KeyValuePair<int, List<Hashtable>> kvpURLRequest in dictURLRequests)
                {
                    // Store off the likely initial URL for this URL Request
                    string sUrl = String.Empty;

                    // Remove data we're unlikely to need, and replace magics with constant strings.
                    foreach (Hashtable ht in kvpURLRequest.Value)
                    {
                        ht.Remove("source");
                        ht.Remove("time");

                        try
                        {
                            // Replace Event type integers with names.
                            int iType = getIntValue(ht["type"], -1);
                            ht["type"] = dictEventTypes[iType];

                            if (iType == NetLogMagics.URL_REQUEST_START_JOB) {
                                sUrl = ((string)(ht["params"] as Hashtable)?["url"] ?? sUrl);
                            }

                            // Replace Event phase integers with names.
                            int iPhase = getIntValue(ht["phase"], -1);
                            ht["phase"] = (iPhase == 1) ? "BEGIN" : (iPhase == 2) ? "END" : "NONE";

                            // Replace NetError integers with names.
                            Hashtable htParams = ht["params"] as Hashtable;
                            if (null != htParams && htParams["net_error"] is Double d)
                            {
                                int iErr = (int)d;
                                if (iErr != 0) // 0 isn't valid; NetErrors are usually negative.
                                {
                                    htParams["net_error"] = dictNetErrors[iErr];
                                }
                            }
                        }
                        catch (Exception e) { FiddlerApplication.Log.LogFormat(DescribeExceptionWithStack(e)); }
                    }

                    // Copy List<Hashtable> to ArrayList, which is the only type the serializer understands.
                    ArrayList alE = new ArrayList(kvpURLRequest.Value);

                    htDebug.Add(String.Format("{0} - {1}", kvpURLRequest.Key, sUrl), alE);
                }

                if (htDebug.Count > 0)
                {
                    Session sessURLRequests = Session.BuildFromData(false,
                            new HTTPRequestHeaders(
                                String.Format("/URL_REQUESTS"),
                                new[] { "Host: NETLOG" }),
                            Utilities.emptyByteArray,
                            new HTTPResponseHeaders(200, "Analyzed Data", new[] { "Content-Type: application/json; charset=utf-8" }),
                            Encoding.UTF8.GetBytes(JSON.JsonEncode(htDebug)),
                            SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache);
                    setAllTimers(sessURLRequests, _baseTime);
                    _listSessions.Add(sessURLRequests);
                }
            }
            catch (Exception e) { FiddlerApplication.Log.LogFormat("GenerateDebugTreeSession failed: "+ DescribeExceptionWithStack(e)); }
        }

        private void GenerateSocketListSession(Dictionary<int, List<Hashtable>> dictSockets)
        {
            try
            {
                Hashtable htAllSockets = new Hashtable();
                foreach (KeyValuePair<int, List<Hashtable>> kvpSocket in dictSockets)
                {
                    string sSubjectCNinFirstCert = String.Empty;
                    Hashtable htThisSocket = new Hashtable();

                    foreach (Hashtable htEvent in kvpSocket.Value)
                    {
                        int iType = getIntValue(htEvent["type"], -1);
                        var htParams = (Hashtable) htEvent["params"];

                        if (iType == NetLogMagics.TCP_CONNECT)
                        {
                            if (htParams.ContainsKey("local_address"))
                            {
                                htThisSocket.Add("local_address", htParams["local_address"]);
                            }
                            //"remote_address", "local_address", "address_list"
                            if (htParams.ContainsKey("remote_address"))
                            {
                                htThisSocket.Add("remote_address", htParams["remote_address"]);
                            }
                            if (htParams.ContainsKey("address_list"))
                            {
                                htThisSocket.Add("address_list", htParams["address_list"]);
                            }
                            continue;
                        }

                        if (iType == NetLogMagics.SSL_CERTIFICATES_RECEIVED)
                        {
                            StringBuilder sbCertsReceived = new StringBuilder();
                            ArrayList alCerts = htParams["certificates"] as ArrayList;
                            if (alCerts.Count < 1) continue;

                            Hashtable htParsedCerts = new Hashtable(alCerts.Count);
                            try
                            {
                                for (int i = 0; i < alCerts.Count; i++)
                                {
                                    var htThisCert = new Hashtable();
                                    htParsedCerts.Add(i.ToString(), htThisCert);
                                    var certItem = new X509Certificate2();

                                    certItem.Import(Encoding.ASCII.GetBytes(alCerts[i] as string));

                                    // Try to promote the SubjectCN to the title of this Socket.
                                    if (String.IsNullOrEmpty(sSubjectCNinFirstCert))
                                    {
                                        sSubjectCNinFirstCert = (" - " + certItem.GetNameInfo(X509NameType.SimpleName, false)).ToLower();
                                    }

                                    htThisCert.Add("Parsed", new ArrayList
                                    {
                                        "Subject: " + certItem.GetNameInfo(X509NameType.SimpleName, false),
                                        "Issuer: " + certItem.Issuer,
                                        "Expires: " + certItem.NotAfter.ToString("yyyy-MM-dd")
                                    });

                                    htThisCert.Add("RAW", new ArrayList
                                    {
                                        alCerts[i]
                                    });
                                }
                                htThisSocket.Add("Server Certificates", htParsedCerts);
                            }
                            catch (Exception ex)
                            {
                                FiddlerApplication.Log.LogString(ex.Message);
                                htThisSocket.Add("Server Certificates", alCerts);
                            }

                            continue;
                        }

                        if (iType == NetLogMagics.SSL_HANDSHAKE_MESSAGE_SENT)
                        {
                            // https://source.chromium.org/chromium/chromium/src/+/main:third_party/boringssl/src/include/openssl/ssl3.h;l=306;drc=5539ecff898c79b0771340051d62bf81649e448d
                            int iHandshakeMessageType = getIntValue(htParams["type"], -1);

                            if ((iHandshakeMessageType != 1/*ClientHello*/)) continue;

                            // Okay, it's a ClientHello. Log it.
                            string sBase64Bytes = htParams["bytes"] as string;
                            if (String.IsNullOrEmpty(sBase64Bytes)) continue;
                            // FiddlerApplication.Log.LogFormat("Saw Handshake Message Sent of type={0}", iHandshakeMessageType);

                            if (iHandshakeMessageType == 1 /*ClientHello*/)
                            {
                                try
                                {
                                    var htClientHello = new Hashtable();
                                    htThisSocket.Add("ClientHello", htClientHello);       // TODO: Figure out why we're often hitting this twice.

                                    byte[] arr = Convert.FromBase64String(sBase64Bytes);

                                    MemoryStream oMS = new MemoryStream();
                                    // BUG BUG BUG: HACKERY; we have to construct a fake header here.
                                    oMS.WriteByte(0x16);    // TLS handshake protocol
                                    oMS.WriteByte(0x3);
                                    oMS.WriteByte(0x3);     // TODO: We should at least fill the version info correctly.
                                    oMS.WriteByte(0);
                                    oMS.WriteByte(0x9b);
                                    oMS.Write(arr, 0, arr.Length);

                                    oMS.Position = 0;
                                    string sDesc = Utilities.UNSTABLE_DescribeClientHello(oMS);
                                    //FiddlerApplication.Log.LogFormat("Got ClientHello:\n{0}\n{1}", Utilities.ByteArrayToHexView(arr, 16), sDesc);

                                    htClientHello.Add("RAW", sBase64Bytes);
                                    ArrayList arrDesc = new ArrayList(sDesc.Split('\n').Select(s => s.Trim().Replace('\t', ' ')).Where(s => !string.IsNullOrEmpty(s)).Skip(2).ToArray());
                                    htClientHello.Add("Parsed", arrDesc);
                                }
                                catch { }

                                continue;
                            }
                        }

                        // {"params":{"certificates":["-----BEGIN CERTIFICATE-----\nMIINqg==\n-----END CERTIFICATE-----\n","-----BEGIN CERTIFICATE-----\u4\n-----END CERTIFICATE-----\n"]},"phase":0,"source":{"id":789,"type":8},"time":"464074729","type":69},
                        // Parse out client certificate requests (Type 13==CertificateRequest)
                        // {"params":{"bytes":"DQA...","type":13},"phase":0,"source":{"id":10850,"type":8},"time":"160915359","type":60 (SSL_HANDSHAKE_MESSAGE_RECEIVED)})
                        if (iType == NetLogMagics.SSL_HANDSHAKE_MESSAGE_RECEIVED)
                        {
                            // https://source.chromium.org/chromium/chromium/src/+/main:third_party/boringssl/src/include/openssl/ssl3.h;l=306;drc=5539ecff898c79b0771340051d62bf81649e448d
                            int iHandshakeMessageType = getIntValue(htParams["type"], -1);

                            if ((iHandshakeMessageType != 2/*ServerHello*/) &&
                                (iHandshakeMessageType != 13/*CertificateRequest*/)) continue;

                            // Okay, it's a ServerHello or CertificateRequest. Log it.
                            string sBase64Bytes = htParams["bytes"] as string;
                            if (String.IsNullOrEmpty(sBase64Bytes)) continue;
                            // FiddlerApplication.Log.LogFormat("Saw Handshake Message Received of type={0}", iHandshakeMessageType);

                            if (iHandshakeMessageType == 2 /*ServerHello*/)
                            {
                                try {
                                    var htServerHello = new Hashtable();
                                    htThisSocket.Add("ServerHello", htServerHello);  // TODO: Figure out why we're often reaching this twice.

                                    byte[] arr = Convert.FromBase64String(sBase64Bytes);

                                    MemoryStream oMS = new MemoryStream();
                                    // BUG BUG BUG: HACKERY; we have to construct a fake header here to feed it into the Utilities function which was meant for reading socket data not NetLog messages.
                                    oMS.WriteByte(0x16);
                                    oMS.WriteByte(0x3);
                                    oMS.WriteByte(0x3);             // TODO: We probably should at least fill the version info properly!
                                    oMS.WriteByte(0);
                                    oMS.WriteByte(0x9b);
                                    oMS.Write(arr, 0, arr.Length);

                                    oMS.Position = 0;
                                    string sDesc = Utilities.UNSTABLE_DescribeServerHello(oMS);
                                    // FiddlerApplication.Log.LogFormat("Got ServerHello:\n{0}\n{1}", Utilities.ByteArrayToHexView(arr, 16), sDesc);

                                    htServerHello.Add("RAW", sBase64Bytes);
                                    ArrayList arrDesc = new ArrayList(sDesc.Split('\n').Select(s => s.Trim().Replace('\t', ' ')).Where(s => !string.IsNullOrEmpty(s)).Skip(2).ToArray());
                                    htServerHello.Add("Parsed", arrDesc);

                                    // We learn if the server is using TLS/1.3 by checking if ServerHello's supported_versions specifies TLS/1.3
                                    // https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.1
                                    // Note: This is Super Hacky and depends on Fiddler not changing the format of this string.
                                    if (sDesc.Contains("supported_versions\tTls1.3"))
                                      htThisSocket.Add("Negotiated TLS Version", "1.3");
                                }
                                catch {}

                                continue;
                            }

                            Debug.Assert(iHandshakeMessageType == 13 /*CertificateRequest*/);

                            // BORING SSL verion of the parsing logic:
                            // https://cs.chromium.org/chromium/src/third_party/boringssl/src/ssl/handshake_client.cc?l=1102&rcl=5ce7022394055e183c12368778d361461fe90a6e

                            var htCertFilter = new Hashtable();
                            htThisSocket.Add("Request for Client Certificate", htCertFilter);
                            htThisSocket.Add("RAW", sBase64Bytes);

                            byte[] arrCertRequest = Convert.FromBase64String(sBase64Bytes);
                            Debug.Assert(13 == arrCertRequest[0]);

                            /* Each version of TLS redefined the format of the CertificateRequest message.
                             * TLS 1.0/TLS/1.1: https://www.rfc-editor.org/rfc/rfc4346#section-7.4.4
                                struct {
                                    ClientCertificateType certificate_types<1..2^8-1>;
                                    DistinguishedName certificate_authorities<3..2^16-1>;
                                } CertificateRequest;

                             * TLS 1.2: https://www.rfc-editor.org/rfc/rfc5246#section-7.4.4
                                struct {
                                    ClientCertificateType certificate_types<1..2^8-1>;
                                    SignatureAndHashAlgorithm supported_signature_algorithms<2^16-1>;
                                    DistinguishedName certificate_authorities<0..2^16-1>;
                                } CertificateRequest;

                             * TLS 1.3: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
                                struct {
                                    opaque certificate_request_context<0..2^8-1>;
                                    Extension extensions<2..2^16-1>;
                                } CertificateRequest
                             */

                            if ((htThisSocket["Negotiated TLS Version"] as string) == "1.3")
                            {
                                ParseTLS1dot3CertificateRequest(htCertFilter, arrCertRequest);
                                continue;
                            }

                            // TLS/1.2 path

                            byte cCertTypes = arrCertRequest[4];
                            var alCertTypes = new ArrayList();
                            for (int ixCertType = 0; ixCertType<cCertTypes; ++ixCertType)
                            {
                                int iCertType = arrCertRequest[5 + ixCertType];
                                string sCertType;
                                // https://tools.ietf.org/html/rfc5246#section-12 ClientCertificateType
                                switch (iCertType)
                                {
                                    // https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-2
                                    case 1: sCertType = "rsa_sign"; break;
                                    case 2: sCertType = "dss_sign"; break;
                                    case 3: sCertType = "rsa_fixed_dh"; break;
                                    case 4: sCertType = "dss_fixed_dh"; break;
                                    case 5: sCertType = "rsa_ephemeral_dh_RESERVED"; break;
                                    case 6: sCertType = "dss_ephemeral_dh_RESERVED"; break;
                                    case 20: sCertType = "fortezza_dms_RESERVED"; break;
                                    case 0x40: sCertType = "ecdsa_sign"; break;
                                    case 0x41: sCertType = "rsa_fixed_ecdh"; break;
                                    case 0x42: sCertType = "ecdsa_fixed_ecdh"; break;
                                    case 0x43: sCertType = "gost_sign256"; break;
                                    case 0x44: sCertType = "gost_sign512"; break;
                                    default: sCertType = String.Format("unknown(0x{0:x})", iCertType); break;
                                }
                                alCertTypes.Add(sCertType);
                            }
                            htCertFilter.Add("Accepted ClientCertificateTypes", alCertTypes);

                            int iPtr = 5 + cCertTypes;
                            // BUGBUG: Only TLS/1.2+ have sig/hash pairs; these are omitted in TLS/1.1 and earlier. This probably
                            // doesn't really matter now that Chromium only supports TLS/1.2 and later.
                            try
                            {
                                int cbSigHashAlgs = (arrCertRequest[iPtr++] << 8) +
                                                     arrCertRequest[iPtr++];
                                Debug.Assert((cbSigHashAlgs % 2) == 0);

                                var alSigHashAlgs = new ArrayList();

                                for (int ixSigHashPair = 0; ixSigHashPair < cbSigHashAlgs / 2; ++ixSigHashPair)
                                {
                                    alSigHashAlgs.Add(GetHashSigString(arrCertRequest[iPtr + (2 * ixSigHashPair)], arrCertRequest[iPtr + (2 * ixSigHashPair) + 1]));
                                }
                                htCertFilter.Add("Accepted SignatureAndHashAlgorithms", alSigHashAlgs);
                                iPtr += (cbSigHashAlgs);
                            }
                            catch (Exception eX) {
                                FiddlerApplication.ReportException(eX, "Failed to parse Signature/Hash algorithms in NetLog");
                            }

                            Debug.Assert(iPtr < arrCertRequest.Length);  // Truncated data?

                            try
                            {
                                int cbCADistinguishedNames = (arrCertRequest[iPtr++] << 8) +
                                                              arrCertRequest[iPtr++];

                                var alCADNs = new ArrayList();
                                while (cbCADistinguishedNames > 0)
                                {
                                    int cbThisDN = (arrCertRequest[iPtr++] << 8) + arrCertRequest[iPtr++];
                                    Debug.Assert(cbThisDN < cbCADistinguishedNames);
                                    try
                                    {
                                        byte[] bytesDER = new byte[cbThisDN];
                                        Buffer.BlockCopy(arrCertRequest, iPtr, bytesDER, 0, cbThisDN);
                                        AsnEncodedData asndata = new AsnEncodedData(bytesDER);
                                        alCADNs.Add(new X500DistinguishedName(asndata).Name);
                                    }
                                    catch { Debug.Assert(false); }
                                    iPtr += cbThisDN;
                                    cbCADistinguishedNames -= (2 + cbThisDN);
                                }
                                htCertFilter.Add("Accepted Authorities", alCADNs);
                            }
                            catch { }

                            continue;
                        }
                    }

                    if (htThisSocket.Count > 0)
                    {
                        htAllSockets.Add(kvpSocket.Key + sSubjectCNinFirstCert, htThisSocket);
                    }
                }

                // Don't add a node if there were no sockets.
                if (htAllSockets.Count > 0)
                {
                    Session sessAllSockets = Session.BuildFromData(false,
                            new HTTPRequestHeaders(
                                String.Format("/SOCKETS"),
                                new[] { "Host: NETLOG" }),
                            Utilities.emptyByteArray,
                            new HTTPResponseHeaders(200, "Analyzed Data", new[] { "Content-Type: application/json; charset=utf-8" }),
                            Encoding.UTF8.GetBytes(JSON.JsonEncode(htAllSockets)),
                            SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache);
                    setAllTimers(sessAllSockets, _baseTime);
                    _listSessions.Add(sessAllSockets);
                }
            }
            catch (Exception e) { FiddlerApplication.Log.LogFormat("GenerateSocketListSession failed: " + DescribeExceptionWithStack(e)); }
        }

        private static void setAllTimers(Session oS, long dt)
        {
            var oTimers = oS.Timers;
            oTimers.ClientConnected = oTimers.ClientBeginRequest = oTimers.FiddlerGotRequestHeaders = oTimers.FiddlerBeginRequest =
            oTimers.ClientBeginResponse = oTimers.FiddlerGotResponseHeaders = oTimers.ServerBeginResponse =
            oTimers.ServerDoneResponse = oTimers.ClientDoneResponse = GetTimeStamp(0.0, dt);
        }

        /* TLS 1.3: https://datatracker.ietf.org/doc/html/rfc8446#section-4.3.2
            struct {
                opaque certificate_request_context<0..2^8-1>;
                Extension extensions<2..2^16-1>;
            } CertificateRequest

            In TLS/1.3, fields for the certificate request are carried by "extensions":
             https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
               Extension 0x2F (decimal 47) => certificate_authorities
               Extension 0x0D (decimal 13) => signature_algorithms
               Extension 0x32 (decimal 50) => signature_algorithms_cert
        */
        private void ParseTLS1dot3CertificateRequest(Hashtable htCertFilter, byte[] arrCertRequest)
        {
            int iPayloadSize = (arrCertRequest[1] << 16) +
                   (arrCertRequest[2] << 8) +
                    arrCertRequest[3];

            Debug.Assert(iPayloadSize == arrCertRequest.Length - 4);

            int iPtr = 4;

            // The first field of the request is a length-prefixed 0-255 byte opaque array named certificate_request_context
            iPtr += 1+arrCertRequest[iPtr];

            int cbExtensionList = (arrCertRequest[iPtr++] << 8) +
                                  (arrCertRequest[iPtr++]);
            Debug.Assert(iPtr + cbExtensionList == arrCertRequest.Length);
            while (iPtr < arrCertRequest.Length)
            {
              int iExtensionType = (arrCertRequest[iPtr++] << 8) + arrCertRequest[iPtr++];
              int iExtDataLen = (arrCertRequest[iPtr++] << 8) + arrCertRequest[iPtr++];

              byte[] arrExtData = new byte[iExtDataLen];
              Buffer.BlockCopy(arrCertRequest, iPtr, arrExtData, 0, arrExtData.Length);

              switch (iExtensionType)
              {
                case 0x2f: // certificate_authorities
                    try {
                        var alCADNs = new ArrayList();
                        int iX = 0;
                        int cbCADistinguishedNames = (arrExtData[iX++] << 8) + arrExtData[iX++];
                        while (cbCADistinguishedNames > 0)
                        {
                            int cbThisDN = (arrExtData[iX++] << 8) + arrExtData[iX++];
                            try
                            {
                                byte[] bytesDER = new byte[cbThisDN];
                                Buffer.BlockCopy(arrExtData, iX, bytesDER, 0, cbThisDN);
                                AsnEncodedData asndata = new AsnEncodedData(bytesDER);
                                alCADNs.Add(new X500DistinguishedName(asndata).Name);
                            }
                            catch { Debug.Assert(false); }
                            cbCADistinguishedNames -= (2 + cbThisDN);
                            iX += cbThisDN;
                        }
                        htCertFilter.Add("Accepted Authorities", alCADNs);
                        }
                    catch { htCertFilter.Add("Accepted Authorities", "Parse failure"); }
                    break;
                case 0x0d: // signature_algorithms
                    try {
                        int iX = 0;
                        int cbSigHashAlgs = (arrExtData[iX++] << 8) +
                                             arrExtData[iX++];
                        Debug.Assert((cbSigHashAlgs % 2) == 0);

                        var alSigSchemes = new ArrayList();

                        for (int ixSigHashPair = 0; ixSigHashPair < cbSigHashAlgs / 2; ++ixSigHashPair)
                        {
                                alSigSchemes.Add(GetTLS13SigSchemeString((arrExtData[iX + (2 * ixSigHashPair)] << 8) + arrExtData[1+ iX + (2 * ixSigHashPair)]));
                        }
                        htCertFilter.Add("Accepted SignatureSchemes", alSigSchemes);
                    }
                    catch { htCertFilter.Add("Accepted SignatureSchemes", "Parse failure"); }
                    break;
                default:
                    htCertFilter.Add("FilterExt #" + iExtensionType.ToString(), "Length" + iExtDataLen.ToString());
                break;
              }

              iPtr += (iExtDataLen);  // Skip the data*/
            }
        }

        private void GenerateDNSResolutionListSession(Dictionary<int, List<Hashtable>> dictDNSResolutions)
        {
            if (dictDNSResolutions.Count < 1) return;
            try
            {
                Hashtable htAllResolutions = new Hashtable();
                foreach (KeyValuePair<int, List<Hashtable>> kvpResolution in dictDNSResolutions)
                {
                    string sHost = String.Empty;
                    Hashtable htData = new Hashtable();
                    foreach (Hashtable htEvent in kvpResolution.Value)
                    {
                        int iType = getIntValue(htEvent["type"], -1);
                        var htParams = (Hashtable)htEvent["params"];

                        // TODO: HOST_RESOLVER_IMPL_JOB_REQUEST_ATTACH has a list of all of the sslconnectjobs
                        // that attached to this resolution looking for an address to use.

                        if (iType == NetLogMagics.HOST_RESOLVER_IMPL_JOB)
                        {
                            sHost = (htParams["host"] as String) ?? "(missing)";
                            continue;
                        }
                        if (iType == NetLogMagics.HOST_RESOLVER_IMPL_PROC_TASK)
                        {
                            // TODO: What if there's more than one?
                            if (htParams.ContainsKey("canonical_name") && ((htParams["canonical_name"] as String) == String.Empty))
                            {
                                htParams.Remove("canonical_name");
                            }
                            htData = htParams;
                            continue;
                        }

                    }
                    htAllResolutions.Add(sHost, htData);
                }

                Session sessDNS = Session.BuildFromData(false,
                        new HTTPRequestHeaders(
                            String.Format("/DNS_LOOKUPS"),
                            new[] { "Host: NETLOG" }),
                        Utilities.emptyByteArray,
                        new HTTPResponseHeaders(200, "Analyzed Data", new[] { "Content-Type: application/json; charset=utf-8" }),
                        Encoding.UTF8.GetBytes(JSON.JsonEncode(htAllResolutions)),
                        SessionFlags.ImportedFromOtherTool | SessionFlags.RequestGeneratedByFiddler | SessionFlags.ResponseGeneratedByFiddler | SessionFlags.ServedFromCache);
                setAllTimers(sessDNS, _baseTime);
                _listSessions.Add(sessDNS);
            }
            catch (Exception e) { FiddlerApplication.Log.LogFormat("GenerateDNSResolutionListSession failed: " + DescribeExceptionWithStack(e)); }
        }

        // https://www.rfc-editor.org/rfc/rfc8446#section-4.3.2:~:text=extensions%20contains%20a-,SignatureSchemeList,-value%3A%0A%0A%20%20%20%20%20%20enum%20%7B%0A%20%20%20%20%20%20%20%20%20%20/*%20RSASSA
        private static string GetTLS13SigSchemeString(int iValue)
        {
            switch (iValue)
            {
                case 0x0401: return "rsa_pkcs1_sha256";
                case 0x0501: return "rsa_pkcs1_sha384";
                case 0x0601: return "rsa_pkcs1_sha512";

                /* ECDSA algorithms */
                case 0x0403: return "ecdsa_secp256r1_sha256";
                case 0x0503: return "ecdsa_secp384r1_sha384";
                case 0x0603: return "ecdsa_secp521r1_sha512";

                /* RSASSA-PSS algorithms with public key OID rsaEncryption */
                case 0x0804: return "rsa_pss_rsae_sha256";
                case 0x0805: return "rsa_pss_rsae_sha384";
                case 0x0806: return "rsa_pss_rsae_sha512";

                /* EdDSA algorithms */
                case 0x0807: return "ed25519";
                case 0x0808: return "ed448";

                /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
                case 0x0809: return "rsa_pss_pss_sha256";
                case 0x080a: return "rsa_pss_pss_sha384";
                case 0x080b: return "rsa_pss_pss_sha512";

                case 0x0201: return "rsa_pkcs1_sha1";
                case 0x0202: return "dsa_sha1";
                case 0x0203: return "ecdsa_sha1";

                default: return String.Format("unknown(0x{0:x})", iValue);
            }
        }

        private static string GetHashSigString(int iHash, int iSig)
        {
            string sHash;
            string sSig;
            switch (iHash)
            {
                // Hash https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-18
                case 0: sHash = "none"; break;
                case 1: sHash = "md5"; break;
                case 2: sHash = "sha1"; break;
                case 3: sHash = "sha224"; break;
                case 4: sHash = "sha256"; break;
                case 5: sHash = "sha384"; break;
                case 6: sHash = "sha512"; break;
                case 8: sHash = "intrinsic"; break;
                default: sHash = String.Format("unknown(0x{0:x})", iHash); break;
            }
            switch (iSig)
            {
                // Sigs https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-16
                case 0: sSig = "anonymous"; break;
                case 1: sSig = "rsa"; break;
                case 2: sSig = "dsa"; break;
                case 3: sSig = "ecdsa"; break;
                case 4: sSig = "(reserved-4)"; break;
                case 5: sSig = "(reserved-5)"; break;
                case 6: sSig = "(reserved-6)"; break;
                case 7: sSig = "ed25519"; break;
                case 8: sSig = "ed448"; break;
                case 64: sSig = "gostr34102012_256"; break;
                case 65: sSig = "gostr34102012_512"; break;
                default: sSig = String.Format("unknown(0x{0:x})", iSig); break;
            }
            return String.Format("{0}_{1}", sHash, sSig);
        }

        private int GenerateSessionsFromURLRequests(Dictionary<int, List<Hashtable>> dictURLRequests)
        {
            int cURLRequests = dictURLRequests.Count;
            int iLastPct;
            int iRequest = 0;
            iLastPct = 75;

            // Iterate over each URLRequest's events bucket and parse one or more Sessions out of it.
            foreach (KeyValuePair<int, List<Hashtable>> kvpUR in dictURLRequests)
            {
                ++iRequest;
                ParseSessionsFromBucket(kvpUR);
                int iPct = (int)(100 * (0.75f + 0.25f * (iRequest / (float)cURLRequests)));
                if (iPct != iLastPct)
                {
                    NotifyProgress(iPct / 100f, "Completed analysis of URLRequest");
                    iLastPct = iPct;
                }
            }

            return iLastPct;
        }

        // Each bucket contains all of the events associated with a URL_REQUEST, and each URL_REQUEST may contain
        // one or more (Auth, Redirects) Web Sessions.
        private void ParseSessionsFromBucket(KeyValuePair<int, List<Hashtable>> kvpUR)
        {
            List<Hashtable> listEvents = kvpUR.Value;

            SessionFlags oSF = SessionFlags.ImportedFromOtherTool | SessionFlags.ResponseStreamed;  // IsHTTPS?
            HTTPRequestHeaders oRQH = null;
            HTTPResponseHeaders oRPH = null;
            ArrayList alEarlyHints = null;
            MemoryStream msResponseBody = new MemoryStream();
            Dictionary<string, string> dictSessionFlags = new Dictionary<string, string>();
            List<string> listCookieSendExclusions = new List<string>();
            List<string> listCookieSetExclusions = new List<string>();

            dictSessionFlags["X-Netlog-URLRequest-ID"] = kvpUR.Key.ToString();
            dictSessionFlags["X-ProcessInfo"] = String.Format("{0}:0", _sClient);

            string sURL = String.Empty;
            string sMethod = "GET";
            SessionTimers oTimers = new SessionTimers();

            int cbDroppedResponseBody = 0;
            bool bHasStartJob = false;
            bool bHasSendRequest = false;

            foreach (Hashtable htEvent in listEvents)
            {
                try
                {
                    int iType = getIntValue(htEvent["type"], -1);

                    if (iType == -1)
                    {
                        string sType = (htEvent["name"] as String);
                        switch (sType) {
                            case "REQUEST_ALIVE": iType = NetLogMagics.REQUEST_ALIVE; break;
                            case "URL_REQUEST_START_JOB": iType = NetLogMagics.URL_REQUEST_START_JOB; break;
                            case "HTTP_TRANSACTION_SEND_REQUEST_HEADERS": iType = NetLogMagics.SEND_HEADERS; break;
                            case "HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS": iType = NetLogMagics.SEND_QUIC_HEADERS; break;
                            case "HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS": iType = NetLogMagics.SEND_HTTP2_HEADERS; break;
                            case "HTTP_TRANSACTION_READ_RESPONSE_HEADERS": iType = NetLogMagics.READ_HEADERS; break;
                            case "URL_REQUEST_JOB_FILTERED_BYTES_READ": iType = NetLogMagics.FILTERED_BYTES_READ; break;
                            case "COOKIE_INCLUSION_STATUS": iType = NetLogMagics.COOKIE_INCLUSION_STATUS; break;
                            case "HTTP_TRANSACTION_SEND_REQUEST_BODY": iType = NetLogMagics.SEND_BODY; break;
                            case "HTTP_TRANSACTION_SEND_REQUEST": iType = NetLogMagics.SEND_REQUEST; break;
                            case "SSL_CERTIFICATES_RECEIVED": iType = NetLogMagics.SSL_CERTIFICATES_RECEIVED; break;
                            case "SSL_HANDSHAKE_MESSAGE_SENT": iType = NetLogMagics.SSL_HANDSHAKE_MESSAGE_SENT; break;
                            case "SSL_HANDSHAKE_MESSAGE_RECEIVED": iType = NetLogMagics.SSL_HANDSHAKE_MESSAGE_RECEIVED; break;
                            case "SOCKET_BYTES_SENT": iType = NetLogMagics.SOCKET_BYTES_SENT; break;
                        }
                    }

                    var htParams = htEvent["params"] as Hashtable;
                    if (null == htParams)
                    {
                        // The "Trace" format nests the params object inside an args object.
                        var htArgs = htEvent["args"] as Hashtable;
                        if (null != htArgs) htParams = htArgs["params"] as Hashtable;
                    }

                    // Most events we care about should have parameters.  LANDMINE_MEME HERE
                    if (iType != NetLogMagics.SEND_REQUEST && null == htParams) continue;

                    // FiddlerApplication.Log.LogFormat("URLRequest#{0} - Event type: {1} - {2}", kvpUR.Key, iType, sURL);

                    #region ParseImportantEvents
                    // C# cannot |switch()| on non-constant case values. Hrmph.
                    if (iType == NetLogMagics.REQUEST_ALIVE)
                    {
                        int iTrafficAnnotation = getIntValue(htParams["traffic_annotation"], 0);
                        if (iTrafficAnnotation > 0)
                        {
                            string sAnnotation = iTrafficAnnotation.ToString();
                            switch (iTrafficAnnotation)
                            {
                                // TODO (Bug #3): Lookup a friendly string from https://source.chromium.org/chromium/chromium/src/+/master:tools/traffic_annotation/summary/annotations.xml;l=27?q=101845102&ss=chromium
                                case 63171670:  sAnnotation += " (navigation_url_loader)"; break;
                                case 101845102: sAnnotation += " (blink_resource_loader)"; break;
                                case 110815970: sAnnotation += " (resource prefetch)"; break;
                                case 112189210: sAnnotation += " (favicon_loader)"; break;
                                case 16469669:  sAnnotation += " (background_fetch)"; break;
                                case 35266994:  sAnnotation += " (early_hints_preload)"; break;
                                case 113711087: sAnnotation += " (edge_replace_update_client)"; break;
                                case 107267424: sAnnotation += " (open_search)"; break;
                                case 21498113:  sAnnotation += " (service_worker_script_load)"; break;
                                case 88863520:  sAnnotation += " (autofill_query)"; break;
                                case 30454590:  sAnnotation += " (smartscreen)"; break;
                            }
                            dictSessionFlags["X-Netlog-Traffic_Annotation"] = sAnnotation;
                        }
                        continue;
                    }

                    if (iType == NetLogMagics.URL_REQUEST_START_JOB)
                    {
                        // If we already had a URL_REQUEST_START_JOB on this URL_REQUEST, we are probably chasing a redirect.
                        // "finish" off the existing Session and start a new one at this point.
                        // TODO: This is really hacky right now.
                        if (bHasStartJob)
                        {
                            FiddlerApplication.Log.LogFormat("Got more than one START_JOB on URLRequest #{0} for {1}", kvpUR.Key, sURL);
                            AnnotateHeadersWithUnstoredCookies(oRPH, listCookieSetExclusions);
                            BuildAndAddSession(ref oSF, oRQH, oRPH, msResponseBody, dictSessionFlags, sURL, sMethod, oTimers, cbDroppedResponseBody);
                            alEarlyHints = null; oRQH = null; oRPH = null; msResponseBody = new MemoryStream(); sURL = String.Empty; sMethod = "GET"; oTimers = new SessionTimers();
                            // We are effectively on a new request, don't act like we've seen headers for it before.
                            bHasSendRequest = false;
                            listCookieSetExclusions.Clear();
                            listCookieSendExclusions.Clear();
                            // ISSUE: There are probably some dictSessionFlags values that should be cleared here.
                            dictSessionFlags.Remove("ui-comment");
                            dictSessionFlags.Remove("ui-backcolor");
                        }

                        bHasStartJob = true;
                        sURL = (string)htParams["url"];
                        sMethod = (string)htParams["method"];

                        // In case we don't get these later.
                        oTimers.ClientBeginRequest = oTimers.FiddlerGotRequestHeaders = oTimers.FiddlerBeginRequest = GetTimeStamp(htEvent["time"], _baseTime);
                        continue;
                    }

                    if (iType == NetLogMagics.SEND_REQUEST)
                    {
                        // Only look for "BEGIN" events.
                        if ((getIntValue(htEvent["phase"], -1) != 1) &&
                            (htEvent["ph"] as string != "b")) continue;

                        // If we already had a SEND_REQUEST on this URL_REQUEST, we are probably in a HTTP Auth transaction.
                        // "finish" off the existing Session and start a new one at this point.
                        // TODO: This is really hacky right now.
                        if (bHasSendRequest)
                        {
                            FiddlerApplication.Log.LogFormat("Got more than one SendRequest on the URLRequest for {0}", sURL);
                            AnnotateHeadersWithUnstoredCookies(oRPH, listCookieSetExclusions);
                            BuildAndAddSession(ref oSF, oRQH, oRPH, msResponseBody, dictSessionFlags, sURL, sMethod, oTimers, cbDroppedResponseBody);
                            // Keep sURL and sMethod, they shouldn't be changing.
                            alEarlyHints = null; oRQH = null; oRPH = null; msResponseBody = new MemoryStream(); oTimers = new SessionTimers();

                            listCookieSetExclusions.Clear();
                            listCookieSendExclusions.Clear();
                            // ISSUE: There are probably some dictSessionFlags values that should be cleared here.
                        }

                        bHasSendRequest = true;
                        continue;
                    }

                    if (iType == NetLogMagics.SEND_HEADERS)
                    {
                        oTimers.ClientBeginRequest = oTimers.FiddlerGotRequestHeaders = oTimers.FiddlerBeginRequest = GetTimeStamp(htEvent["time"], _baseTime);
                        ArrayList alHeaderLines = htParams["headers"] as ArrayList;
                        if (null != alHeaderLines && alHeaderLines.Count > 0)
                        {
                            string sRequest = sMethod + " " + sURL + " HTTP/1.1\r\n" + String.Join("\r\n", alHeaderLines.Cast<string>().ToArray());
                            oRQH = Fiddler.Parser.ParseRequest(sRequest);
                            AnnotateHeadersWithUnsentCookies(oRQH, listCookieSendExclusions);
                        }
                        continue;
                    }

                    if (iType == NetLogMagics.SEND_QUIC_HEADERS)
                    {
                        dictSessionFlags["X-Transport"] = "QUIC";
                        oTimers.ClientBeginRequest = oTimers.FiddlerGotRequestHeaders = oTimers.FiddlerBeginRequest = GetTimeStamp(htEvent["time"], _baseTime);
                        string sRequest = HeadersToString(htParams["headers"]);
                        if (!String.IsNullOrEmpty(sRequest))
                        {
                            oRQH = Fiddler.Parser.ParseRequest(sRequest);
                            AnnotateHeadersWithUnsentCookies(oRQH, listCookieSendExclusions);
                        }
                        continue;
                    }

                    if (iType == NetLogMagics.SEND_HTTP2_HEADERS)
                    {
                        dictSessionFlags["X-Transport"] = "HTTP2";
                        oTimers.ClientBeginRequest = oTimers.FiddlerGotRequestHeaders = oTimers.FiddlerBeginRequest = GetTimeStamp(htEvent["time"], _baseTime);
                        string sRequest = HeadersToString(htParams["headers"]);
                        if (!String.IsNullOrEmpty(sRequest))
                        {
                            oRQH = Fiddler.Parser.ParseRequest(sRequest);
                            AnnotateHeadersWithUnsentCookies(oRQH, listCookieSendExclusions);
                        }
                        continue;
                    }

                    if (iType == NetLogMagics.COOKIE_INCLUSION_STATUS)
                    {
                        string sOperation = (htParams["operation"] as string) ?? String.Empty;
                        string sCookieName = (htParams["name"] as string) ?? "(name-unavailable)";

                        // Edge-specific fields
                        // bool bIsLegacyCookie = (htParams["msft_browser_legacy_cookie"] as Boolean) ?? false;
                        // string bBrowserProvenance = (htParams["browser_provenance"] as string) ?? String.Empty /*Native*/;

                        // TODO: As of Chrome 81, CookieInclusionStatusNetLogParams also adds |domain| and |path| attributes available if "sensitive" data is included.

                        // In Chrome 81.3993, the |exclusion_reason| field was renamed to |status| because the |cookie_inclusion_status| entries are
                        // now also emitted for included cookies.
                        string sExclusionReasons = (htParams["exclusion_reason"] as string);
                                        if (String.IsNullOrEmpty(sExclusionReasons)) sExclusionReasons = (htParams["status"] as string) ?? String.Empty;

                        // If the log indicates that the cookie was included, just skip it for now.
                        // https://source.chromium.org/chromium/chromium/src/+/master:net/cookies/canonical_cookie.cc;l=899?q=GetDebugString%20cookie&ss=chromium&originalUrl=https:%2F%2Fcs.chromium.org%2F
                        if (sExclusionReasons.OICContains("include"))
                        {
                            if ("expire" == sOperation)
                            {
                                // EXCLUDE_INVALID_DOMAIN,EXCLUDE_OVERWRITE_HTTP_ONLY,EXCLUDE_OVERWRITE_SECURE,
                                // EXCLUDE_FAILURE_TO_STORE (e.g. Set-Cookie header > 4096 characters),
                                // EXCLUDE_NONCOOKIEABLE_SCHEME,EXCLUDE_INVALID_PREFIX
                                listCookieSetExclusions.Add(String.Format("The cookie '{0}' was sent already expired.", sCookieName));
                            }

                            // TODO: Offer a richer cookie-debugging story that exposes the domain/path/inclusion status.
                            continue;
                        }

                        // See |ExclusionReason| list in https://cs.chromium.org/chromium/src/net/cookies/canonical_cookie.h?type=cs&q=EXCLUDE_SAMESITE_LAX&sq=package:chromium&g=0&l=304
                        // EXCLUDE_HTTP_ONLY, EXCLUDE_SECURE_ONLY,EXCLUDE_DOMAIN_MISMATCH,EXCLUDE_NOT_ON_PATH,EXCLUDE_INVALID_PREFIX
                        // EXCLUDE_SAMESITE_STRICT,EXCLUDE_SAMESITE_LAX,EXCLUDE_SAMESITE_EXTENDED,
                        // EXCLUDE_SAMESITE_UNSPECIFIED_TREATED_AS_LAX,EXCLUDE_SAMESITE_NONE_INSECURE,
                        // EXCLUDE_USER_PREFERENCES,

                        if ("store" == sOperation)
                        {
                            // EXCLUDE_INVALID_DOMAIN,EXCLUDE_OVERWRITE_HTTP_ONLY,EXCLUDE_OVERWRITE_SECURE,
                            // EXCLUDE_FAILURE_TO_STORE (e.g. Set-Cookie header > 4096 characters),
                            // EXCLUDE_NONCOOKIEABLE_SCHEME,EXCLUDE_INVALID_PREFIX
                            listCookieSetExclusions.Add(String.Format("Blocked set of '{0}' due to '{1}'", sCookieName, sExclusionReasons));
                        }
                        else if ("expire" == sOperation)
                        {
                            listCookieSetExclusions.Add(String.Format("Blocked expire (set) of '{0}' due to '{1}'", sCookieName, sExclusionReasons));
                        }
                        else if ("send" == sOperation)
                        {
                            // Don't warn about cookies which are obviously inapplicable
                            if (!new string[] { "EXCLUDE_DOMAIN_MISMATCH", "EXCLUDE_NOT_ON_PATH" }.Any(s => sExclusionReasons.Contains(s)))
                            {
                                listCookieSendExclusions.Add(String.Format("Blocked send of '{0}' due to '{1}'", sCookieName, sExclusionReasons));
                            }
                        }
                        else { Debug.Assert(false, "Unknown operation"); }

                        continue;
                    }

                    if (iType == NetLogMagics.SEND_BODY)
                    {
                        int iBodyLength = getIntValue(htParams["length"], 0);
                        if (iBodyLength > 0)
                        {
                            oSF |= SessionFlags.RequestBodyDropped;
                            dictSessionFlags["X-RequestBodyLength"] = iBodyLength.ToString("N0");
                        }
                        continue;
                    }

                    if (iType == NetLogMagics.READ_EARLY_HINTS_RESPONSE_HEADERS)
                    {
                        ArrayList alHeaderLines = htParams["headers"] as ArrayList;
                        if (null != alHeaderLines && alHeaderLines.Count > 0)
                        {
                            if (null == alEarlyHints) alEarlyHints = new ArrayList();
                            alEarlyHints.AddRange(alHeaderLines);
                        }

                    }
                    if ((iType == NetLogMagics.READ_HEADERS) ||
                        (iType == NetLogMagics.FAKE_RESPONSE_HEADERS_CREATED))
                    {
                        ArrayList alHeaderLines = htParams["headers"] as ArrayList;
                        if (null != alHeaderLines && alHeaderLines.Count > 0)
                        {
                            string sResponse = string.Join("\r\n", alHeaderLines.Cast<string>().ToArray());
                            oRPH = Fiddler.Parser.ParseResponse(sResponse);
                            if (null != alEarlyHints && alEarlyHints.Count > 0)
                            {
                                foreach (string s in alEarlyHints)
                                {
                                    oRPH.Add("_X-NetLog-Found-Early-Hint", s);
                                }
                            }
                        }

                        oTimers.ClientBeginResponse = oTimers.FiddlerGotResponseHeaders = oTimers.ServerBeginResponse = GetTimeStamp(htEvent["time"], _baseTime);
                        continue;
                    }

                    // ISSUE: WHAT ABOUT "URL_REQUEST_JOB_BYTES_READ" BYTES? DONT WANT DUPLICATES.

                    if (iType == NetLogMagics.FILTERED_BYTES_READ)
                    {
                        string sBase64Bytes = htParams["bytes"] as string;
                        if (!String.IsNullOrEmpty(sBase64Bytes))
                        {
                            byte[] arrThisRead = Convert.FromBase64String(sBase64Bytes);
                            msResponseBody.Write(arrThisRead, 0, arrThisRead.Length); // WTF, why so verbose?
                        }
                        else
                        {
                            cbDroppedResponseBody += getIntValue(htParams["byte_count"], 0);
                        }
                        oTimers.ServerDoneResponse = oTimers.ClientDoneResponse = GetTimeStamp(htEvent["time"], _baseTime);
                        continue;
                    }
                }
                catch (Exception eX)
                {
                    FiddlerApplication.Log.LogFormat("Parsing event failed:\n{0}", DescribeExceptionWithStack(eX));
                }
                #endregion ParseImportantEvents
            }

            bool bCookieSetFailed = listCookieSetExclusions.Count > 0;
            if (bCookieSetFailed) {
                dictSessionFlags["ui-backcolor"] = "#FF8080";
                dictSessionFlags["ui-comments"] = "A cookie set by Set-Cookie was not stored.";
                AnnotateHeadersWithUnstoredCookies(oRPH, listCookieSetExclusions);
            }
            BuildAndAddSession(ref oSF, oRQH, oRPH, msResponseBody, dictSessionFlags, sURL, sMethod, oTimers, cbDroppedResponseBody);
        }

        private static void AnnotateHeadersWithUnsentCookies(HTTPRequestHeaders oRQH, List<string> listExclusions)
        {
            if (null == oRQH) return;
            foreach (string sExclusion in listExclusions) {
                oRQH.Add("$NETLOG-CookieNotSent", sExclusion);
            }

            listExclusions.Clear();
        }

        private static void AnnotateHeadersWithUnstoredCookies(HTTPResponseHeaders oRPH, List<string> listExclusions)
        {
            if (null == oRPH) return;
            foreach (string sExclusion in listExclusions)
            {
                oRPH.Add("$NETLOG-CookieNotStored", sExclusion);
            }

            listExclusions.Clear();
        }

        private void BuildAndAddSession(ref SessionFlags oSF, HTTPRequestHeaders oRQH, HTTPResponseHeaders oRPH, MemoryStream msResponseBody,
                                        Dictionary<string, string> dictSessionFlags, string sURL, string sMethod, SessionTimers oTimers, int cbDroppedResponseBody)
        {
            // TODO: Sanity-check missing headers.
            if (null == oRQH && !String.IsNullOrWhiteSpace(sURL))
            {
                oRQH = Fiddler.Parser.ParseRequest(sMethod + " " + sURL + " HTTP/1.1\r\nMissing-Data: Request Headers not captured in NetLog\r\n\r\n");
            }

            if (msResponseBody.Length < 1 && cbDroppedResponseBody > 0)
            {
                dictSessionFlags["X-RESPONSEBODYTRANSFERLENGTH"] = cbDroppedResponseBody.ToString("N0");
                oSF |= SessionFlags.ResponseBodyDropped;
            }

            if ((null != oRPH) && msResponseBody.Length > 0)
            {
                // Body bytes stored in the file were already unchunked and decompressed, so rename these
                // headers so we can use this session for AutoResponder playback, etc.
                oRPH.RenameHeaderItems("Content-Encoding", "X-Netlog-Removed-Content-Encoding");
                oRPH.RenameHeaderItems("Transfer-Encoding", "X-Netlog-Removed-Transfer-Encoding");
                string sOriginalCL = oRPH["Content-Length"];
                oRPH["Content-Length"] = msResponseBody.Length.ToString();
                if (!String.IsNullOrEmpty(sOriginalCL) && oRPH["Content-Length"] != sOriginalCL)
                {
                    oRPH["X-Netlog-Original-Content-Length"] = sOriginalCL;
                }
            }

            Session oS = Session.BuildFromData(false,
                oRQH,
                Utilities.emptyByteArray,
                oRPH,
                msResponseBody.ToArray(),
                oSF);

            // Store the URL from the URLRequest here, because it might have a URL Fragment in it, and the URL built
            // out of the headers definitely should not.
            if (oS.fullUrl != sURL) {
                oS["X-Netlog-URLRequest-URL"] = sURL;
            }

            // Attach the SessionFlags to the new Session.
            foreach (KeyValuePair<string, string> sFlag in dictSessionFlags)
            {
                oS[sFlag.Key] = sFlag.Value;
            }

            // Assign the timestamps we read from the events.
            oS.Timers = oTimers;

            _listSessions.Add(oS);
            // FiddlerApplication.Log.LogFormat("Added Session #{0}", oS.id);
        }

        // Chrome annoyingly uses both Hashtables (JS Object) and Arraylists (JS Array) to represent headers
        // depending on which event is in use.
        public static string HeadersToString(object o)
        {
            if (o is ArrayList) return HeaderArrayToHeaderString((ArrayList)o);
            if (o is Hashtable) return HeaderHashtableToHeaderString((Hashtable)o);
            if (null != o) Debug.Assert(false, "Unexpected header format");
            return String.Empty;
        }

        private static string HeaderHashtableToHeaderString(Hashtable ht)
        {
            if (null == ht || ht.Count < 1) return String.Empty;

            string sMethod = "MISSING";
            string sScheme = "MISSING";
            string sAuthority = "MISSING";
            string sPath = "/MISSING";
            List<string> slHeaders = new List<string>();

            foreach (DictionaryEntry de in ht)
            {
                KeyValuePair<string, string> kvp = new KeyValuePair<string, string>((string)de.Key, (string)de.Value);
                if (kvp.Key.StartsWith(":"))
                {
                    if (kvp.Key.Equals(":method")) { sMethod = kvp.Value; continue; }
                    if (kvp.Key.Equals(":scheme")) { sScheme = kvp.Value; continue; }
                    if (kvp.Key.Equals(":authority")) { sAuthority = kvp.Value; continue; }
                    if (kvp.Key.Equals(":path")) { sPath = kvp.Value; continue; }
                }
                slHeaders.Add(kvp.Key + ": " + kvp.Value);
            }

            return String.Format("{0} {1}://{2}{3} {4}\r\n{5}",
                sMethod, sScheme, sAuthority, sPath, "HTTP/1.1",
                String.Join("\r\n", slHeaders.ToArray()));
        }

        private static string HeaderArrayToHeaderString(ArrayList alIn)
        {
            if (null == alIn || alIn.Count < 1) return String.Empty;

            string sMethod = "MISSING";
            string sScheme = "MISSING";
            string sAuthority = "MISSING";
            string sPath = "/MISSING";
            List<string> slHeaders = new List<string>();

            foreach (string s in alIn)
            {
                if (s.StartsWith(":"))
                {
                    if (s.StartsWith(":method: ")) { sMethod = s.Substring(9); continue; }
                    if (s.StartsWith(":scheme: ")) { sScheme = s.Substring(9); continue; }
                    if (s.StartsWith(":authority: ")) { sAuthority = s.Substring(12); continue; }
                    if (s.StartsWith(":path: ")) { sPath = s.Substring(7); continue; }
                }
                slHeaders.Add(s);
            }

            return String.Format("{0} {1}://{2}{3} {4}\r\n{5}",
                sMethod, sScheme, sAuthority, sPath, "HTTP/1.1",
                String.Join("\r\n", slHeaders.ToArray()));
        }

    }
}
