using System.Reflection;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("FiddlerImportNetlog")]
[assembly: AssemblyDescription("Import Chromium NetLog events to Fiddler")]
[assembly: AssemblyCopyright("Copyright ©2023 Eric Lawrence")]
[assembly: System.Resources.NeutralResourcesLanguage("en-US")]
[assembly: ComVisible(false)]
[assembly: AssemblyVersion("1.3.4.4")]  // ALWAYS UPDATE THE VERSION in the [ProfferFormat] attribute in FiddlerInterface.cs to match!
[assembly: Fiddler.RequiredVersion("4.6.0.0")]


/*
TODO:
HTTP_STREAM_JOB has a binding between the request and the socket. Hook them up so we can propagate the connection info to the URL_REQUEST-generated Sessions.

t=3262 [st=0]        SOCKET_POOL_BOUND_TO_SOCKET
                     --> source_dependency = 1250 (SOCKET)
t=3262 [st=0]    HTTP_STREAM_JOB_BOUND_TO_REQUEST
                 --> source_dependency = 1701 (URL_REQUEST)
*/

// v1.3.4.4
// Add lightweight breakout of server certinfo

// v1.3.4.3
// Set oTimers' values for ClientBeginResponse, ClientDoneResponse, and ServerDoneResponse so Timeline view works better.

// v1.3.4.2
// When renaming Transfer-Encoding/Chunk-Encoding headers, set Content-Length to enhance AutoResponder playback
// Update copyright to 2023

// v1.3.4.1
// Fix parsing of TLS/1.3 sigscheme list

// v1.3.4.0
// Parse certificaterequest message properly on TLS/1.3 connections
// Add smartscreen to net annotations

// v1.3.3.0
// Add ClientHello and ServerHello to SecureSocket list

// v1.3.2.3
// Add more traffic_annotation values

// v1.3.2.2
// Add ".json;.gz" hint to ProfferFormat registration

// v1.3.2.1
// Add DNS entries to log
// Add READ_EARLY_HINTS_RESPONSE_HEADERS - _X-NetLog-Found-Early-Hint - https://www.fastly.com/blog/beyond-server-push-experimenting-with-the-103-early-hints-status-code

// v1.3.1.0
// Support for FAKE_RESPONSE_HEADERS_CREATED for HSTS and Automatic HTTPS upgrades
// Add socket address info to generated SOCKETS list's session

// v1.3.0.1
// Less Log spam
// Write imported filename to log

// v1.3
// Support importing NetLog events from a Chromium trace json file

// v1.2.7
// Flag failed Set-Cookies in Web Sessions list

// v1.2.6
// Record X-Netlog-URLRequest-ID and X-ProcessInfo, even when we don't receive a StartRequest
// Add mappings for most common traffic_annotation values when writing X-Netlog-Traffic_Annotation

// v1.2.5
// Record sensitivity level

// v1.2.4
// Better parse HTTP Auth where there are multiple SendRequests

// v1.2.3
// Add |traffic_annotation| to session properties

// v1.2.2
// Update Cookie Inclusion reasons to match latest CL 81.0.3993 https://chromium-review.googlesource.com/c/chromium/src/+/1960865

// v1.2.1
// Add Cookie Exclusion warnings

// v1.2
// Parse CertificateRequest TLS Handshake message and SSL_HANDSHAKE_MESSAGE_RECEIVED.

// TODO: Surface the CN for each certificate from the server
/* TODO: Parse out messages indicating whether the client sent a cert, and what that cert was.

 t= 7906 [st= 580]      SSL_CLIENT_CERT_PROVIDED
                       --> cert_count = 2
t= 7906 [st= 580]      SSL_HANDSHAKE_MESSAGE_SENT
                       --> bytes =
                         0B 00 0D C0 00 0D BD 00  06 B4 30 82 06 B0 30 82   . .. .. ..0...0.
                         04 98 A0 03 02 01 02 02  13 1C 00 4A 4D 7F 50 4B   .......... JM.PK
                         6F 8E 33 AB 1B 04 00 01  00 4A 4D 7F 30 0D 06 09   o.3... . JM.0...
                         2A 86 48 86 F7 0D 01 01  0B 05 00 30 15 31 13 30   *.H....... 0.1.0
			...
                         4D 86 43 E1 23 A0 F9 B7  4F AF 84 AF 48 EC D5 F8   M.C.#...O...H...
                         DE 4A BD 6B A7 FB 3E 5E  3E E7 8E 11 64 96 2D EB   .J.k..>^>...d.-.
                         69 0A C8 2C                                        i..,
                       --> type = 11

*/

// v1.1.2
// Support ZIP compressed JSON logs

// v1.1.1.2
// Support .gz compressed JSON logs

// v1.1.1.1
// Correct rename of Transfer-Encoding and Content-Encoding response headers

// v1.1.1
// Better exception handling around debugtree creation
// Publish as open source on GitHub.

// v1.0.0.1
// Change installer to not require Admin
// Handle logs where htConstants["timeTickOffset"] is a string rather than a long

// v1.0.1.0
// Improve exception handling
// Handle cases where headers are missing
// Handle cases where headers are encoded as a JSObject instead of a JSArray
// Rename Content-Encoding header to avoid confusion

// v1.0.2.0
// Basic support for timers

// v1.0.3.0
// Handle captures that are missing polledData (e.g. extensions) because capture was created at Browser Startup

// v1.0.4.0
// Reduce progress notification spew

// v1.1
// Cleanup code
// Support multiple sessions per URL_REQUEST entry (e.g. on redirection)




