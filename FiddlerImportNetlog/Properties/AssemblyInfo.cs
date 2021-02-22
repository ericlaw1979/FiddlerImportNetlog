using System.Reflection;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("FiddlerImportNetlog")]
[assembly: AssemblyDescription("Import Chromium NetLog events to Fiddler")]
[assembly: AssemblyCopyright("Copyright ©2020 Eric Lawrence")]
[assembly: System.Resources.NeutralResourcesLanguage("en-US")]
[assembly: ComVisible(false)]
[assembly: AssemblyVersion("1.2.6.0")]  // ALWAYS UPDATE THE VERSION in the [ProfferFormat] attribute in FiddlerInterface.cs to match!
[assembly: Fiddler.RequiredVersion("4.6.0.0")]

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




