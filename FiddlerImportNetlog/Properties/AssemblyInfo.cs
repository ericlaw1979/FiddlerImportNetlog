using System.Reflection;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("FiddlerImportNetlog")]
[assembly: AssemblyDescription("Import Chromium NetLog events to Fiddler")]
[assembly: AssemblyCopyright("Copyright ©2019 Eric Lawrence")]
[assembly: System.Resources.NeutralResourcesLanguage("en-US")]
[assembly: ComVisible(false)]
[assembly: AssemblyVersion("1.1.2.0")]              // ALSO UPDATE THE VERSION in the [ProfferFormat] attribute to match!
[assembly: Fiddler.RequiredVersion("4.6.0.0")]

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




