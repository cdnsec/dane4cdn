//Define our namespace
if(!dane4cdn) var dane4cdn={};

window.addEventListener("load", function() { dane4cdn.Extension.init(); }, false);
window.addEventListener("unload", function() { dane4cdn.Extension.uninit(); }, false);

/*
 * Main extension object
 */
dane4cdn.Extension = {
    dane4cdnExtID: "dane4cdn@ccert.edu.cn",
    debugOutput: false,
    debugPrefix: "dane4cdn: ",
    prefBranch : "extensions.dane4cdn.",
    prefs: null,

    init: function() {
        //initilize our preferences
        this.prefs = Components.classes["@mozilla.org/preferences-service;1"]
                     .getService(Components.interfaces.nsIPrefService)
                     .getBranch(this.prefBranch);
        this.prefs.QueryInterface(Components.interfaces.nsIPrefBranch2);
        this.prefs.addObserver("", this, false);

        
        // Read initial preferences
        this.getDebugOutputFlag(); // Enable debugging information on stdout if desired
        
        //initialize the UI and libunbound context
        dane4cdn.UIHandler.init();
        dane4cdn.Cache.init();
        dane4cdn.Libunbound.init();

        // Set error mode (no icon)
        dane4cdn.UIHandler.setState(null, dane4cdn.UIHandler.STATE_ERROR);
    
        // Add a progress listener to the urlbar
        //gBrowser.addProgressListener(extvalUrlBarListener, Components.interfaces.nsIWebProgress.NOTIFY_LOCATION);
        // var flags = 0;
        // flags |= Components.interfaces.nsIWebProgress.NOTIFY_ALL;
        // flags |= Components.interfaces.nsIWebProgress.NOTIFY_STATE_ALL;
        // addProgressListener accepts only one argument
        //gBrowser.addProgressListener(dane4cdn.UrlBarListener, flags);
        
        // gBrowser.addProgressListener only accepts one argument!
        gBrowser.addProgressListener(dane4cdn.UrlBarListener);
    },

  
    uninit: function() {
        gBrowser.removeProgressListener(dane4cdn.UrlBarListener);
        this.prefs.removeObserver("", this);
        dane4cdn.Libunbound.shutdown();
    },


  /*
   * If debugout is enabled, log the message to console
   */
    logMsg: function(msg) {
        if(this.debugOutput) {
            var consoleService = Components.classes["@mozilla.org/consoleservice;1"]
                .getService(Components.interfaces.nsIConsoleService);
            consoleService.logStringMessage("dane4cdn console: " + msg);
            dump(this.debugPrefix + msg + "\n");
        }
    },


    getDebugOutputFlag: function() {
        this.debugOutput = this.prefs.getBoolPref("debugoutput");
    },

  /*
   * Called when events occur
   */
    observe: function(aSubject, aTopic, aData) {
        if (aTopic != "nsPref:changed") return;

        switch (aData) {
            case "debugoutput":
                this.getDebugOutputFlag();
                break;
            case "dnsserver":
                dane4cdn.Cache.delAllRecords();
                break;
            case "cacheflushinterval":
                dane4cdn.Cache.getFlushInterval();
                if (!dane4cdnCache.flushInterval) dane4cdnCache.delAllRecords();
                break;
            default :
                this.logMsg("Undefined change.");
                break;
        }
    },


    processNewURL: function(aLocationURI) {
        var scheme = null;
        var asciiHost = null;
        var utf8Host = null;
        
        //prevent NS_ERRORS from StringBundle
        try {
            scheme = aLocationURI.scheme;             // Get URI scheme
            asciiHost = aLocationURI.asciiHost;       // Get punycoded hostname
            utf8Host = aLocationURI.host;             // Get UTF-8 encoded hostname
        } catch(ex) {
            this.logMsg('Exception: ' + ex);
        }
    
        this.logMsg('Scheme: "' + scheme + '"; ' + 'ASCII domain name: "' + asciiHost + '"');
        dane4cdn.UIHandler.setState(aLocationURI, dane4cdn.UIHandler.STATE_ERROR);
    
        if (scheme == 'chrome' ||                   // Eliminate chrome scheme
            asciiHost == null ||
            asciiHost == '' ||                      // Empty string
            asciiHost.indexOf("\\") != -1 ||        // Eliminate addr containing '\'
            asciiHost.indexOf(":") != -1 ||         // Eliminate IPv6 addr notation
            asciiHost.search(/[A-Za-z]/) == -1) {   // Eliminate IPv4 addr notation
    
            this.logMsg('URI is invalid');
    
            // Set error mode (no icon)
//            dane4cdn.UIHandler.setState(dane4cdn.UIHandler.STATE_ERROR);
            
            return;
        }

        if (scheme != "https") {
            this.logMsg('Please use https');
 //           dane4cdn.UIHandler.setState(dane4cdn.UIHandler.STATE_ERROR);
            return;
        }

        // Check domain certs security by DANE
        dane4cdn.Resolver.checkDomainSecurity(aLocationURI);
    }
};


dane4cdn.UrlBarListener = {
    
    //window location changed, also happens on changing tabs
    onLocationChange: function(aWebProgress, aRequest, aLocationURI) {
        dane4cdn.Extension.processNewURL(aLocationURI);
    },
  
    onSecurityChange: function(aWebProgress, aRequest, aState) {
//        dane4cdn.Extension.processNewURL(window.gBrowser.currentURI);
    }
    
//    onStateChange: function(aWebProgress, aRequest, aStateFlags, aStatus) {
//    },
//    
//    onProgressChange: function(aWebProgress, aRequest,
//                               aCurSelfProgress, aMaxSelfProgress,
//                               aCurTotalProgress, aMaxTotalProgress) {
//    },
//    
//    onStatusChange: function(aWebProgress, aRequest, aStatus, aMessage) {
//    }
};
