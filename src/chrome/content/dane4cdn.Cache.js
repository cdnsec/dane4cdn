/* Extended DNSSEC Validator's internal cache - shared with all window tabs */
dane4cdn.Cache = {

    flushTimer: null,
    flushInterval: 0,     // in seconds (0 is for cache disable)
    data: null,

    init: function() {

    // Create new array for caching
        this.data = new Array();

    // Get cache flush interval
        this.getFlushInterval();

    // Timer cache flushing is currently disabled
    /*
    // Create the timer for cache flushing
    if (dnssecExtension.debugOutput) {
      dump(dnssecExtension.debugPrefix + 'Initializing flush timer with interval: '
           + this.flushInterval + ' s\n');
    }

    this.flushTimer = Components.classes["@mozilla.org/timer;1"]
                                .createInstance(Components.interfaces.nsITimer);

    // Define cache flush timer callback
    this.flushTimer.initWithCallback(
      function() {
        dnssecExtCache.delExpiredRecords();
      },
      this.flushInterval * 1000,
      Components.interfaces.nsITimer.TYPE_REPEATING_SLACK); // repeat periodically
    */
    },

    getFlushInterval: function() {
        this.flushInterval = dane4cdn.Extension.prefs.getIntPref("cacheflushinterval");
    },

    addRecord: function(certRecords) {
    
        // Get current time
        const cur_t = new Date().getTime();
    
        // Record expiration time
        certRecords.exp_ttl = cur_t + certRecords.ttl * 1000;   // expire4 is in seconds
    
        // delete this.data[domainRecord.domain];
        this.data[certRecords.domain] = certRecords;
    },

    getRecord: function(domain) {
        const c = this.data;

        if (typeof c[domain] != 'undefined') {
            return c[domain];
        }
        return new dane4cdn.CertRecord();
    },

    printContent: function() {
        var i = 0;
        const c = this.data;
        const cur_t = new Date().getTime();
        var ttl;
    
        dane4cdn.Extension.logMsg('Cache content:');
    
        for (var n in c) {
            // compute TTL in seconds
            ttl = Math.round((c[n].exp_ttl - cur_t) / 1000);
      
            dane4cdn.Extension.logMsg('r' + i + ': \"' + n + '\": '
                 + c[n].exp_ttl + ' (' + c[n].ttl + '); nxdomain:' + c[n].nxdomain + '; secure:' + c[n].secure +
                  '; bogus:' + c[n].bogus + '; why_bogus:' + c[n].why_bogus + '\n');
            i++;
        }
    },

    delExpiredRecords: function() {
        const c = this.data;

        // Get current time
        const cur_t = new Date().getTime();

        dane4cdn.Extension.logMsg('Flushing expired cache records...');

        for (var n in c) {
            if (cur_t > c[n].exp_ttl ) {
                dane4cdn.Extension.logMsg('Deleting cache r: \"' + n + '\"');
                delete c[n];
            }
        }
    },

    delAllRecords: function() {

        dane4cdn.Extension.logMsg('Flushing all cache records...');

        delete this.data;
        this.data = new Array();
    },

    existsUnexpiredRecord: function(n) {
        const c = this.data;
        const cur_t = new Date().getTime();
    
        if (typeof c[n] != 'undefined') {
          return (cur_t <= c[n].exp_ttl);
        }
        return false;
    },
  
};
