dane4cdn.Resolver = {
  
    uri: null,

    checkDomainSecurity: function(uri) {

        // Set action state
        dane4cdn.UIHandler.setState(uri, dane4cdn.UIHandler.STATE_ACTION);

        certRecords = this.getValidatedCert(uri.asciiHost);

        if(certRecords) { 
            var ret = this.setCertState(uri, certRecords);
            if (!ret) return;

            if(uri.schemeIs("https")) {
            //check if https is available anyway
                dane4cdn.Extension.logMsg('connection is https, going to checkCertificate');
                dane4cdn.CertTools.checkCertificate(uri, certRecords);
            }
            else {
                dane4cdn.Extension.logMsg(uri.asciiHost + ' has dane certs, please try https!');
//                dane4cdn.UIHandler.enableSwitchHttps(uri, true)
            }
        }
    },

    getValidatedCert: function(domain) {

        var certRecords = null; //CERT list

        if (dane4cdn.Cache.existsUnexpiredRecord(domain)) {
            dane4cdn.Extension.logMsg("Get validated certificates from cache.");
            certRecords = dane4cdn.Cache.getRecord(domain);
        } 
        else {
            dane4cdn.Extension.logMsg("Get validated certificates from DNS.");
            certRecords = dane4cdn.DNSResolver.getCertRecord(domain);

            if (dane4cdn.Cache.flushInterval) { // do not cache if 0
                dane4cdn.Cache.addRecord(certRecords);
            }
        }

        return certRecords;
    },

  //Update the ui with appropriate cert state
  //Returns false on DNSSEC unsecured
     setCertState: function(uri, certRecord) {
         if (!certRecord.secure) {
             dane4cdn.UIHandler.setState(uri, dane4cdn.UIHandler.STATE_CERT_DNSSEC_ERROR);
             return false;
         }
         else if (certRecord.nxdomain) {
                 dane4cdn.UIHandler.setState(uri, dane4cdn.UIHandler.STATE_CERT_DANE_NX);
                 return false;
         }
         
         return true;
     }
};
