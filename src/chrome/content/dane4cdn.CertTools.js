/*
 * Certificate functions
 */
dane4cdn.CertTools = {

    overrideService: Components.classes["@mozilla.org/security/certoverride;1"]
        .getService(Components.interfaces.nsICertOverrideService),

    state : {
        STATE_IS_BROKEN : 
            Components.interfaces.nsIWebProgressListener.STATE_IS_BROKEN,
        STATE_IS_INSECURE :
            Components.interfaces.nsIWebProgressListener.STATE_IS_INSECURE,
        STATE_IS_SECURE :
            Components.interfaces.nsIWebProgressListener.STATE_IS_SECURE
    },


    //Checks if the certificate presented by the uri is valid
    //Based on Perspectives addon
    //Source: https://github.com/danwent/Perspectives
    checkCertificate: function(uri, certRecord) {
        //won't work if we're not on https
        if(!uri.schemeIs("https")) { return };

        dane4cdn.Extension.logMsg('Connection is https, checking certificates...');

        var cert = this.getCertificate(window.gBrowser);
        if(!cert) {
            dane4cdn.Extension.logMsg('Unable to get a certificate');
            dane4cdn.UIHandler.setState(uri, dane4cdn.UIHandler.STATE_CERT_ERROR);
            return;
        }

        var state = window.gBrowser.securityUI.state;
        var is_override_cert = this.overrideService.isCertUsedForOverrides(cert, true, true);

        dane4cdn.Extension.logMsg('is_override_cert = ' + is_override_cert);

        // see if the browser has this cert installed prior to this browser session
        // seems like we can't tell the difference between an exception added by the user
        // manually and one we installed permemently during a previous browser run.
        var secureConnection = !(state & this.state.STATE_IS_INSECURE);
        var browser_trusted = secureConnection && !(is_override_cert);

        dane4cdn.Extension.logMsg('browser_trusted = ' + browser_trusted);

        var dns_trusted = this.is_trusted_by_dns(cert, certRecord);

        dane4cdn.Extension.logMsg('dns_trusted = ' + dns_trusted.state);


        switch (dns_trusted.state) {
            case "insecure" :
                if (is_override_cert) {
                    dane4cdn.Extension.logMsg('Should remove override, no dnssec protection');
                    dane4cdn.UIHandler.setState(uri, dane4cdn.UIHandler.STATE_CERT_DANE_NOTMATCH);
                }

                if (browser_trusted) {
                    dane4cdn.UIHandler.setState(uri, dane4cdn.UIHandler.STATE_CERT_DANE_NOTMATCH);
                }
                break;

            case "delegation" :
                if(!secureConnection) {
                    if(this.do_override(window.gBrowser, cert)) {
                        dane4cdn.Extension.logMsg('Certificate trust is overrided');
                    }
                }
                dane4cdn.UIHandler.setDelegationInfo(uri, dns_trusted.delegation);
                if(browser_trusted) {
                    dane4cdn.UIHandler.setState(uri, dane4cdn.UIHandler.STATE_CERT_DANE_DELEGATED_CA);
                } 
                else {
                    dane4cdn.UIHandler.setState(uri, dane4cdn.UIHandler.STATE_CERT_DANE_DELEGATED);
                }
                break;

            case "owner" :
                if(!secureConnection) {
                    if(this.do_override(window.gBrowser, cert)) {
                        dane4cdn.Extension.logMsg('Certificate trust is overrided');
                    }
                }
                if(browser_trusted) {
                    dane4cdn.UIHandler.setState(uri, dane4cdn.UIHandler.STATE_CERT_DANE_OWNER_CA);
                } 
                else {
                    dane4cdn.UIHandler.setState(uri, dane4cdn.UIHandler.STATE_CERT_DANE_OWNER);
                }
                break;
        }
    },

    //checks if certificate can be validated using dnssec
    is_trusted_by_dns: function(cert, certRecord) {
        //var sha1 = cert.sha1Fingerprint.replace(/:/g,'').toUpperCase();
        var flag = "insecure";

        if (!certRecord.secure || certRecord.nxdomain) {
            return {state: flag, delegation: null};
        }

        var delegationInfo = null, tmp_state = false;
        for(var i = 0; i < certRecord.tlsa.length; i++) {
            if (certRecord.tlsa[i][0] == 4 && !delegationInfo) {
                if (this.isCertValidated(certRecord.tlsa[i][3])) {
                    var dane_cert = this.constructCertificate(certRecord.tlsa[i][3]);
                    if (dane_cert) {
                        delegationInfo = {delegatorCN: dane_cert.commonName, 
                           organization: dane_cert.organization, 
                           country: null,
                           cert: cert};
                    }
                }
            } else if (certRecord.tlsa[i][0] == 3 && !tmp_state) {
                if ( this.isCertMatch(cert, certRecord.tlsa[i]) ) {
                    tmp_state = true;
                }
            }
        }

        if (tmp_state && delegationInfo) {
            flag = "delegation";
            delegationInfo.delegateeCN = cert.commonName;
        } else if (tmp_state) {
            flag = "owner";
        }
        dane4cdn.Extension.logMsg("Cert from dane is: " + flag);

        return {state: flag, 
            delegation: delegationInfo} ;
    },


    isCertValidated: function(certStr) {
        // validated the cert with certChain, combining with CERT DB in browser
        return true
    },


    isCertMatch: function(cert, tlsa_record) {
        var ihash = Components.interfaces.nsICryptoHash;
        var hasher = Components.classes["@mozilla.org/security/hash;1"].createInstance(ihash);
        var hashlen = 0;
        if (tlsa_record[2] == 1) {
            hasher.init(ihash.SHA256);
            hashlen = 64;
        }
        else if (tlsa_record[2] == 2) {
            hasher.init(ihash.SHA512);
            hashlen = 128;
        }
        else {
            //0 type (exact content) not supported yet
            return false
        }

        var len = {};
        var der = cert.getRawDER(len);
        hasher.update(der, len.value);

        var binHash = hasher.finish(false);
        // convert the binary hash data to a hex string.
        var s = [this.charcodeToHexString(binHash.charCodeAt(i)) for (i in binHash)].join("").toUpperCase().substring(0,hashlen);
        dane4cdn.Extension.logMsg("checking tlsa record: " + s + " / " + tlsa_record[3]);
        return s == tlsa_record[3];
    },

    charcodeToHexString: function(charcode) {
        return ("0" + charcode.toString(16)).slice(-2);
    },

    hex2a : function (hex) {
        var str = '';
        for (var i = 0; i < hex.length; i += 2)
            str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
        return str;
    },

    hex2b : function (hex) {
        b64 = btoa(this.hex2a(hex));
        return b64;
    },

    constructCertificate: function(str) {
        //str is hex  string
        var certDB = Components.classes["@mozilla.org/security/x509certdb;1"]
            .getService(Components.interfaces.nsIX509CertDB);

        cert = certDB.constructX509FromBase64(this.hex2b(str));

        for (i in cert) {
            if (cert[i])
            dane4cdn.Extension.logMsg(i.toString() + ':' + cert[i].toString());
        }

        return cert;

    },

    //gets valid or invalid certificate used by the browser
    getCertificate: function(browser) {
        var uri = browser.currentURI;
        var ui = browser.securityUI;

        var cert = this.get_valid_cert(ui);
        if(!cert){
            cert = this.get_invalid_cert(uri);
        }

        if(!cert) {
            return null;
        }
        return cert;
    },

    // gets current certificate, if it PASSED the browser check 
    get_valid_cert: function(ui) {
        try { 
            ui.QueryInterface(Components.interfaces.nsISSLStatusProvider); 
            if(!ui.SSLStatus) 
                return null; 
            return ui.SSLStatus.serverCert; 
        }
        catch (e) {
            dane4cdn.Extension.logMsg('get_valid_cert: ' + e);
            return null;
        }
    },

    // gets current certificate, if it FAILED the security check
    get_invalid_cert: function(uri) {
        var gSSLStatus = this.get_invalid_cert_SSLStatus(uri);
        if(!gSSLStatus){
            return null;
        }
        return gSSLStatus.QueryInterface(Components.interfaces.nsISSLStatus)
            .serverCert;
    },
    /*  
        get_invalid_cert_SSLStatus: function(uri) {
        var recentCertsSvc = 
        Components.classes["@mozilla.org/security/recentbadcerts;1"]
        .getService(Components.interfaces.nsIRecentBadCertsService);
        org.os3sec.Extval.Extension.logMsg('66666');
        if (!recentCertsSvc)
        return null;

        var port = (uri.port == -1) ? 443 : uri.port;  

        var hostWithPort = uri.host + ":" + port;
        org.os3sec.Extval.Extension.logMsg('77777');
        var gSSLStatus = recentCertsSvc.getRecentBadCert(hostWithPort);
        org.os3sec.Extval.Extension.logMsg('88888');
        if (!gSSLStatus)
        return null;
        return gSSLStatus;
        },
        */

    get_invalid_cert_SSLStatus: function(uri){
        var recentCertsSvc = null;

        // firefox <= 19 and seamonkey
        if (typeof Components.classes["@mozilla.org/security/recentbadcerts;1"]
                !== "undefined") {

                    recentCertsSvc = Components.classes["@mozilla.org/security/recentbadcerts;1"]
                        .getService(Components.interfaces.nsIRecentBadCertsService);
                }
        // firefox > v20
        else if (typeof Components.classes["@mozilla.org/security/x509certdb;1"]
                !== "undefined") {
                    var certDB = Components.classes["@mozilla.org/security/x509certdb;1"]
                        .getService(Components.interfaces.nsIX509CertDB);
                    if (!certDB)
                        return null;

                    //			var pbs = Components.classes["@mozilla.org/privatebrowsing;1"]
                    //				.getService(Components.interfaces.nsIPrivateBrowsingService);
                    //			recentCertsSvc = certDB.getRecentBadCerts(pbs.privateBrowsingEnabled);
                    
                    //			firefox > v21
                    recentCertsSvc = certDB.getRecentBadCerts(true);
        }
        else {
            dane4cdn.Extension.logMsg("error", "No way to get invalid cert status!");
            return null;
        }

        if (!recentCertsSvc)
            return null;

        var port = (uri.port == -1) ? 443 : uri.port;

        var hostWithPort = uri.host + ":" + port;
        var gSSLStatus = recentCertsSvc.getRecentBadCert(hostWithPort);
        if (!gSSLStatus){
            return null;
        }
        return gSSLStatus;
    },

    //Override the certificate as trusted
    do_override: function(browser, cert) { 
        var uri = browser.currentURI;

        dane4cdn.Extension.logMsg('Overriding certificate trust ');

        //Get SSL status (untrusted flags)
        var gSSLStatus = this.get_invalid_cert_SSLStatus(uri);
        if(gSSLStatus == null) { 
            return false; 
        } 
        var flags = 0;
        if(gSSLStatus.isUntrusted)
            flags |= this.overrideService.ERROR_UNTRUSTED;
        if(gSSLStatus.isDomainMismatch)
            flags |= this.overrideService.ERROR_MISMATCH;
        if(gSSLStatus.isNotValidAtThisTime)
            flags |= this.overrideService.ERROR_TIME;
        //override the certificate trust
        this.overrideService.clearValidityOverride(uri.asciiHost, uri.port);
        this.overrideService.rememberValidityOverride(uri.asciiHost, uri.port, cert, flags, true);

        setTimeout(function (){ browser.loadURIWithFlags(uri.spec, flags);}, 25);
    }
}
