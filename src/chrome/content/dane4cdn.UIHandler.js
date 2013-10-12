dane4cdn.UIHandler = {
    STATE_CERT_DANE_DELEGATED               : "daneDelegation",
    STATE_CERT_DANE_DELEGATED_CA            : "daneDelegationCA",
    STATE_CERT_DANE_OWNER_CA                : "daneOwnerCA",
    STATE_CERT_DANE_OWNER                   : "daneOwner",
    
    STATE_CERT_ERROR                        : "certError",
    STATE_CERT_DANE_NX                      : "certNotExist",
    STATE_CERT_DANE_NOTMATCH                : "certNotMatch",
    STATE_CERT_DNSSEC_ERROR                 : "dnssecError",

    //Action
    STATE_ACTION : "stateAction",
    // Error or unknown state occured
    STATE_ERROR : "stateError",
  
    // Cache the most recent uri and state
    _uri : null,
    _state : null,
  
    init : function() {
        this.strings = document.getElementById("dane4cdn-strings");
        this.identityPopupDane4CDNLabel = document.getElementById("identity-popup-dane4cdn-label");
        this.identityPopupDane4CDNDelegatorLabel = document.getElementById("identity-popup-dane4cdn-delegator-label");
        this.identityPopupDane4CDNDelegateeLabel = document.getElementById("identity-popup-dane4cdn-delegatee-label");
        this.identityPopupContentVerifier = document.getElementById("identity-popup-content-verifier");
        this.identityPopupDaneIcon = document.getElementById("identity-popup-dane-icon");
//        this.switchHttpsBox = document.getElementById("switch-https-box");
        this.identityIconLabel = document.getElementById("identity-icon-dane-label");
        this.identityIconCountryLabel = document.getElementById("identity-icon-country-dane-label");
        this.cert = null
    },

  /*
   * Updates the messages in identity popup when it opens
   */
    onIdentityPopupShow: function(event) {
        this.setMessages(this._state);
    },
  

    setDelegationInfo : function(uri, delegation) {
        if (delegation.organization) {
            this.identityIconLabel.setAttribute("value", "("+delegation.organization+")");
        }
        if (delegation.country) {
            this.identityIconCountryLabel.setAttribute("value", "["+delegation.country+"]");
        }
        if (delegation.cert) {
            this.cert = delegation.cert;
        }
        if (delegation.delegatorCN) {
            this.identityPopupDane4CDNDelegatorLabel.textContent = "Website : " + delegation.delegatorCN;
        }
        if (delegation.delegateeCN) {
            this.identityPopupDane4CDNDelegateeLabel.textContent = "CDN : " + delegation.delegateeCN;
        }
    },

    onCertInfoClick : function(event) {
        dane4cdn.Extension.logMsg("cert info button clicked");
        if (!this.cert) return;

        const nsICertificateDialogs = Components.interfaces.nsICertificateDialogs;
        const nsCertificateDialogs = "@mozilla.org/nsCertificateDialogs;1";

        var cd = Components.classes[nsCertificateDialogs].getService(nsICertificateDialogs);
        cd.viewCert(window, cert);
    },

  /**
   * Update the UI to reflect the specified state, which should be one of the
   * STATE_* constants.
   */
    setState : function(uri, newState) {
        dane4cdn.Extension.logMsg("Changing state to: "+newState + "("+ ((uri!=null)?uri.host:"null") +")");

        if (newState == this.STATE_ERROR) {
            this.cert = null;
            this.identityIconLabel.setAttribute("value", "");
            this.identityIconCountryLabel.setAttribute("value", "");
            this.identityPopupDane4CDNDelegatorLabel.textContent = "";
            this.identityPopupDane4CDNDelegateeLabel.textContent = "";
        }
        
        //stop updating if hostname changed during resolving process (tab has been switched)
       // if(uri != null && uri.spec != gBrowser.currentURI.spec) {
        if(uri != null && uri.spec != gBrowser.currentURI.spec) {
            dane4cdn.Extension.logMsg("Ignoring setState because current browser tab is different"+gBrowser.currentURI.host);
            return;
        }
    
        this.identityPopupDaneIcon.className = newState;
        this._state = newState;
        this._uri = uri;
        this.setMessages(newState);

        
        //disable the switch https button
        // this.enableSwitchHttps(uri, false);
        
        gIdentityHandler.hideIdentityPopup();
    },

  /**
   * Set up the supplemental and tooltip messages for the identity popup,
   * based on the specified state
   *
   * @param newMode The newly set security state. Should be one of the STATE_* constants.
   */
    setMessages: function(state) {
        this.identityPopupDane4CDNLabel.textContent = this.strings.getString("dane4cdn."+state);
    }

  /*
   * Handles the button to switch current page to https
   */
    /*
    switchHttps: function() {
        dane4cdn.Extension.logMsg("Locationbar-btn: switching to https");
        window.gBrowser.loadURI(this._uri.spec.replace('http','https'));
    },
  
  
  Enables the switch to https button in location bar
  
    enableSwitchHttps: function(uri, enable) {
        if(uri != null &&  uri != gBrowser.currentURI) {
          return; //tab is changed
        }
        this.switchHttpsBox.className = enable ? "" : "disabled";
    },
 */ 
};
