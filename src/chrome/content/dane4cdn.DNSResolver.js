dane4cdn.DomainRecord = function() {
    this.domain = null;
    //   this.addresses = new Array();
    this.nxdomain = null;
    this.secure = null;
    this.bogus = null;
    this.why_bogus = "";
    this.ttl = 60;
    this.exp_ttl = null;
    this.tlsa = new Array();

    this.setNxdomain = function(nxdomain) {
        if (this.nxdomain == null) {
            this.nxdomain = nxdomain;
        } 
        else {
            this.nxdomain = (this.nxdomain && nxdomain);
        }
    };

    this.setSecure = function(secure) {
        if(this.secure == null) {
            this.secure = secure;
        } else {
            this.secure = (this.secure && secure);
        }
    };

    this.setBogus = function(bogus) {
        if(this.bogus == null) {
            this.bogus = bogus;
        } else {
            this.bogus = (this.bogus || bogus);
        }
    };

    this.setWhy_bogus = function(why_bogus) {
        this.why_bogus += why_bogus + " ";
    }
}

/* Do a validated DNS lookup using Libunbound */
dane4cdn.DNSResolver = {
    //RR types
    RRTYPE_A: 1,
    RRTYPE_AAAA: 28,
    RRTYPE_TLSA: 52, //  TLSA assigned

    //Returns a domain record containing addresses, and txt records
    getDomainRecord: function(domain, resolvipv4, resolvipv6) {
        var domainRecord = this._doValidatedDomainLookup(domain, resolvipv4, resolvipv6);
        var tlsa = this._doValidatedCertLookup(domain);

        domainRecord.tlsa = tlsa.tlsa;
        domainRecord.setSecure(tlsa.secure);
        domainRecord.setBogus(tlsa.bogus);
        domainRecord.setWhy_bogus(tlsa.why_bogus);

        return domainRecord;
    },

    getCertRecord: function(domain) {
        return this._doValidatedCertLookup(domain);
    },

    _doValidatedCertLookup: function(domain) {
        dane4cdn.Extension.logMsg("Starting validated cert lookup (TLSA) using libunbound");

        var domainRecord = new dane4cdn.DomainRecord();
        domainRecord.domain = domain;

        var res = this._executeLibunbound("_443._tcp."+domain, this.RRTYPE_TLSA);
//        dane4cdn.Extension.logMsg("TLSA have data status is:" + res.havedata );
        dane4cdn.Extension.logMsg("TLSA secure status is:" + res.secure );

        for(var i=0 in res.rdata) {
            /*
             * Usage field
             * Value        Short description                         Ref.
             * -------------------------------------------------------------
             * 0            CA constraint                            [This]
             * 1            Service constraint
             * 2            Trust anchor assertion
             * 3            Domain issued (end) certificate:w
             * 4-254        Unassigned
             */
            var usage = parseInt(res.rdata[i].substring(0,2));

            /*
               Selector field
               0 -- Full certificate
               1 -- SubjectPublicKeyInfo
               */
            var selector = parseInt(res.rdata[i].substring(2,4));

            /*
             * Matching type field
             * Value        Short description       Ref.
             * -----------------------------------------------------
             * 0            Full cert            [This]
             * 1            SHA-256              NIST FIPS 180-2
             * 2            SHA-512              NIST FIPS 180-2
             * 3-254        Unassigned
             */
            var matchingType = parseInt(res.rdata[i].substring(4,6));

            var certAssociation = res.rdata[i].substring(6);

            dane4cdn.Extension.logMsg("Found certificate: Usage:" + usage + ", Selector: " + selector + ", matchingType: " + matchingType + " associated: " + certAssociation);
            domainRecord.tlsa.push(new Array(usage,selector,matchingType,certAssociation.toUpperCase()));
        }
        domainRecord.setNxdomain(res.nxdomain != 0);
        domainRecord.setSecure(res.secure != 0);
        domainRecord.setBogus(res.bogus != 0);
        domainRecord.setWhy_bogus(res.why_bogus);

        return domainRecord;
    },

    _executeLibunbound : function(domain, rrtype) {
        dane4cdn.Extension.logMsg("execute libunbound for " + domain + " rrtype: " + rrtype); 
        var result = new dane4cdn.Libunbound.ub_result_ptr();

        var retval = dane4cdn.Libunbound.ub_resolve(dane4cdn.Libunbound.ctx, domain,
                rrtype, 
                1, // CLASS IN (internet)
                result.address());

        var rdata = this.parseRdata(result.contents.len, result.contents.data,rrtype);
        dane4cdn.Extension.logMsg("TLSA record lookup res.havedata state is:" + result.contents.havedata.toString());
        dane4cdn.Extension.logMsg("TLSA record lookup res.secure state is:" + result.contents.secure.toString());

        return {rdata: rdata,
            nxdomain: result.contents.nxdomain.toString(),
            secure: result.contents.secure.toString(),
            bogus: result.contents.bogus.toString(),
            why_bogus: result.contents.why_bogus.isNull() ? "" : result.contents.why_bogus.readString()
        };
    },

    //parse rdata array from result set
    parseRdata : function(len, data, rrtype) {
        //len contains length of each item in data.
        //Iterate untill length = 0, which is the last item.
        //FIXME: find a nicer way for totalItems, currently limited with hardcoded max=10
        var lengthArray = ctypes.cast(len, ctypes.int.array(10).ptr);
        var totalLines = 0;
        var lengths = new Array();
        for(var i=0; i<10; i++) {
            //stop at 0 zero length
            if(lengthArray.contents[i].toString() == 0) {
                break;
            }
            //raise total items
            totalLines++;
            lengths.push(parseInt(lengthArray.contents[i].toString()));
        }

        var results = new Array();
        dane4cdn.Extension.logMsg("received RRTYPE: " + rrtype);
        switch (rrtype) {
            case this.RRTYPE_A:
                dane4cdn.Extension.logMsg("received RRTYPE_A");
                //cast to 4 uint8 per rdata line
                var rdata = ctypes.cast(data, ctypes.uint8_t.array(4*totalLines).ptr.ptr);
                for (var i=0; i<4*totalLines; i+=4) {
                    //concatenate and add to results 
                    var ip = rdata.contents.contents[i].toString()
                        +"."+rdata.contents.contents[i+1].toString()
                        +"."+rdata.contents.contents[i+2].toString()
                        +"."+rdata.contents.contents[i+3].toString();
                    results.push(ip);
                }
                break;

            case this.RRTYPE_AAAA:
                dane4cdn.Extension.logMsg("received RRTYPE_AAAA");
                //cast to 16 uint8 per rdata line
                var rdata = ctypes.cast(data, ctypes.uint8_t.array(16*totalLines).ptr.ptr);
                for (var i=0; i<16*totalLines; i+=16) {
                    //iterate over 16 uint8 and convert to char code
                    var tmp = new String();
                    for(var j=0; j<16; j++) {
                        //inet_ntop('\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\1')
                        //octal representation of characters:
                        //parseInt(rdata.contents.contents[i+j].toString(),10).toString(8)
                        tmp += String.fromCharCode(rdata.contents.contents[i+j].toString());
                    }
                    //add ASCII representation to results
                    results.push(this.inet6_ntop(tmp));
                }
                break;

            case this.RRTYPE_TLSA:
                dane4cdn.Extension.logMsg("received RRTYPE_TLSA");
                var rdata = ctypes.cast(data, ctypes.char.ptr.array(totalLines).ptr);
                dane4cdn.Extension.logMsg("total lines: "+totalLines);
                //iterate all lines
                for(var i=0; i<totalLines;i++) {
                    //convert line to array of characters
                    //parsing the complete string fails due to ending null character
                    dane4cdn.Extension.logMsg("Length:"+lengths[i]);
                    var tmp = new String();
                    var line = ctypes.cast(rdata.contents[i], ctypes.uint8_t.array(lengths[i]).ptr);
                    var hex;
                    //skip the first strange character
                    for(var j=0; j<lengths[i];j++) {
                        hex = dane4cdn.CertTools.charcodeToHexString(line.contents[j]);
                        //hex = line.contents[j].toString(16);
                        //if(hex < 16) { hex = "0" + hex; } // DONT LOOK AT ME

                        tmp += hex;
                    }
                    results.push(tmp);
                }        
                break;
        }

        dane4cdn.Extension.logMsg("RData parsed: "+results);

        return results;
    },

    //Converts a packed inet address to a human readable IP address string
    //Source: http://phpjs.org/functions/inet_ntop:882
    //original by: Theriault
    inet6_ntop : function(a) {
        var i = 0, m = '', c = [];
        a += '';
        if (a.length === 16) { // IPv6 length
            for (i = 0; i < 16; i++) {
                c.push(((a.charCodeAt(i++) << 8) + a.charCodeAt(i)).toString(16));
            }
            return c.join(':').replace(/((^|:)0(?=:|$))+:?/g, function (t) {
                m = (t.length > m.length) ? t : m;
                return t;
            }).replace(m || ' ', '::');
        } else { // Invalid length
            return false;
        }
    }
}
