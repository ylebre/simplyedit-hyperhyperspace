var HHS = (function (exports) {
    'use strict';

    var _a$1;
    let getRandomValues; // = require('get-random-values');
    if (((_a$1 = window === null || window === void 0 ? void 0 : window.crypto) === null || _a$1 === void 0 ? void 0 : _a$1.getRandomValues) !== undefined) {
        getRandomValues = window.crypto.getRandomValues;
    }
    else {
        getRandomValues = require("get-random-values");
    }
    class BrowserRNG {
        randomHexString(bits) {
            if (bits % 4 !== 0) {
                throw new Error('Hex strings must have a size in bits that is a multiple of 4');
            }
            let length = bits / 4;
            const step = 2;
            let result = '';
            while (length >= step) {
                result = result + this.randomHex8bitsWord();
                length = length - step;
            }
            result = result + this.randomHex8bitsWord().substring(2 - length, 2);
            return result.toUpperCase();
        }
        randomHex8bitsWord() {
            var _a;
            let result = (((((_a = window === null || window === void 0 ? void 0 : window.crypto) === null || _a === void 0 ? void 0 : _a.getRandomValues) !== undefined) ? window.crypto.getRandomValues(new Uint8Array(1)) : (getRandomValues(new Uint8Array(1))))[0].toString(16));
            return result.padStart(2, '0');
        }
    }

    var commonjsGlobal = typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

    var hashes = {exports: {}};

    /**
     * jshashes - https://github.com/h2non/jshashes
     * Released under the "New BSD" license
     *
     * Algorithms specification:
     *
     * MD5 - http://www.ietf.org/rfc/rfc1321.txt
     * RIPEMD-160 - http://homes.esat.kuleuven.be/~bosselae/ripemd160.html
     * SHA1   - http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
     * SHA256 - http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
     * SHA512 - http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
     * HMAC - http://www.ietf.org/rfc/rfc2104.txt
     */

    (function (module, exports) {
    (function() {
      var Hashes;

      function utf8Encode(str) {
        var x, y, output = '',
          i = -1,
          l;

        if (str && str.length) {
          l = str.length;
          while ((i += 1) < l) {
            /* Decode utf-16 surrogate pairs */
            x = str.charCodeAt(i);
            y = i + 1 < l ? str.charCodeAt(i + 1) : 0;
            if (0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF) {
              x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
              i += 1;
            }
            /* Encode output as utf-8 */
            if (x <= 0x7F) {
              output += String.fromCharCode(x);
            } else if (x <= 0x7FF) {
              output += String.fromCharCode(0xC0 | ((x >>> 6) & 0x1F),
                0x80 | (x & 0x3F));
            } else if (x <= 0xFFFF) {
              output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                0x80 | ((x >>> 6) & 0x3F),
                0x80 | (x & 0x3F));
            } else if (x <= 0x1FFFFF) {
              output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                0x80 | ((x >>> 12) & 0x3F),
                0x80 | ((x >>> 6) & 0x3F),
                0x80 | (x & 0x3F));
            }
          }
        }
        return output;
      }

      function utf8Decode(str) {
        var i, ac, c1, c2, c3, arr = [],
          l;
        i = ac = c1 = c2 = c3 = 0;

        if (str && str.length) {
          l = str.length;
          str += '';

          while (i < l) {
            c1 = str.charCodeAt(i);
            ac += 1;
            if (c1 < 128) {
              arr[ac] = String.fromCharCode(c1);
              i += 1;
            } else if (c1 > 191 && c1 < 224) {
              c2 = str.charCodeAt(i + 1);
              arr[ac] = String.fromCharCode(((c1 & 31) << 6) | (c2 & 63));
              i += 2;
            } else {
              c2 = str.charCodeAt(i + 1);
              c3 = str.charCodeAt(i + 2);
              arr[ac] = String.fromCharCode(((c1 & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
              i += 3;
            }
          }
        }
        return arr.join('');
      }

      /**
       * Add integers, wrapping at 2^32. This uses 16-bit operations internally
       * to work around bugs in some JS interpreters.
       */

      function safe_add(x, y) {
        var lsw = (x & 0xFFFF) + (y & 0xFFFF),
          msw = (x >> 16) + (y >> 16) + (lsw >> 16);
        return (msw << 16) | (lsw & 0xFFFF);
      }

      /**
       * Bitwise rotate a 32-bit number to the left.
       */

      function bit_rol(num, cnt) {
        return (num << cnt) | (num >>> (32 - cnt));
      }

      /**
       * Convert a raw string to a hex string
       */

      function rstr2hex(input, hexcase) {
        var hex_tab = hexcase ? '0123456789ABCDEF' : '0123456789abcdef',
          output = '',
          x, i = 0,
          l = input.length;
        for (; i < l; i += 1) {
          x = input.charCodeAt(i);
          output += hex_tab.charAt((x >>> 4) & 0x0F) + hex_tab.charAt(x & 0x0F);
        }
        return output;
      }

      /**
       * Convert an array of big-endian words to a string
       */

      function binb2rstr(input) {
        var i, l = input.length * 32,
          output = '';
        for (i = 0; i < l; i += 8) {
          output += String.fromCharCode((input[i >> 5] >>> (24 - i % 32)) & 0xFF);
        }
        return output;
      }

      /**
       * Convert an array of little-endian words to a string
       */

      function binl2rstr(input) {
        var i, l = input.length * 32,
          output = '';
        for (i = 0; i < l; i += 8) {
          output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);
        }
        return output;
      }

      /**
       * Convert a raw string to an array of little-endian words
       * Characters >255 have their high-byte silently ignored.
       */

      function rstr2binl(input) {
        var i, l = input.length * 8,
          output = Array(input.length >> 2),
          lo = output.length;
        for (i = 0; i < lo; i += 1) {
          output[i] = 0;
        }
        for (i = 0; i < l; i += 8) {
          output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (i % 32);
        }
        return output;
      }

      /**
       * Convert a raw string to an array of big-endian words
       * Characters >255 have their high-byte silently ignored.
       */

      function rstr2binb(input) {
        var i, l = input.length * 8,
          output = Array(input.length >> 2),
          lo = output.length;
        for (i = 0; i < lo; i += 1) {
          output[i] = 0;
        }
        for (i = 0; i < l; i += 8) {
          output[i >> 5] |= (input.charCodeAt(i / 8) & 0xFF) << (24 - i % 32);
        }
        return output;
      }

      /**
       * Convert a raw string to an arbitrary string encoding
       */

      function rstr2any(input, encoding) {
        var divisor = encoding.length,
          remainders = Array(),
          i, q, x, ld, quotient, dividend, output, full_length;

        /* Convert to an array of 16-bit big-endian values, forming the dividend */
        dividend = Array(Math.ceil(input.length / 2));
        ld = dividend.length;
        for (i = 0; i < ld; i += 1) {
          dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
        }

        /**
         * Repeatedly perform a long division. The binary array forms the dividend,
         * the length of the encoding is the divisor. Once computed, the quotient
         * forms the dividend for the next step. We stop when the dividend is zerHashes.
         * All remainders are stored for later use.
         */
        while (dividend.length > 0) {
          quotient = Array();
          x = 0;
          for (i = 0; i < dividend.length; i += 1) {
            x = (x << 16) + dividend[i];
            q = Math.floor(x / divisor);
            x -= q * divisor;
            if (quotient.length > 0 || q > 0) {
              quotient[quotient.length] = q;
            }
          }
          remainders[remainders.length] = x;
          dividend = quotient;
        }

        /* Convert the remainders to the output string */
        output = '';
        for (i = remainders.length - 1; i >= 0; i--) {
          output += encoding.charAt(remainders[i]);
        }

        /* Append leading zero equivalents */
        full_length = Math.ceil(input.length * 8 / (Math.log(encoding.length) / Math.log(2)));
        for (i = output.length; i < full_length; i += 1) {
          output = encoding[0] + output;
        }
        return output;
      }

      /**
       * Convert a raw string to a base-64 string
       */

      function rstr2b64(input, b64pad) {
        var tab = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
          output = '',
          len = input.length,
          i, j, triplet;
        b64pad = b64pad || '=';
        for (i = 0; i < len; i += 3) {
          triplet = (input.charCodeAt(i) << 16) | (i + 1 < len ? input.charCodeAt(i + 1) << 8 : 0) | (i + 2 < len ? input.charCodeAt(i + 2) : 0);
          for (j = 0; j < 4; j += 1) {
            if (i * 8 + j * 6 > input.length * 8) {
              output += b64pad;
            } else {
              output += tab.charAt((triplet >>> 6 * (3 - j)) & 0x3F);
            }
          }
        }
        return output;
      }

      Hashes = {
        /**
         * @property {String} version
         * @readonly
         */
        VERSION: '1.0.6',
        /**
         * @member Hashes
         * @class Base64
         * @constructor
         */
        Base64: function() {
          // private properties
          var tab = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
            pad = '=', // default pad according with the RFC standard
            utf8 = true; // by default enable UTF-8 support encoding

          // public method for encoding
          this.encode = function(input) {
            var i, j, triplet,
              output = '',
              len = input.length;

            pad = pad || '=';
            input = (utf8) ? utf8Encode(input) : input;

            for (i = 0; i < len; i += 3) {
              triplet = (input.charCodeAt(i) << 16) | (i + 1 < len ? input.charCodeAt(i + 1) << 8 : 0) | (i + 2 < len ? input.charCodeAt(i + 2) : 0);
              for (j = 0; j < 4; j += 1) {
                if (i * 8 + j * 6 > len * 8) {
                  output += pad;
                } else {
                  output += tab.charAt((triplet >>> 6 * (3 - j)) & 0x3F);
                }
              }
            }
            return output;
          };

          // public method for decoding
          this.decode = function(input) {
            // var b64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
            var i, o1, o2, o3, h1, h2, h3, h4, bits, ac,
              dec = '',
              arr = [];
            if (!input) {
              return input;
            }

            i = ac = 0;
            input = input.replace(new RegExp('\\' + pad, 'gi'), ''); // use '='
            //input += '';

            do { // unpack four hexets into three octets using index points in b64
              h1 = tab.indexOf(input.charAt(i += 1));
              h2 = tab.indexOf(input.charAt(i += 1));
              h3 = tab.indexOf(input.charAt(i += 1));
              h4 = tab.indexOf(input.charAt(i += 1));

              bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;

              o1 = bits >> 16 & 0xff;
              o2 = bits >> 8 & 0xff;
              o3 = bits & 0xff;
              ac += 1;

              if (h3 === 64) {
                arr[ac] = String.fromCharCode(o1);
              } else if (h4 === 64) {
                arr[ac] = String.fromCharCode(o1, o2);
              } else {
                arr[ac] = String.fromCharCode(o1, o2, o3);
              }
            } while (i < input.length);

            dec = arr.join('');
            dec = (utf8) ? utf8Decode(dec) : dec;

            return dec;
          };

          // set custom pad string
          this.setPad = function(str) {
            pad = str || pad;
            return this;
          };
          // set custom tab string characters
          this.setTab = function(str) {
            tab = str || tab;
            return this;
          };
          this.setUTF8 = function(bool) {
            if (typeof bool === 'boolean') {
              utf8 = bool;
            }
            return this;
          };
        },

        /**
         * CRC-32 calculation
         * @member Hashes
         * @method CRC32
         * @static
         * @param {String} str Input String
         * @return {String}
         */
        CRC32: function(str) {
          var crc = 0,
            x = 0,
            y = 0,
            table, i, iTop;
          str = utf8Encode(str);

          table = [
            '00000000 77073096 EE0E612C 990951BA 076DC419 706AF48F E963A535 9E6495A3 0EDB8832 ',
            '79DCB8A4 E0D5E91E 97D2D988 09B64C2B 7EB17CBD E7B82D07 90BF1D91 1DB71064 6AB020F2 F3B97148 ',
            '84BE41DE 1ADAD47D 6DDDE4EB F4D4B551 83D385C7 136C9856 646BA8C0 FD62F97A 8A65C9EC 14015C4F ',
            '63066CD9 FA0F3D63 8D080DF5 3B6E20C8 4C69105E D56041E4 A2677172 3C03E4D1 4B04D447 D20D85FD ',
            'A50AB56B 35B5A8FA 42B2986C DBBBC9D6 ACBCF940 32D86CE3 45DF5C75 DCD60DCF ABD13D59 26D930AC ',
            '51DE003A C8D75180 BFD06116 21B4F4B5 56B3C423 CFBA9599 B8BDA50F 2802B89E 5F058808 C60CD9B2 ',
            'B10BE924 2F6F7C87 58684C11 C1611DAB B6662D3D 76DC4190 01DB7106 98D220BC EFD5102A 71B18589 ',
            '06B6B51F 9FBFE4A5 E8B8D433 7807C9A2 0F00F934 9609A88E E10E9818 7F6A0DBB 086D3D2D 91646C97 ',
            'E6635C01 6B6B51F4 1C6C6162 856530D8 F262004E 6C0695ED 1B01A57B 8208F4C1 F50FC457 65B0D9C6 ',
            '12B7E950 8BBEB8EA FCB9887C 62DD1DDF 15DA2D49 8CD37CF3 FBD44C65 4DB26158 3AB551CE A3BC0074 ',
            'D4BB30E2 4ADFA541 3DD895D7 A4D1C46D D3D6F4FB 4369E96A 346ED9FC AD678846 DA60B8D0 44042D73 ',
            '33031DE5 AA0A4C5F DD0D7CC9 5005713C 270241AA BE0B1010 C90C2086 5768B525 206F85B3 B966D409 ',
            'CE61E49F 5EDEF90E 29D9C998 B0D09822 C7D7A8B4 59B33D17 2EB40D81 B7BD5C3B C0BA6CAD EDB88320 ',
            '9ABFB3B6 03B6E20C 74B1D29A EAD54739 9DD277AF 04DB2615 73DC1683 E3630B12 94643B84 0D6D6A3E ',
            '7A6A5AA8 E40ECF0B 9309FF9D 0A00AE27 7D079EB1 F00F9344 8708A3D2 1E01F268 6906C2FE F762575D ',
            '806567CB 196C3671 6E6B06E7 FED41B76 89D32BE0 10DA7A5A 67DD4ACC F9B9DF6F 8EBEEFF9 17B7BE43 ',
            '60B08ED5 D6D6A3E8 A1D1937E 38D8C2C4 4FDFF252 D1BB67F1 A6BC5767 3FB506DD 48B2364B D80D2BDA ',
            'AF0A1B4C 36034AF6 41047A60 DF60EFC3 A867DF55 316E8EEF 4669BE79 CB61B38C BC66831A 256FD2A0 ',
            '5268E236 CC0C7795 BB0B4703 220216B9 5505262F C5BA3BBE B2BD0B28 2BB45A92 5CB36A04 C2D7FFA7 ',
            'B5D0CF31 2CD99E8B 5BDEAE1D 9B64C2B0 EC63F226 756AA39C 026D930A 9C0906A9 EB0E363F 72076785 ',
            '05005713 95BF4A82 E2B87A14 7BB12BAE 0CB61B38 92D28E9B E5D5BE0D 7CDCEFB7 0BDBDF21 86D3D2D4 ',
            'F1D4E242 68DDB3F8 1FDA836E 81BE16CD F6B9265B 6FB077E1 18B74777 88085AE6 FF0F6A70 66063BCA ',
            '11010B5C 8F659EFF F862AE69 616BFFD3 166CCF45 A00AE278 D70DD2EE 4E048354 3903B3C2 A7672661 ',
            'D06016F7 4969474D 3E6E77DB AED16A4A D9D65ADC 40DF0B66 37D83BF0 A9BCAE53 DEBB9EC5 47B2CF7F ',
            '30B5FFE9 BDBDF21C CABAC28A 53B39330 24B4A3A6 BAD03605 CDD70693 54DE5729 23D967BF B3667A2E ',
            'C4614AB8 5D681B02 2A6F2B94 B40BBE37 C30C8EA1 5A05DF1B 2D02EF8D'
          ].join('');

          crc = crc ^ (-1);
          for (i = 0, iTop = str.length; i < iTop; i += 1) {
            y = (crc ^ str.charCodeAt(i)) & 0xFF;
            x = '0x' + table.substr(y * 9, 8);
            crc = (crc >>> 8) ^ x;
          }
          // always return a positive number (that's what >>> 0 does)
          return (crc ^ (-1)) >>> 0;
        },
        /**
         * @member Hashes
         * @class MD5
         * @constructor
         * @param {Object} [config]
         *
         * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
         * Digest Algorithm, as defined in RFC 1321.
         * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
         * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
         * See <http://pajhome.org.uk/crypt/md5> for more infHashes.
         */
        MD5: function(options) {
          /**
           * Private config properties. You may need to tweak these to be compatible with
           * the server-side, but the defaults work in most cases.
           * See {@link Hashes.MD5#method-setUpperCase} and {@link Hashes.SHA1#method-setUpperCase}
           */
          var hexcase = (options && typeof options.uppercase === 'boolean') ? options.uppercase : false, // hexadecimal output case format. false - lowercase; true - uppercase
            b64pad = (options && typeof options.pad === 'string') ? options.pad : '=', // base-64 pad character. Defaults to '=' for strict RFC compliance
            utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true; // enable/disable utf8 encoding

          // privileged (public) methods
          this.hex = function(s) {
            return rstr2hex(rstr(s), hexcase);
          };
          this.b64 = function(s) {
            return rstr2b64(rstr(s), b64pad);
          };
          this.any = function(s, e) {
            return rstr2any(rstr(s), e);
          };
          this.raw = function(s) {
            return rstr(s);
          };
          this.hex_hmac = function(k, d) {
            return rstr2hex(rstr_hmac(k, d), hexcase);
          };
          this.b64_hmac = function(k, d) {
            return rstr2b64(rstr_hmac(k, d), b64pad);
          };
          this.any_hmac = function(k, d, e) {
            return rstr2any(rstr_hmac(k, d), e);
          };
          /**
           * Perform a simple self-test to see if the VM is working
           * @return {String} Hexadecimal hash sample
           */
          this.vm_test = function() {
            return hex('abc').toLowerCase() === '900150983cd24fb0d6963f7d28e17f72';
          };
          /**
           * Enable/disable uppercase hexadecimal returned string
           * @param {Boolean}
           * @return {Object} this
           */
          this.setUpperCase = function(a) {
            if (typeof a === 'boolean') {
              hexcase = a;
            }
            return this;
          };
          /**
           * Defines a base64 pad string
           * @param {String} Pad
           * @return {Object} this
           */
          this.setPad = function(a) {
            b64pad = a || b64pad;
            return this;
          };
          /**
           * Defines a base64 pad string
           * @param {Boolean}
           * @return {Object} [this]
           */
          this.setUTF8 = function(a) {
            if (typeof a === 'boolean') {
              utf8 = a;
            }
            return this;
          };

          // private methods

          /**
           * Calculate the MD5 of a raw string
           */

          function rstr(s) {
            s = (utf8) ? utf8Encode(s) : s;
            return binl2rstr(binl(rstr2binl(s), s.length * 8));
          }

          /**
           * Calculate the HMAC-MD5, of a key and some data (raw strings)
           */

          function rstr_hmac(key, data) {
            var bkey, ipad, opad, hash, i;

            key = (utf8) ? utf8Encode(key) : key;
            data = (utf8) ? utf8Encode(data) : data;
            bkey = rstr2binl(key);
            if (bkey.length > 16) {
              bkey = binl(bkey, key.length * 8);
            }

            ipad = Array(16), opad = Array(16);
            for (i = 0; i < 16; i += 1) {
              ipad[i] = bkey[i] ^ 0x36363636;
              opad[i] = bkey[i] ^ 0x5C5C5C5C;
            }
            hash = binl(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
            return binl2rstr(binl(opad.concat(hash), 512 + 128));
          }

          /**
           * Calculate the MD5 of an array of little-endian words, and a bit length.
           */

          function binl(x, len) {
            var i, olda, oldb, oldc, oldd,
              a = 1732584193,
              b = -271733879,
              c = -1732584194,
              d = 271733878;

            /* append padding */
            x[len >> 5] |= 0x80 << ((len) % 32);
            x[(((len + 64) >>> 9) << 4) + 14] = len;

            for (i = 0; i < x.length; i += 16) {
              olda = a;
              oldb = b;
              oldc = c;
              oldd = d;

              a = md5_ff(a, b, c, d, x[i + 0], 7, -680876936);
              d = md5_ff(d, a, b, c, x[i + 1], 12, -389564586);
              c = md5_ff(c, d, a, b, x[i + 2], 17, 606105819);
              b = md5_ff(b, c, d, a, x[i + 3], 22, -1044525330);
              a = md5_ff(a, b, c, d, x[i + 4], 7, -176418897);
              d = md5_ff(d, a, b, c, x[i + 5], 12, 1200080426);
              c = md5_ff(c, d, a, b, x[i + 6], 17, -1473231341);
              b = md5_ff(b, c, d, a, x[i + 7], 22, -45705983);
              a = md5_ff(a, b, c, d, x[i + 8], 7, 1770035416);
              d = md5_ff(d, a, b, c, x[i + 9], 12, -1958414417);
              c = md5_ff(c, d, a, b, x[i + 10], 17, -42063);
              b = md5_ff(b, c, d, a, x[i + 11], 22, -1990404162);
              a = md5_ff(a, b, c, d, x[i + 12], 7, 1804603682);
              d = md5_ff(d, a, b, c, x[i + 13], 12, -40341101);
              c = md5_ff(c, d, a, b, x[i + 14], 17, -1502002290);
              b = md5_ff(b, c, d, a, x[i + 15], 22, 1236535329);

              a = md5_gg(a, b, c, d, x[i + 1], 5, -165796510);
              d = md5_gg(d, a, b, c, x[i + 6], 9, -1069501632);
              c = md5_gg(c, d, a, b, x[i + 11], 14, 643717713);
              b = md5_gg(b, c, d, a, x[i + 0], 20, -373897302);
              a = md5_gg(a, b, c, d, x[i + 5], 5, -701558691);
              d = md5_gg(d, a, b, c, x[i + 10], 9, 38016083);
              c = md5_gg(c, d, a, b, x[i + 15], 14, -660478335);
              b = md5_gg(b, c, d, a, x[i + 4], 20, -405537848);
              a = md5_gg(a, b, c, d, x[i + 9], 5, 568446438);
              d = md5_gg(d, a, b, c, x[i + 14], 9, -1019803690);
              c = md5_gg(c, d, a, b, x[i + 3], 14, -187363961);
              b = md5_gg(b, c, d, a, x[i + 8], 20, 1163531501);
              a = md5_gg(a, b, c, d, x[i + 13], 5, -1444681467);
              d = md5_gg(d, a, b, c, x[i + 2], 9, -51403784);
              c = md5_gg(c, d, a, b, x[i + 7], 14, 1735328473);
              b = md5_gg(b, c, d, a, x[i + 12], 20, -1926607734);

              a = md5_hh(a, b, c, d, x[i + 5], 4, -378558);
              d = md5_hh(d, a, b, c, x[i + 8], 11, -2022574463);
              c = md5_hh(c, d, a, b, x[i + 11], 16, 1839030562);
              b = md5_hh(b, c, d, a, x[i + 14], 23, -35309556);
              a = md5_hh(a, b, c, d, x[i + 1], 4, -1530992060);
              d = md5_hh(d, a, b, c, x[i + 4], 11, 1272893353);
              c = md5_hh(c, d, a, b, x[i + 7], 16, -155497632);
              b = md5_hh(b, c, d, a, x[i + 10], 23, -1094730640);
              a = md5_hh(a, b, c, d, x[i + 13], 4, 681279174);
              d = md5_hh(d, a, b, c, x[i + 0], 11, -358537222);
              c = md5_hh(c, d, a, b, x[i + 3], 16, -722521979);
              b = md5_hh(b, c, d, a, x[i + 6], 23, 76029189);
              a = md5_hh(a, b, c, d, x[i + 9], 4, -640364487);
              d = md5_hh(d, a, b, c, x[i + 12], 11, -421815835);
              c = md5_hh(c, d, a, b, x[i + 15], 16, 530742520);
              b = md5_hh(b, c, d, a, x[i + 2], 23, -995338651);

              a = md5_ii(a, b, c, d, x[i + 0], 6, -198630844);
              d = md5_ii(d, a, b, c, x[i + 7], 10, 1126891415);
              c = md5_ii(c, d, a, b, x[i + 14], 15, -1416354905);
              b = md5_ii(b, c, d, a, x[i + 5], 21, -57434055);
              a = md5_ii(a, b, c, d, x[i + 12], 6, 1700485571);
              d = md5_ii(d, a, b, c, x[i + 3], 10, -1894986606);
              c = md5_ii(c, d, a, b, x[i + 10], 15, -1051523);
              b = md5_ii(b, c, d, a, x[i + 1], 21, -2054922799);
              a = md5_ii(a, b, c, d, x[i + 8], 6, 1873313359);
              d = md5_ii(d, a, b, c, x[i + 15], 10, -30611744);
              c = md5_ii(c, d, a, b, x[i + 6], 15, -1560198380);
              b = md5_ii(b, c, d, a, x[i + 13], 21, 1309151649);
              a = md5_ii(a, b, c, d, x[i + 4], 6, -145523070);
              d = md5_ii(d, a, b, c, x[i + 11], 10, -1120210379);
              c = md5_ii(c, d, a, b, x[i + 2], 15, 718787259);
              b = md5_ii(b, c, d, a, x[i + 9], 21, -343485551);

              a = safe_add(a, olda);
              b = safe_add(b, oldb);
              c = safe_add(c, oldc);
              d = safe_add(d, oldd);
            }
            return Array(a, b, c, d);
          }

          /**
           * These functions implement the four basic operations the algorithm uses.
           */

          function md5_cmn(q, a, b, x, s, t) {
            return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s), b);
          }

          function md5_ff(a, b, c, d, x, s, t) {
            return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
          }

          function md5_gg(a, b, c, d, x, s, t) {
            return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
          }

          function md5_hh(a, b, c, d, x, s, t) {
            return md5_cmn(b ^ c ^ d, a, b, x, s, t);
          }

          function md5_ii(a, b, c, d, x, s, t) {
            return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
          }
        },
        /**
         * @member Hashes
         * @class Hashes.SHA1
         * @param {Object} [config]
         * @constructor
         *
         * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined in FIPS 180-1
         * Version 2.2 Copyright Paul Johnston 2000 - 2009.
         * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
         * See http://pajhome.org.uk/crypt/md5 for details.
         */
        SHA1: function(options) {
          /**
           * Private config properties. You may need to tweak these to be compatible with
           * the server-side, but the defaults work in most cases.
           * See {@link Hashes.MD5#method-setUpperCase} and {@link Hashes.SHA1#method-setUpperCase}
           */
          var hexcase = (options && typeof options.uppercase === 'boolean') ? options.uppercase : false, // hexadecimal output case format. false - lowercase; true - uppercase
            b64pad = (options && typeof options.pad === 'string') ? options.pad : '=', // base-64 pad character. Defaults to '=' for strict RFC compliance
            utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true; // enable/disable utf8 encoding

          // public methods
          this.hex = function(s) {
            return rstr2hex(rstr(s), hexcase);
          };
          this.b64 = function(s) {
            return rstr2b64(rstr(s), b64pad);
          };
          this.any = function(s, e) {
            return rstr2any(rstr(s), e);
          };
          this.raw = function(s) {
            return rstr(s);
          };
          this.hex_hmac = function(k, d) {
            return rstr2hex(rstr_hmac(k, d));
          };
          this.b64_hmac = function(k, d) {
            return rstr2b64(rstr_hmac(k, d), b64pad);
          };
          this.any_hmac = function(k, d, e) {
            return rstr2any(rstr_hmac(k, d), e);
          };
          /**
           * Perform a simple self-test to see if the VM is working
           * @return {String} Hexadecimal hash sample
           * @public
           */
          this.vm_test = function() {
            return hex('abc').toLowerCase() === '900150983cd24fb0d6963f7d28e17f72';
          };
          /**
           * @description Enable/disable uppercase hexadecimal returned string
           * @param {boolean}
           * @return {Object} this
           * @public
           */
          this.setUpperCase = function(a) {
            if (typeof a === 'boolean') {
              hexcase = a;
            }
            return this;
          };
          /**
           * @description Defines a base64 pad string
           * @param {string} Pad
           * @return {Object} this
           * @public
           */
          this.setPad = function(a) {
            b64pad = a || b64pad;
            return this;
          };
          /**
           * @description Defines a base64 pad string
           * @param {boolean}
           * @return {Object} this
           * @public
           */
          this.setUTF8 = function(a) {
            if (typeof a === 'boolean') {
              utf8 = a;
            }
            return this;
          };

          // private methods

          /**
           * Calculate the SHA-512 of a raw string
           */

          function rstr(s) {
            s = (utf8) ? utf8Encode(s) : s;
            return binb2rstr(binb(rstr2binb(s), s.length * 8));
          }

          /**
           * Calculate the HMAC-SHA1 of a key and some data (raw strings)
           */

          function rstr_hmac(key, data) {
            var bkey, ipad, opad, i, hash;
            key = (utf8) ? utf8Encode(key) : key;
            data = (utf8) ? utf8Encode(data) : data;
            bkey = rstr2binb(key);

            if (bkey.length > 16) {
              bkey = binb(bkey, key.length * 8);
            }
            ipad = Array(16), opad = Array(16);
            for (i = 0; i < 16; i += 1) {
              ipad[i] = bkey[i] ^ 0x36363636;
              opad[i] = bkey[i] ^ 0x5C5C5C5C;
            }
            hash = binb(ipad.concat(rstr2binb(data)), 512 + data.length * 8);
            return binb2rstr(binb(opad.concat(hash), 512 + 160));
          }

          /**
           * Calculate the SHA-1 of an array of big-endian words, and a bit length
           */

          function binb(x, len) {
            var i, j, t, olda, oldb, oldc, oldd, olde,
              w = Array(80),
              a = 1732584193,
              b = -271733879,
              c = -1732584194,
              d = 271733878,
              e = -1009589776;

            /* append padding */
            x[len >> 5] |= 0x80 << (24 - len % 32);
            x[((len + 64 >> 9) << 4) + 15] = len;

            for (i = 0; i < x.length; i += 16) {
              olda = a;
              oldb = b;
              oldc = c;
              oldd = d;
              olde = e;

              for (j = 0; j < 80; j += 1) {
                if (j < 16) {
                  w[j] = x[i + j];
                } else {
                  w[j] = bit_rol(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
                }
                t = safe_add(safe_add(bit_rol(a, 5), sha1_ft(j, b, c, d)),
                  safe_add(safe_add(e, w[j]), sha1_kt(j)));
                e = d;
                d = c;
                c = bit_rol(b, 30);
                b = a;
                a = t;
              }

              a = safe_add(a, olda);
              b = safe_add(b, oldb);
              c = safe_add(c, oldc);
              d = safe_add(d, oldd);
              e = safe_add(e, olde);
            }
            return Array(a, b, c, d, e);
          }

          /**
           * Perform the appropriate triplet combination function for the current
           * iteration
           */

          function sha1_ft(t, b, c, d) {
            if (t < 20) {
              return (b & c) | ((~b) & d);
            }
            if (t < 40) {
              return b ^ c ^ d;
            }
            if (t < 60) {
              return (b & c) | (b & d) | (c & d);
            }
            return b ^ c ^ d;
          }

          /**
           * Determine the appropriate additive constant for the current iteration
           */

          function sha1_kt(t) {
            return (t < 20) ? 1518500249 : (t < 40) ? 1859775393 :
              (t < 60) ? -1894007588 : -899497514;
          }
        },
        /**
         * @class Hashes.SHA256
         * @param {config}
         *
         * A JavaScript implementation of the Secure Hash Algorithm, SHA-256, as defined in FIPS 180-2
         * Version 2.2 Copyright Angel Marin, Paul Johnston 2000 - 2009.
         * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
         * See http://pajhome.org.uk/crypt/md5 for details.
         * Also http://anmar.eu.org/projects/jssha2/
         */
        SHA256: function(options) {
          /**
           * Private properties configuration variables. You may need to tweak these to be compatible with
           * the server-side, but the defaults work in most cases.
           * @see this.setUpperCase() method
           * @see this.setPad() method
           */
          (options && typeof options.uppercase === 'boolean') ? options.uppercase : false; // hexadecimal output case format. false - lowercase; true - uppercase  */
            var b64pad = (options && typeof options.pad === 'string') ? options.pad : '=',
            /* base-64 pad character. Default '=' for strict RFC compliance   */
            utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true,
            /* enable/disable utf8 encoding */
            sha256_K;

          /* privileged (public) methods */
          this.hex = function(s) {
            return rstr2hex(rstr(s, utf8));
          };
          this.b64 = function(s) {
            return rstr2b64(rstr(s, utf8), b64pad);
          };
          this.any = function(s, e) {
            return rstr2any(rstr(s, utf8), e);
          };
          this.raw = function(s) {
            return rstr(s, utf8);
          };
          this.hex_hmac = function(k, d) {
            return rstr2hex(rstr_hmac(k, d));
          };
          this.b64_hmac = function(k, d) {
            return rstr2b64(rstr_hmac(k, d), b64pad);
          };
          this.any_hmac = function(k, d, e) {
            return rstr2any(rstr_hmac(k, d), e);
          };
          /**
           * Perform a simple self-test to see if the VM is working
           * @return {String} Hexadecimal hash sample
           * @public
           */
          this.vm_test = function() {
            return hex('abc').toLowerCase() === '900150983cd24fb0d6963f7d28e17f72';
          };
          /**
           * Enable/disable uppercase hexadecimal returned string
           * @param {boolean}
           * @return {Object} this
           * @public
           */
          this.setUpperCase = function(a) {
            return this;
          };
          /**
           * @description Defines a base64 pad string
           * @param {string} Pad
           * @return {Object} this
           * @public
           */
          this.setPad = function(a) {
            b64pad = a || b64pad;
            return this;
          };
          /**
           * Defines a base64 pad string
           * @param {boolean}
           * @return {Object} this
           * @public
           */
          this.setUTF8 = function(a) {
            if (typeof a === 'boolean') {
              utf8 = a;
            }
            return this;
          };

          // private methods

          /**
           * Calculate the SHA-512 of a raw string
           */

          function rstr(s, utf8) {
            s = (utf8) ? utf8Encode(s) : s;
            return binb2rstr(binb(rstr2binb(s), s.length * 8));
          }

          /**
           * Calculate the HMAC-sha256 of a key and some data (raw strings)
           */

          function rstr_hmac(key, data) {
            key = (utf8) ? utf8Encode(key) : key;
            data = (utf8) ? utf8Encode(data) : data;
            var hash, i = 0,
              bkey = rstr2binb(key),
              ipad = Array(16),
              opad = Array(16);

            if (bkey.length > 16) {
              bkey = binb(bkey, key.length * 8);
            }

            for (; i < 16; i += 1) {
              ipad[i] = bkey[i] ^ 0x36363636;
              opad[i] = bkey[i] ^ 0x5C5C5C5C;
            }

            hash = binb(ipad.concat(rstr2binb(data)), 512 + data.length * 8);
            return binb2rstr(binb(opad.concat(hash), 512 + 256));
          }

          /*
           * Main sha256 function, with its support functions
           */

          function sha256_S(X, n) {
            return (X >>> n) | (X << (32 - n));
          }

          function sha256_R(X, n) {
            return (X >>> n);
          }

          function sha256_Ch(x, y, z) {
            return ((x & y) ^ ((~x) & z));
          }

          function sha256_Maj(x, y, z) {
            return ((x & y) ^ (x & z) ^ (y & z));
          }

          function sha256_Sigma0256(x) {
            return (sha256_S(x, 2) ^ sha256_S(x, 13) ^ sha256_S(x, 22));
          }

          function sha256_Sigma1256(x) {
            return (sha256_S(x, 6) ^ sha256_S(x, 11) ^ sha256_S(x, 25));
          }

          function sha256_Gamma0256(x) {
            return (sha256_S(x, 7) ^ sha256_S(x, 18) ^ sha256_R(x, 3));
          }

          function sha256_Gamma1256(x) {
            return (sha256_S(x, 17) ^ sha256_S(x, 19) ^ sha256_R(x, 10));
          }

          sha256_K = [
            1116352408, 1899447441, -1245643825, -373957723, 961987163, 1508970993, -1841331548, -1424204075, -670586216, 310598401, 607225278, 1426881987,
            1925078388, -2132889090, -1680079193, -1046744716, -459576895, -272742522,
            264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, -1740746414, -1473132947, -1341970488, -1084653625, -958395405, -710438585,
            113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291,
            1695183700, 1986661051, -2117940946, -1838011259, -1564481375, -1474664885, -1035236496, -949202525, -778901479, -694614492, -200395387, 275423344,
            430227734, 506948616, 659060556, 883997877, 958139571, 1322822218,
            1537002063, 1747873779, 1955562222, 2024104815, -2067236844, -1933114872, -1866530822, -1538233109, -1090935817, -965641998
          ];

          function binb(m, l) {
            var HASH = [1779033703, -1150833019, 1013904242, -1521486534,
              1359893119, -1694144372, 528734635, 1541459225
            ];
            var W = new Array(64);
            var a, b, c, d, e, f, g, h;
            var i, j, T1, T2;

            /* append padding */
            m[l >> 5] |= 0x80 << (24 - l % 32);
            m[((l + 64 >> 9) << 4) + 15] = l;

            for (i = 0; i < m.length; i += 16) {
              a = HASH[0];
              b = HASH[1];
              c = HASH[2];
              d = HASH[3];
              e = HASH[4];
              f = HASH[5];
              g = HASH[6];
              h = HASH[7];

              for (j = 0; j < 64; j += 1) {
                if (j < 16) {
                  W[j] = m[j + i];
                } else {
                  W[j] = safe_add(safe_add(safe_add(sha256_Gamma1256(W[j - 2]), W[j - 7]),
                    sha256_Gamma0256(W[j - 15])), W[j - 16]);
                }

                T1 = safe_add(safe_add(safe_add(safe_add(h, sha256_Sigma1256(e)), sha256_Ch(e, f, g)),
                  sha256_K[j]), W[j]);
                T2 = safe_add(sha256_Sigma0256(a), sha256_Maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = safe_add(d, T1);
                d = c;
                c = b;
                b = a;
                a = safe_add(T1, T2);
              }

              HASH[0] = safe_add(a, HASH[0]);
              HASH[1] = safe_add(b, HASH[1]);
              HASH[2] = safe_add(c, HASH[2]);
              HASH[3] = safe_add(d, HASH[3]);
              HASH[4] = safe_add(e, HASH[4]);
              HASH[5] = safe_add(f, HASH[5]);
              HASH[6] = safe_add(g, HASH[6]);
              HASH[7] = safe_add(h, HASH[7]);
            }
            return HASH;
          }

        },

        /**
         * @class Hashes.SHA512
         * @param {config}
         *
         * A JavaScript implementation of the Secure Hash Algorithm, SHA-512, as defined in FIPS 180-2
         * Version 2.2 Copyright Anonymous Contributor, Paul Johnston 2000 - 2009.
         * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
         * See http://pajhome.org.uk/crypt/md5 for details.
         */
        SHA512: function(options) {
          /**
           * Private properties configuration variables. You may need to tweak these to be compatible with
           * the server-side, but the defaults work in most cases.
           * @see this.setUpperCase() method
           * @see this.setPad() method
           */
          (options && typeof options.uppercase === 'boolean') ? options.uppercase : false;
            var /* hexadecimal output case format. false - lowercase; true - uppercase  */
            b64pad = (options && typeof options.pad === 'string') ? options.pad : '=',
            /* base-64 pad character. Default '=' for strict RFC compliance   */
            utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true,
            /* enable/disable utf8 encoding */
            sha512_k;

          /* privileged (public) methods */
          this.hex = function(s) {
            return rstr2hex(rstr(s));
          };
          this.b64 = function(s) {
            return rstr2b64(rstr(s), b64pad);
          };
          this.any = function(s, e) {
            return rstr2any(rstr(s), e);
          };
          this.raw = function(s) {
            return rstr(s);
          };
          this.hex_hmac = function(k, d) {
            return rstr2hex(rstr_hmac(k, d));
          };
          this.b64_hmac = function(k, d) {
            return rstr2b64(rstr_hmac(k, d), b64pad);
          };
          this.any_hmac = function(k, d, e) {
            return rstr2any(rstr_hmac(k, d), e);
          };
          /**
           * Perform a simple self-test to see if the VM is working
           * @return {String} Hexadecimal hash sample
           * @public
           */
          this.vm_test = function() {
            return hex('abc').toLowerCase() === '900150983cd24fb0d6963f7d28e17f72';
          };
          /**
           * @description Enable/disable uppercase hexadecimal returned string
           * @param {boolean}
           * @return {Object} this
           * @public
           */
          this.setUpperCase = function(a) {
            return this;
          };
          /**
           * @description Defines a base64 pad string
           * @param {string} Pad
           * @return {Object} this
           * @public
           */
          this.setPad = function(a) {
            b64pad = a || b64pad;
            return this;
          };
          /**
           * @description Defines a base64 pad string
           * @param {boolean}
           * @return {Object} this
           * @public
           */
          this.setUTF8 = function(a) {
            if (typeof a === 'boolean') {
              utf8 = a;
            }
            return this;
          };

          /* private methods */

          /**
           * Calculate the SHA-512 of a raw string
           */

          function rstr(s) {
            s = (utf8) ? utf8Encode(s) : s;
            return binb2rstr(binb(rstr2binb(s), s.length * 8));
          }
          /*
           * Calculate the HMAC-SHA-512 of a key and some data (raw strings)
           */

          function rstr_hmac(key, data) {
            key = (utf8) ? utf8Encode(key) : key;
            data = (utf8) ? utf8Encode(data) : data;

            var hash, i = 0,
              bkey = rstr2binb(key),
              ipad = Array(32),
              opad = Array(32);

            if (bkey.length > 32) {
              bkey = binb(bkey, key.length * 8);
            }

            for (; i < 32; i += 1) {
              ipad[i] = bkey[i] ^ 0x36363636;
              opad[i] = bkey[i] ^ 0x5C5C5C5C;
            }

            hash = binb(ipad.concat(rstr2binb(data)), 1024 + data.length * 8);
            return binb2rstr(binb(opad.concat(hash), 1024 + 512));
          }

          /**
           * Calculate the SHA-512 of an array of big-endian dwords, and a bit length
           */

          function binb(x, len) {
            var j, i, l,
              W = new Array(80),
              hash = new Array(16),
              //Initial hash values
              H = [
                new int64(0x6a09e667, -205731576),
                new int64(-1150833019, -2067093701),
                new int64(0x3c6ef372, -23791573),
                new int64(-1521486534, 0x5f1d36f1),
                new int64(0x510e527f, -1377402159),
                new int64(-1694144372, 0x2b3e6c1f),
                new int64(0x1f83d9ab, -79577749),
                new int64(0x5be0cd19, 0x137e2179)
              ],
              T1 = new int64(0, 0),
              T2 = new int64(0, 0),
              a = new int64(0, 0),
              b = new int64(0, 0),
              c = new int64(0, 0),
              d = new int64(0, 0),
              e = new int64(0, 0),
              f = new int64(0, 0),
              g = new int64(0, 0),
              h = new int64(0, 0),
              //Temporary variables not specified by the document
              s0 = new int64(0, 0),
              s1 = new int64(0, 0),
              Ch = new int64(0, 0),
              Maj = new int64(0, 0),
              r1 = new int64(0, 0),
              r2 = new int64(0, 0),
              r3 = new int64(0, 0);

            if (sha512_k === undefined) {
              //SHA512 constants
              sha512_k = [
                new int64(0x428a2f98, -685199838), new int64(0x71374491, 0x23ef65cd),
                new int64(-1245643825, -330482897), new int64(-373957723, -2121671748),
                new int64(0x3956c25b, -213338824), new int64(0x59f111f1, -1241133031),
                new int64(-1841331548, -1357295717), new int64(-1424204075, -630357736),
                new int64(-670586216, -1560083902), new int64(0x12835b01, 0x45706fbe),
                new int64(0x243185be, 0x4ee4b28c), new int64(0x550c7dc3, -704662302),
                new int64(0x72be5d74, -226784913), new int64(-2132889090, 0x3b1696b1),
                new int64(-1680079193, 0x25c71235), new int64(-1046744716, -815192428),
                new int64(-459576895, -1628353838), new int64(-272742522, 0x384f25e3),
                new int64(0xfc19dc6, -1953704523), new int64(0x240ca1cc, 0x77ac9c65),
                new int64(0x2de92c6f, 0x592b0275), new int64(0x4a7484aa, 0x6ea6e483),
                new int64(0x5cb0a9dc, -1119749164), new int64(0x76f988da, -2096016459),
                new int64(-1740746414, -295247957), new int64(-1473132947, 0x2db43210),
                new int64(-1341970488, -1728372417), new int64(-1084653625, -1091629340),
                new int64(-958395405, 0x3da88fc2), new int64(-710438585, -1828018395),
                new int64(0x6ca6351, -536640913), new int64(0x14292967, 0xa0e6e70),
                new int64(0x27b70a85, 0x46d22ffc), new int64(0x2e1b2138, 0x5c26c926),
                new int64(0x4d2c6dfc, 0x5ac42aed), new int64(0x53380d13, -1651133473),
                new int64(0x650a7354, -1951439906), new int64(0x766a0abb, 0x3c77b2a8),
                new int64(-2117940946, 0x47edaee6), new int64(-1838011259, 0x1482353b),
                new int64(-1564481375, 0x4cf10364), new int64(-1474664885, -1136513023),
                new int64(-1035236496, -789014639), new int64(-949202525, 0x654be30),
                new int64(-778901479, -688958952), new int64(-694614492, 0x5565a910),
                new int64(-200395387, 0x5771202a), new int64(0x106aa070, 0x32bbd1b8),
                new int64(0x19a4c116, -1194143544), new int64(0x1e376c08, 0x5141ab53),
                new int64(0x2748774c, -544281703), new int64(0x34b0bcb5, -509917016),
                new int64(0x391c0cb3, -976659869), new int64(0x4ed8aa4a, -482243893),
                new int64(0x5b9cca4f, 0x7763e373), new int64(0x682e6ff3, -692930397),
                new int64(0x748f82ee, 0x5defb2fc), new int64(0x78a5636f, 0x43172f60),
                new int64(-2067236844, -1578062990), new int64(-1933114872, 0x1a6439ec),
                new int64(-1866530822, 0x23631e28), new int64(-1538233109, -561857047),
                new int64(-1090935817, -1295615723), new int64(-965641998, -479046869),
                new int64(-903397682, -366583396), new int64(-779700025, 0x21c0c207),
                new int64(-354779690, -840897762), new int64(-176337025, -294727304),
                new int64(0x6f067aa, 0x72176fba), new int64(0xa637dc5, -1563912026),
                new int64(0x113f9804, -1090974290), new int64(0x1b710b35, 0x131c471b),
                new int64(0x28db77f5, 0x23047d84), new int64(0x32caab7b, 0x40c72493),
                new int64(0x3c9ebe0a, 0x15c9bebc), new int64(0x431d67c4, -1676669620),
                new int64(0x4cc5d4be, -885112138), new int64(0x597f299c, -60457430),
                new int64(0x5fcb6fab, 0x3ad6faec), new int64(0x6c44198c, 0x4a475817)
              ];
            }

            for (i = 0; i < 80; i += 1) {
              W[i] = new int64(0, 0);
            }

            // append padding to the source string. The format is described in the FIPS.
            x[len >> 5] |= 0x80 << (24 - (len & 0x1f));
            x[((len + 128 >> 10) << 5) + 31] = len;
            l = x.length;
            for (i = 0; i < l; i += 32) { //32 dwords is the block size
              int64copy(a, H[0]);
              int64copy(b, H[1]);
              int64copy(c, H[2]);
              int64copy(d, H[3]);
              int64copy(e, H[4]);
              int64copy(f, H[5]);
              int64copy(g, H[6]);
              int64copy(h, H[7]);

              for (j = 0; j < 16; j += 1) {
                W[j].h = x[i + 2 * j];
                W[j].l = x[i + 2 * j + 1];
              }

              for (j = 16; j < 80; j += 1) {
                //sigma1
                int64rrot(r1, W[j - 2], 19);
                int64revrrot(r2, W[j - 2], 29);
                int64shr(r3, W[j - 2], 6);
                s1.l = r1.l ^ r2.l ^ r3.l;
                s1.h = r1.h ^ r2.h ^ r3.h;
                //sigma0
                int64rrot(r1, W[j - 15], 1);
                int64rrot(r2, W[j - 15], 8);
                int64shr(r3, W[j - 15], 7);
                s0.l = r1.l ^ r2.l ^ r3.l;
                s0.h = r1.h ^ r2.h ^ r3.h;

                int64add4(W[j], s1, W[j - 7], s0, W[j - 16]);
              }

              for (j = 0; j < 80; j += 1) {
                //Ch
                Ch.l = (e.l & f.l) ^ (~e.l & g.l);
                Ch.h = (e.h & f.h) ^ (~e.h & g.h);

                //Sigma1
                int64rrot(r1, e, 14);
                int64rrot(r2, e, 18);
                int64revrrot(r3, e, 9);
                s1.l = r1.l ^ r2.l ^ r3.l;
                s1.h = r1.h ^ r2.h ^ r3.h;

                //Sigma0
                int64rrot(r1, a, 28);
                int64revrrot(r2, a, 2);
                int64revrrot(r3, a, 7);
                s0.l = r1.l ^ r2.l ^ r3.l;
                s0.h = r1.h ^ r2.h ^ r3.h;

                //Maj
                Maj.l = (a.l & b.l) ^ (a.l & c.l) ^ (b.l & c.l);
                Maj.h = (a.h & b.h) ^ (a.h & c.h) ^ (b.h & c.h);

                int64add5(T1, h, s1, Ch, sha512_k[j], W[j]);
                int64add(T2, s0, Maj);

                int64copy(h, g);
                int64copy(g, f);
                int64copy(f, e);
                int64add(e, d, T1);
                int64copy(d, c);
                int64copy(c, b);
                int64copy(b, a);
                int64add(a, T1, T2);
              }
              int64add(H[0], H[0], a);
              int64add(H[1], H[1], b);
              int64add(H[2], H[2], c);
              int64add(H[3], H[3], d);
              int64add(H[4], H[4], e);
              int64add(H[5], H[5], f);
              int64add(H[6], H[6], g);
              int64add(H[7], H[7], h);
            }

            //represent the hash as an array of 32-bit dwords
            for (i = 0; i < 8; i += 1) {
              hash[2 * i] = H[i].h;
              hash[2 * i + 1] = H[i].l;
            }
            return hash;
          }

          //A constructor for 64-bit numbers

          function int64(h, l) {
            this.h = h;
            this.l = l;
            //this.toString = int64toString;
          }

          //Copies src into dst, assuming both are 64-bit numbers

          function int64copy(dst, src) {
            dst.h = src.h;
            dst.l = src.l;
          }

          //Right-rotates a 64-bit number by shift
          //Won't handle cases of shift>=32
          //The function revrrot() is for that

          function int64rrot(dst, x, shift) {
            dst.l = (x.l >>> shift) | (x.h << (32 - shift));
            dst.h = (x.h >>> shift) | (x.l << (32 - shift));
          }

          //Reverses the dwords of the source and then rotates right by shift.
          //This is equivalent to rotation by 32+shift

          function int64revrrot(dst, x, shift) {
            dst.l = (x.h >>> shift) | (x.l << (32 - shift));
            dst.h = (x.l >>> shift) | (x.h << (32 - shift));
          }

          //Bitwise-shifts right a 64-bit number by shift
          //Won't handle shift>=32, but it's never needed in SHA512

          function int64shr(dst, x, shift) {
            dst.l = (x.l >>> shift) | (x.h << (32 - shift));
            dst.h = (x.h >>> shift);
          }

          //Adds two 64-bit numbers
          //Like the original implementation, does not rely on 32-bit operations

          function int64add(dst, x, y) {
            var w0 = (x.l & 0xffff) + (y.l & 0xffff);
            var w1 = (x.l >>> 16) + (y.l >>> 16) + (w0 >>> 16);
            var w2 = (x.h & 0xffff) + (y.h & 0xffff) + (w1 >>> 16);
            var w3 = (x.h >>> 16) + (y.h >>> 16) + (w2 >>> 16);
            dst.l = (w0 & 0xffff) | (w1 << 16);
            dst.h = (w2 & 0xffff) | (w3 << 16);
          }

          //Same, except with 4 addends. Works faster than adding them one by one.

          function int64add4(dst, a, b, c, d) {
            var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff);
            var w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (w0 >>> 16);
            var w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (w1 >>> 16);
            var w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (w2 >>> 16);
            dst.l = (w0 & 0xffff) | (w1 << 16);
            dst.h = (w2 & 0xffff) | (w3 << 16);
          }

          //Same, except with 5 addends

          function int64add5(dst, a, b, c, d, e) {
            var w0 = (a.l & 0xffff) + (b.l & 0xffff) + (c.l & 0xffff) + (d.l & 0xffff) + (e.l & 0xffff),
              w1 = (a.l >>> 16) + (b.l >>> 16) + (c.l >>> 16) + (d.l >>> 16) + (e.l >>> 16) + (w0 >>> 16),
              w2 = (a.h & 0xffff) + (b.h & 0xffff) + (c.h & 0xffff) + (d.h & 0xffff) + (e.h & 0xffff) + (w1 >>> 16),
              w3 = (a.h >>> 16) + (b.h >>> 16) + (c.h >>> 16) + (d.h >>> 16) + (e.h >>> 16) + (w2 >>> 16);
            dst.l = (w0 & 0xffff) | (w1 << 16);
            dst.h = (w2 & 0xffff) | (w3 << 16);
          }
        },
        /**
         * @class Hashes.RMD160
         * @constructor
         * @param {Object} [config]
         *
         * A JavaScript implementation of the RIPEMD-160 Algorithm
         * Version 2.2 Copyright Jeremy Lin, Paul Johnston 2000 - 2009.
         * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
         * See http://pajhome.org.uk/crypt/md5 for details.
         * Also http://www.ocf.berkeley.edu/~jjlin/jsotp/
         */
        RMD160: function(options) {
          /**
           * Private properties configuration variables. You may need to tweak these to be compatible with
           * the server-side, but the defaults work in most cases.
           * @see this.setUpperCase() method
           * @see this.setPad() method
           */
          (options && typeof options.uppercase === 'boolean') ? options.uppercase : false;
            var /* hexadecimal output case format. false - lowercase; true - uppercase  */
            b64pad = (options && typeof options.pad === 'string') ? options.pa : '=',
            /* base-64 pad character. Default '=' for strict RFC compliance   */
            utf8 = (options && typeof options.utf8 === 'boolean') ? options.utf8 : true,
            /* enable/disable utf8 encoding */
            rmd160_r1 = [
              0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
              7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
              3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
              1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
              4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
            ],
            rmd160_r2 = [
              5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
              6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
              15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
              8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
              12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
            ],
            rmd160_s1 = [
              11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
              7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
              11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
              11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
              9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
            ],
            rmd160_s2 = [
              8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
              9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
              9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
              15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
              8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
            ];

          /* privileged (public) methods */
          this.hex = function(s) {
            return rstr2hex(rstr(s));
          };
          this.b64 = function(s) {
            return rstr2b64(rstr(s), b64pad);
          };
          this.any = function(s, e) {
            return rstr2any(rstr(s), e);
          };
          this.raw = function(s) {
            return rstr(s);
          };
          this.hex_hmac = function(k, d) {
            return rstr2hex(rstr_hmac(k, d));
          };
          this.b64_hmac = function(k, d) {
            return rstr2b64(rstr_hmac(k, d), b64pad);
          };
          this.any_hmac = function(k, d, e) {
            return rstr2any(rstr_hmac(k, d), e);
          };
          /**
           * Perform a simple self-test to see if the VM is working
           * @return {String} Hexadecimal hash sample
           * @public
           */
          this.vm_test = function() {
            return hex('abc').toLowerCase() === '900150983cd24fb0d6963f7d28e17f72';
          };
          /**
           * @description Enable/disable uppercase hexadecimal returned string
           * @param {boolean}
           * @return {Object} this
           * @public
           */
          this.setUpperCase = function(a) {
            return this;
          };
          /**
           * @description Defines a base64 pad string
           * @param {string} Pad
           * @return {Object} this
           * @public
           */
          this.setPad = function(a) {
            if (typeof a !== 'undefined') {
              b64pad = a;
            }
            return this;
          };
          /**
           * @description Defines a base64 pad string
           * @param {boolean}
           * @return {Object} this
           * @public
           */
          this.setUTF8 = function(a) {
            if (typeof a === 'boolean') {
              utf8 = a;
            }
            return this;
          };

          /* private methods */

          /**
           * Calculate the rmd160 of a raw string
           */

          function rstr(s) {
            s = (utf8) ? utf8Encode(s) : s;
            return binl2rstr(binl(rstr2binl(s), s.length * 8));
          }

          /**
           * Calculate the HMAC-rmd160 of a key and some data (raw strings)
           */

          function rstr_hmac(key, data) {
            key = (utf8) ? utf8Encode(key) : key;
            data = (utf8) ? utf8Encode(data) : data;
            var i, hash,
              bkey = rstr2binl(key),
              ipad = Array(16),
              opad = Array(16);

            if (bkey.length > 16) {
              bkey = binl(bkey, key.length * 8);
            }

            for (i = 0; i < 16; i += 1) {
              ipad[i] = bkey[i] ^ 0x36363636;
              opad[i] = bkey[i] ^ 0x5C5C5C5C;
            }
            hash = binl(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
            return binl2rstr(binl(opad.concat(hash), 512 + 160));
          }

          /**
           * Convert an array of little-endian words to a string
           */

          function binl2rstr(input) {
            var i, output = '',
              l = input.length * 32;
            for (i = 0; i < l; i += 8) {
              output += String.fromCharCode((input[i >> 5] >>> (i % 32)) & 0xFF);
            }
            return output;
          }

          /**
           * Calculate the RIPE-MD160 of an array of little-endian words, and a bit length.
           */

          function binl(x, len) {
            var T, j, i, l,
              h0 = 0x67452301,
              h1 = 0xefcdab89,
              h2 = 0x98badcfe,
              h3 = 0x10325476,
              h4 = 0xc3d2e1f0,
              A1, B1, C1, D1, E1,
              A2, B2, C2, D2, E2;

            /* append padding */
            x[len >> 5] |= 0x80 << (len % 32);
            x[(((len + 64) >>> 9) << 4) + 14] = len;
            l = x.length;

            for (i = 0; i < l; i += 16) {
              A1 = A2 = h0;
              B1 = B2 = h1;
              C1 = C2 = h2;
              D1 = D2 = h3;
              E1 = E2 = h4;
              for (j = 0; j <= 79; j += 1) {
                T = safe_add(A1, rmd160_f(j, B1, C1, D1));
                T = safe_add(T, x[i + rmd160_r1[j]]);
                T = safe_add(T, rmd160_K1(j));
                T = safe_add(bit_rol(T, rmd160_s1[j]), E1);
                A1 = E1;
                E1 = D1;
                D1 = bit_rol(C1, 10);
                C1 = B1;
                B1 = T;
                T = safe_add(A2, rmd160_f(79 - j, B2, C2, D2));
                T = safe_add(T, x[i + rmd160_r2[j]]);
                T = safe_add(T, rmd160_K2(j));
                T = safe_add(bit_rol(T, rmd160_s2[j]), E2);
                A2 = E2;
                E2 = D2;
                D2 = bit_rol(C2, 10);
                C2 = B2;
                B2 = T;
              }

              T = safe_add(h1, safe_add(C1, D2));
              h1 = safe_add(h2, safe_add(D1, E2));
              h2 = safe_add(h3, safe_add(E1, A2));
              h3 = safe_add(h4, safe_add(A1, B2));
              h4 = safe_add(h0, safe_add(B1, C2));
              h0 = T;
            }
            return [h0, h1, h2, h3, h4];
          }

          // specific algorithm methods

          function rmd160_f(j, x, y, z) {
            return (0 <= j && j <= 15) ? (x ^ y ^ z) :
              (16 <= j && j <= 31) ? (x & y) | (~x & z) :
              (32 <= j && j <= 47) ? (x | ~y) ^ z :
              (48 <= j && j <= 63) ? (x & z) | (y & ~z) :
              (64 <= j && j <= 79) ? x ^ (y | ~z) :
              'rmd160_f: j out of range';
          }

          function rmd160_K1(j) {
            return (0 <= j && j <= 15) ? 0x00000000 :
              (16 <= j && j <= 31) ? 0x5a827999 :
              (32 <= j && j <= 47) ? 0x6ed9eba1 :
              (48 <= j && j <= 63) ? 0x8f1bbcdc :
              (64 <= j && j <= 79) ? 0xa953fd4e :
              'rmd160_K1: j out of range';
          }

          function rmd160_K2(j) {
            return (0 <= j && j <= 15) ? 0x50a28be6 :
              (16 <= j && j <= 31) ? 0x5c4dd124 :
              (32 <= j && j <= 47) ? 0x6d703ef3 :
              (48 <= j && j <= 63) ? 0x7a6d76e9 :
              (64 <= j && j <= 79) ? 0x00000000 :
              'rmd160_K2: j out of range';
          }
        }
      };

      // exposes Hashes
      (function(window, undefined$1) {
        var freeExports = false;
        {
          freeExports = exports;
          if (exports && typeof commonjsGlobal === 'object' && commonjsGlobal && commonjsGlobal === commonjsGlobal.global) {
            window = commonjsGlobal;
          }
        }

        if (typeof undefined$1 === 'function' && typeof undefined$1.amd === 'object' && undefined$1.amd) {
          // define as an anonymous module, so, through path mapping, it can be aliased
          undefined$1(function() {
            return Hashes;
          });
        } else if (freeExports) {
          // in Node.js or RingoJS v0.8.0+
          if (module && module.exports === freeExports) {
            module.exports = Hashes;
          }
          // in Narwhal or RingoJS v0.7.0-
          else {
            freeExports.Hashes = Hashes;
          }
        } else {
          // in a browser or Rhino
          window.Hashes = Hashes;
        }
      }(this));
    }()); // IIFE
    }(hashes, hashes.exports));

    var Hashes = hashes.exports;

    class JSHashesRMD {
        constructor() {
            this.rmd160base64func = new Hashes.RMD160().b64;
            this.rmd160hexfunc = new Hashes.RMD160().hex;
        }
        rmd160base64(text) {
            return this.rmd160base64func(text);
        }
        rmd160hex(text) {
            return this.rmd160hexfunc(text);
        }
        rmd160base64impl() {
            return this.rmd160base64func;
        }
        rmd160heximpl() {
            return this.rmd160hexfunc;
        }
    }

    class JSHashesSHA {
        constructor() {
            this.sha1base64func = new Hashes.SHA1().b64;
            this.sha256base64func = new Hashes.SHA256().b64;
            this.sha512base64func = new Hashes.SHA512().b64;
            this.sha1hexfunc = new Hashes.SHA1().hex;
            this.sha256hexfunc = new Hashes.SHA256().hex;
            this.sha512hexfunc = new Hashes.SHA512().hex;
        }
        sha1base64(text) {
            return this.sha1base64func(text);
        }
        sha256base64(text) {
            return this.sha256base64func(text);
        }
        sha512base64(text) {
            return this.sha512base64func(text);
        }
        sha1hex(text) {
            return this.sha1hexfunc(text);
        }
        sha256hex(text) {
            return this.sha256hexfunc(text);
        }
        sha512hex(text) {
            return this.sha512hexfunc(text);
        }
        sha1base64impl() {
            return this.sha1base64func;
        }
        sha256base64impl() {
            return this.sha256base64func;
        }
        sha512base64impl() {
            return this.sha512base64func;
        }
        sha1heximpl() {
            return this.sha1hexfunc;
        }
        sha256heximpl() {
            return this.sha256hexfunc;
        }
        sha512heximpl() {
            return this.sha512hexfunc;
        }
    }

    class Strings {
        static stingToArrayBuffer(str) {
            const buf = new ArrayBuffer(str.length);
            const bufView = new Uint8Array(buf);
            for (let i = 0, strLen = str.length; i < strLen; i++) {
                bufView[i] = str.charCodeAt(i);
            }
            return buf;
        }
        static Uint8arrayToBase64(u8) {
            return btoa(String.fromCharCode.apply(null, Array.from(u8)));
        }
        static base64ToUint8array(base64) {
            const raw = atob(base64);
            const array = new Uint8Array(raw.length);
            for (let i = 0; i < raw.length; i++) {
                array[i] = raw.charCodeAt(i);
            }
            return array;
        }
        static base64toHex(base64) {
            var raw = atob(base64);
            var hex = '';
            for (let i = 0; i < raw.length; i++) {
                var _hex = raw.charCodeAt(i).toString(16);
                hex += (_hex.length == 2 ? _hex : '0' + _hex);
            }
            return hex.toUpperCase();
        }
        static hexToBase64(hex) {
            return btoa(hex.match(/\w{2}/g).map(function (a) {
                return String.fromCharCode(parseInt(a, 16));
            }).join(""));
        }
        // Slow but simple chunker to use on small strings:
        // RSA-encoded symmetric keys, etc.
        static chunk(text, length) {
            let chunks = new Array();
            while (text.length > length) {
                let chunk = text.slice(0, length);
                chunks.push(chunk);
                text = text.slice(length, text.length);
            }
            chunks.push(text);
            return chunks;
        }
        static unchunk(chunks) {
            let text = '';
            for (let chunk of chunks) {
                text = text + chunk;
            }
            return text;
        }
    }

    class Serialization {
        static default(literal) {
            var plain = '';
            // this works both for object literals and arrays, arrays behave
            // like literals with "0", "1", "2"... as keys.
            if (typeof literal === 'object') {
                var keys = Object.keys(literal);
                keys.sort();
                keys.forEach(key => {
                    plain = plain +
                        Serialization.escapeString(key) + ':' + Serialization.default(literal[key]) + ',';
                });
            }
            else {
                plain = Serialization.escapeString(literal.toString());
            }
            return plain;
        }
        static escapeString(text) {
            return "'" + text.toString().replace("'", "''") + "'";
        }
    }

    class Hashing {
        static forString(text, seed) {
            if (seed === undefined) {
                seed = '';
            }
            let firstPass = Hashing.sha.sha256base64('0a' + text + seed);
            let secondPass = Hashing.rmd.rmd160base64(text + firstPass);
            return secondPass;
        }
        static forValue(value, seed) {
            let text = Serialization.default(value);
            return Hashing.forString(text, seed);
        }
        static toHex(hash) {
            return Strings.base64toHex(hash);
        }
        static fromHex(hex) {
            return Strings.hexToBase64(hex);
        }
    }
    Hashing.sha = new JSHashesSHA();
    Hashing.rmd = new JSHashesRMD();

    class HashedSet {
        constructor(init) {
            this.hashedElements = new Map();
            if (init !== undefined) {
                for (const member of init) {
                    this.add(member);
                }
            }
        }
        add(element) {
            this.hashedElements.set(HashedObject.hashElement(element), element);
        }
        remove(element) {
            return this.removeByHash(HashedObject.hashElement(element));
        }
        removeByHash(hash) {
            return this.hashedElements.delete(hash);
        }
        has(element) {
            return this.hasByHash(HashedObject.hashElement(element));
        }
        hasByHash(hash) {
            return this.hashedElements.has(hash);
        }
        get(hash) {
            return this.hashedElements.get(hash);
        }
        values() {
            return this.hashedElements.values();
        }
        toArrays() {
            let hashes = Array.from(this.hashedElements.keys());
            hashes.sort();
            let elements = [];
            for (let hash of hashes) {
                elements.push(this.hashedElements.get(hash));
            }
            return { hashes: hashes, elements: elements };
        }
        fromArrays(_hashes, elements) {
            for (let i = 0; i < elements.length; i++) {
                this.add(elements[i]);
            }
        }
        equals(another) {
            let hashes = Array.from(this.hashedElements.keys());
            hashes.sort();
            let anotherHashes = Array.from(another.hashedElements.keys());
            anotherHashes.sort();
            let result = hashes.length === anotherHashes.length;
            for (let i = 0; result && i < hashes.length; i++) {
                result = result && hashes[i] === anotherHashes[i];
            }
            return result;
        }
        literalize(path = '', context) {
            let dependencies = new Set();
            let arrays = this.toArrays();
            let hashes = arrays.hashes;
            let child = HashedObject.literalizeField(path, arrays.elements, context);
            let elements = child.value;
            HashedObject.collectChildDeps(dependencies, child.dependencies);
            let value = { _type: 'hashed_set', _hashes: hashes, _elements: elements };
            return { value: value, dependencies: dependencies };
        }
        hash() {
            return Hashing.forValue(this.literalize().value);
        }
        size() {
            return this.hashedElements.size;
        }
        // NOTE ABOUT VALIDATION.
        // There is no validation step for deliteralize, but if the object came from an unstrusted source,
        // it will be re-hashed after reconstruction to check if the advertised hash was correct.
        // Hence if the hashes in the array were not sorted as they should, they will be when the object
        // is re-hashed, the hashes will not match and the object will be discarded.
        static deliteralize(value, context, validate = false) {
            if (value['_type'] !== 'hashed_set') {
                throw new Error("Trying to deliteralize value, but _type is '" + value['_type'] + "' (shoud be 'hashed_set')");
            }
            let hashes = value['_hashes'];
            let elements = HashedObject.deliteralizeField(value['_elements'], context, validate);
            let hset = new HashedSet();
            hset.fromArrays(hashes, elements);
            return hset;
        }
        static elementsFromLiteral(literal) {
            return literal['_elements'];
            //return literal['_elements'].map((elmtValue: {_hash: Hash}) => elmtValue['_hash']);
        }
    }

    class HashReference {
        constructor(hash, className) {
            this.hash = hash;
            this.className = className;
        }
        //static create(target: T) {
        //   return new HashReference<T>(target.hash(), target.getClassName());
        //}
        literalize() {
            return { _type: 'hashed_object_reference', _hash: this.hash, _class: this.className };
        }
        static deliteralize(literal) {
            return new HashReference(literal._hash, literal._class);
        }
        static hashFromLiteral(literal) {
            return literal._hash;
        }
        static classNameFromLiteral(literal) {
            return literal._class;
        }
    }

    class HashedMap {
        constructor(init) {
            this.content = new Map();
            this.contentHashes = new Map();
            if (init !== undefined) {
                for (const [key, value] of init) {
                    this.set(key, value);
                }
            }
        }
        set(key, value) {
            let hash = HashedObject.hashElement(value);
            this.content.set(key, value);
            this.contentHashes.set(key, hash);
        }
        remove(key) {
            this.content.delete(key);
            this.contentHashes.delete(key);
        }
        has(key) {
            return this.contentHashes.has(key);
        }
        entries() {
            return this.content.entries();
        }
        toArrays() {
            let keys = Array.from(this.content.keys());
            keys.sort();
            let entries = [];
            let hashes = [];
            for (const key of keys) {
                entries.push([key, this.content.get(key)]);
                hashes.push(this.contentHashes.get(key));
            }
            return { entries: entries, hashes: hashes };
        }
        fromArrays(_hashes, entries) {
            for (let i = 0; i < entries.length; i++) {
                let [key, value] = entries[i];
                this.set(key, value);
            }
        }
        equals(another) {
            let thisArrays = this.toArrays();
            let anotherArrays = another.toArrays();
            let result = thisArrays.entries.length == anotherArrays.entries.length;
            for (let i = 0; result && i < thisArrays.entries.length; i++) {
                const thisKey = thisArrays.entries[i][0];
                const anotherKey = anotherArrays.entries[i][0];
                const thisHash = thisArrays.hashes[i];
                const anotherHash = anotherArrays.hashes[i];
                result = result &&
                    thisKey === anotherKey &&
                    thisHash === anotherHash;
            }
            return result;
        }
        literalize(path = '', context) {
            let dependencies = new Set();
            let arrays = this.toArrays();
            let hashes = arrays.hashes;
            let child = HashedObject.literalizeField(path, arrays.entries, context);
            let entries = child.value;
            HashedObject.collectChildDeps(dependencies, child.dependencies);
            let value = { _type: 'hashed_map', _hashes: hashes, _entries: entries };
            return { value: value, dependencies: dependencies };
        }
        hash() {
            return Hashing.forValue(this.literalize().value);
        }
        static deliteralize(value, context, validate = false) {
            if (value['_type'] !== 'hashed_map') {
                throw new Error("Trying to deliteralize value, but _type is '" + value['_type'] + "' (shoud be 'hashed_map')");
            }
            let hashes = value['_hashes'];
            let entries = HashedObject.deliteralizeField(value['_entries'], context, validate);
            let hmap = new HashedMap();
            hmap.fromArrays(hashes, entries);
            return hmap;
        }
    }

    class LiteralUtils {
        static getType(literal) {
            return literal.value['_type'];
        }
        static getClassName(literal) {
            return literal.value['_class'];
        }
        static getFields(literal) {
            return literal.value['_fields'];
        }
        static getFlags(literal) {
            return literal.value['_flags'];
        }
        // FIXME: I think this break custom hashes!!!!
        // I think you cannot check the hash without deliteralizing the object.
        static validateHash(literal) {
            return literal.hash === Hashing.forValue(literal.value);
        }
    }

    class Context {
        constructor() {
            this.rootHashes = [];
            this.objects = new Map();
            this.literals = new Map();
        }
        has(hash) {
            var _a;
            return this.literals.has(hash) || this.objects.has(hash) ||
                (((_a = this === null || this === void 0 ? void 0 : this.resources) === null || _a === void 0 ? void 0 : _a.aliasing) !== undefined && this.resources.aliasing.has(hash));
        }
        toLiteralContext() {
            return { rootHashes: Array.from(this.rootHashes), literals: Object.fromEntries(this.literals.entries()) };
        }
        fromLiteralContext(literalContext) {
            this.rootHashes = Array.from(literalContext.rootHashes);
            this.literals = new Map(Object.entries(literalContext.literals));
            this.objects = new Map();
        }
        merge(other) {
            var _a, _b;
            const roots = new Set(this.rootHashes.concat(other.rootHashes));
            this.rootHashes = Array.from(roots);
            for (const [hash, literal] of other.literals.entries()) {
                if (!this.literals.has(hash)) {
                    this.literals.set(hash, literal);
                }
            }
            for (const [hash, obj] of other.objects.entries()) {
                if (!this.objects.has(hash)) {
                    this.objects.set(hash, obj);
                }
            }
            if (this.resources === undefined) {
                this.resources = other.resources;
            }
            else {
                if (((_a = other.resources) === null || _a === void 0 ? void 0 : _a.aliasing) !== undefined) {
                    if (((_b = this.resources) === null || _b === void 0 ? void 0 : _b.aliasing) === undefined) {
                        this.resources.aliasing = new Map();
                    }
                    for (const [hash, aliased] of other.resources.aliasing.entries()) {
                        if (!this.resources.aliasing.has(hash)) {
                            this.resources.aliasing.set(hash, aliased);
                        }
                    }
                }
            }
        }
        // if a dependency is in more than one subobject, it will pick one of the shortest dep chains.
        findMissingDeps(hash, chain, missing) {
            if (chain === undefined) {
                chain = [];
            }
            if (missing === undefined) {
                missing = new Map();
            }
            let literal = this.literals.get(hash);
            if (literal === undefined) {
                let prevChain = missing.get(hash);
                if (prevChain === undefined || chain.length < prevChain.length) {
                    missing.set(hash, chain);
                }
            }
            else {
                for (const dep of literal.dependencies) {
                    let newChain = chain.slice();
                    newChain.unshift(hash);
                    this.findMissingDeps(dep.hash, newChain, missing);
                }
            }
            return missing;
        }
        checkLiteralHashes() {
            let result = true;
            for (const [hash, literal] of this.literals.entries()) {
                if (hash !== literal.hash || !LiteralUtils.validateHash(literal)) {
                    result = false; // but what about custom hashes??
                    break;
                }
            }
            return result;
        }
        checkRootHashes() {
            let result = true;
            for (const hash of this.rootHashes) {
                if (!this.literals.has(hash)) {
                    result = false;
                    break;
                }
            }
            return result;
        }
    }

    //import { __spreadArrays } from 'tslib';
    const BITS_FOR_ID = 128;
    /* HashedObject: Base class for objects than need to be storable in the
                     Hyper Hyper Space global content-addressed database.

     Defines how an object will be serialized, hashed, who it was authored by,
     whether it needs an id (randomized or derived from a parent object's id)
     and which objects should be preloaded when loading operations that mutate
     this object and its subobjects. */
    //let done = false;
    class HashedObject {
        constructor() {
            this._signOnSave = false;
        }
        static registerClass(name, clazz) {
            const another = HashedObject.knownClasses.get(name);
            if (another === undefined) {
                HashedObject.knownClasses.set(name, clazz);
            }
            else if (another !== clazz) {
                throw new Error('Attempting to register two different instances of class ' + name + ', this would cause "instanceof" to give incorrect results. Check if your project has imported two instances of @hyper-hyper-space/core (maybe your dependencies are using two different versions?).');
            }
        }
        static lookupClass(name) {
            return HashedObject.knownClasses.get(name);
        }
        getId() {
            return this.id;
        }
        setId(id) {
            this.id = id;
        }
        setRandomId() {
            //TODO: use b64 here
            this.id = new BrowserRNG().randomHexString(BITS_FOR_ID);
        }
        hasId() {
            return this.id !== undefined;
        }
        setAuthor(author) {
            if (!author.hasKeyPair()) {
                throw new Error('Trying to set the author of an object, but the received identity does not have an attached key pair to sign it.');
            }
            if (!author.equals(this.author)) {
                this.author = author;
                this._signOnSave = true;
            }
        }
        getAuthor() {
            return this.author;
        }
        hasLastSignature() {
            return this._lastSignature !== undefined;
        }
        setLastSignature(signature) {
            this._lastSignature = signature;
        }
        getLastSignature() {
            if (this._lastSignature === undefined) {
                throw new Error('Attempted to retrieve last signature for unsigned object');
            }
            return this._lastSignature;
        }
        overrideChildrenId() {
            for (const fieldName of Object.keys(this)) {
                if (fieldName.length > 0 && fieldName[0] !== '_') {
                    let value = this[fieldName];
                    if (value instanceof HashedObject) {
                        this.overrideIdForPath(fieldName, value);
                    }
                }
            }
        }
        overrideIdForPath(path, target) {
            let parentId = this.getId();
            if (parentId === undefined) {
                throw new Error("Can't override a child's Id because parent's Id is unset");
            }
            target.setId(HashedObject.generateIdForPath(parentId, path));
        }
        hasStore() {
            var _a;
            return ((_a = this._resources) === null || _a === void 0 ? void 0 : _a.store) !== undefined;
        }
        setStore(store) {
            if (this._resources === undefined) {
                this._resources = {};
            }
            this._resources.store = store;
        }
        getStore() {
            var _a;
            if (!this.hasStore()) {
                throw new Error('Attempted to get store from object resources, but one is not present in instance of ' + this._lastHash);
            }
            return (_a = this._resources) === null || _a === void 0 ? void 0 : _a.store;
        }
        getMesh() {
            var _a, _b;
            if (((_a = this._resources) === null || _a === void 0 ? void 0 : _a.mesh) === undefined) {
                throw new Error('Attempted to get mesh from object resources, but one is not present.');
            }
            else {
                return (_b = this._resources) === null || _b === void 0 ? void 0 : _b.mesh;
            }
        }
        hasLastHash() {
            return this._lastHash !== undefined;
        }
        setLastHash(hash) {
            this._lastHash = hash;
        }
        getLastHash() {
            if (this._lastHash === undefined) {
                this.hash();
            }
            return this._lastHash;
        }
        shouldSignOnSave() {
            return this._signOnSave;
        }
        hash(seed) {
            let hash = this.customHash(seed);
            if (hash === undefined) {
                let context = this.toContext();
                if (seed === undefined) {
                    hash = context.rootHashes[0];
                }
                else {
                    let literal = context.literals.get(context.rootHashes[0]);
                    hash = Hashing.forValue(literal.value, seed);
                }
            }
            if (seed === undefined) {
                this._lastHash = hash;
            }
            return hash;
        }
        customHash(seed) {
            return undefined;
        }
        createReference() {
            return new HashReference(this.hash(), this.getClassName());
        }
        equals(another) {
            return another !== undefined && this.hash() === another.hash();
        }
        clone() {
            let c = this.toContext();
            c.objects = new Map();
            let clone = HashedObject.fromContext(c);
            clone.init();
            clone._signOnSave = this._signOnSave;
            clone._lastSignature = this._lastSignature;
            return clone;
        }
        addDerivedField(fieldName, object) {
            object.setId(this.getDerivedFieldId(fieldName));
            this[fieldName] = object;
        }
        checkDerivedField(fieldName) {
            let field = this[fieldName];
            return field !== undefined && field instanceof HashedObject &&
                field.getId() === this.getDerivedFieldId(fieldName);
        }
        getDerivedFieldId(fieldName) {
            return Hashing.forValue('#' + this.getId() + '.' + fieldName);
        }
        setResources(resources) {
            this._resources = resources;
        }
        getResources() {
            return this._resources;
        }
        toLiteralContext(context) {
            if (context === undefined) {
                context = new Context();
            }
            this.toContext(context);
            return context.toLiteralContext();
        }
        toLiteral() {
            let context = this.toContext();
            return context.literals.get(context.rootHashes[0]);
        }
        toContext(context) {
            if (context === undefined) {
                context = new Context();
            }
            let hash = this.literalizeInContext(context, '');
            context.rootHashes.push(hash);
            return context;
        }
        literalizeInContext(context, path, flags) {
            var _a, _b;
            let fields = {};
            let dependencies = new Set();
            for (const fieldName of Object.keys(this)) {
                if (fieldName.length > 0 && fieldName[0] !== '_') {
                    let value = this[fieldName];
                    if (HashedObject.shouldLiteralizeField(value)) {
                        let fieldPath = fieldName;
                        if (path !== '') {
                            fieldPath = path + '.' + fieldName;
                        }
                        let fieldLiteral = HashedObject.literalizeField(fieldPath, value, context);
                        fields[fieldName] = fieldLiteral.value;
                        HashedObject.collectChildDeps(dependencies, fieldLiteral.dependencies);
                    }
                }
            }
            if (flags === undefined) {
                flags = [];
            }
            let value = {
                _type: 'hashed_object',
                _class: this.getClassName(),
                _fields: fields,
                _flags: flags
            };
            let hash = this.customHash();
            if (hash === undefined) {
                hash = Hashing.forValue(value);
            }
            let literal = { hash: hash, value: value, dependencies: Array.from(dependencies) };
            if (this.author !== undefined) {
                literal.author = value['_fields']['author']['_hash'];
            }
            // if we have a signature, we add it to the literal
            if (this.author !== undefined && this.hasLastSignature()) {
                literal.signature = this.getLastSignature();
            }
            if (((_b = (_a = context.resources) === null || _a === void 0 ? void 0 : _a.aliasing) === null || _b === void 0 ? void 0 : _b.get(hash)) !== undefined) {
                context.objects.set(hash, context.resources.aliasing.get(hash));
            }
            else {
                context.objects.set(hash, this);
            }
            context.literals.set(hash, literal);
            this.setLastHash(hash);
            return hash;
        }
        static shouldLiteralizeField(something) {
            if (something === null) {
                throw new Error('HashedObject and its derivatives do not support null-valued fields.');
            }
            if (something === undefined) {
                return false;
            }
            else {
                let typ = typeof (something);
                if (typ === 'function' || typ === 'symbol') {
                    return false;
                }
                else {
                    return true;
                }
            }
        }
        static literalizeField(fieldPath, something, context) {
            let typ = typeof (something);
            let value;
            let dependencies = new Set();
            if (typ === 'boolean' || typ === 'number' || typ === 'string') {
                value = something;
            }
            else if (typ === 'object') {
                if (Array.isArray(something)) {
                    value = [];
                    for (const elmt of something) {
                        if (HashedObject.shouldLiteralizeField(elmt)) {
                            let child = HashedObject.literalizeField(fieldPath, elmt, context); // should we put the index into the path? but then we can't reuse this code for sets...
                            value.push(child.value);
                            HashedObject.collectChildDeps(dependencies, child.dependencies);
                        }
                    }
                }
                else if (something instanceof HashedSet) {
                    const hset = something;
                    const hsetLiteral = hset.literalize(fieldPath, context);
                    value = hsetLiteral.value;
                    HashedObject.collectChildDeps(dependencies, hsetLiteral.dependencies);
                }
                else if (something instanceof HashedMap) {
                    const hmap = something;
                    const hmapLiteral = hmap.literalize(fieldPath, context);
                    value = hmapLiteral.value;
                    HashedObject.collectChildDeps(dependencies, hmapLiteral.dependencies);
                }
                else { // not a set, map or array
                    if (something instanceof HashReference) {
                        let reference = something;
                        let dependency = { path: fieldPath, hash: reference.hash, className: reference.className, type: 'reference' };
                        dependencies.add(dependency);
                        value = reference.literalize();
                    }
                    else if (something instanceof HashedObject) {
                        let hashedObject = something;
                        if (context === undefined) {
                            throw new Error('Context needed to deliteralize HashedObject');
                        }
                        let hash = hashedObject.literalizeInContext(context, fieldPath);
                        let dependency = { path: fieldPath, hash: hash, className: hashedObject.getClassName(), type: 'literal' };
                        dependencies.add(dependency);
                        HashedObject.collectChildDeps(dependencies, new Set(context.literals.get(hash).dependencies));
                        value = { _type: 'hashed_object_dependency', _hash: hash };
                    }
                    else {
                        value = {};
                        for (const fieldName of Object.keys(something)) {
                            if (fieldName.length > 0 && fieldName[0] !== '_') {
                                let fieldValue = something[fieldName];
                                if (HashedObject.shouldLiteralizeField(fieldValue)) {
                                    let field = HashedObject.literalizeField(fieldPath + '.' + fieldName, fieldValue, context);
                                    value[fieldName] = field.value;
                                    HashedObject.collectChildDeps(dependencies, field.dependencies);
                                }
                            }
                        }
                    }
                }
            }
            else {
                throw Error("Unexpected type encountered while attempting to literalize: " + typ);
            }
            return { value: value, dependencies: dependencies };
        }
        static fromLiteralContext(literalContext, hash) {
            let context = new Context();
            context.fromLiteralContext(literalContext);
            return HashedObject.fromContext(context, hash);
        }
        static fromLiteral(literal) {
            let context = new Context();
            context.rootHashes.push(literal.hash);
            context.literals.set(literal.hash, literal);
            return HashedObject.fromContext(context);
        }
        // IMPORTANT: this method is NOT reentrant / thread safe!
        static async fromContextWithValidation(context, hash) {
            if (hash === undefined) {
                if (context.rootHashes.length === 0) {
                    throw new Error('Cannot deliteralize object because the hash was not provided, and there are no hashes in its literal representation.');
                }
                else if (context.rootHashes.length > 1) {
                    throw new Error('Cannot deliteralize object because the hash was not provided, and there are more than one hashes in its literal representation.');
                }
                hash = context.rootHashes[0];
            }
            if (context.objects.has(hash)) {
                return context.objects.get(hash);
            }
            else {
                const literal = context.literals.get(hash);
                if (literal === undefined) {
                    throw new Error('Literal for ' + hash + ' missing from context');
                }
                for (const dep of literal.dependencies) {
                    if (!context.objects.has(dep.hash)) {
                        await HashedObject.fromContextWithValidation(context, dep.hash);
                    }
                }
                const obj = HashedObject.fromContext(context, hash);
                if (obj.hash() !== hash) {
                    context.objects.delete(hash);
                    throw new Error('Wrong hash for ' + hash + ' of type ' + obj.getClassName() + ', hashed to ' + obj.getLastHash() + ' instead');
                }
                if (obj.author !== undefined) {
                    if (literal.signature === undefined) {
                        context.objects.delete(hash);
                        throw new Error('Missing signature for ' + hash + ' of type ' + obj.getClassName());
                    }
                    if (!await obj.author.verifySignature(hash, literal.signature)) {
                        context.objects.delete(hash);
                        throw new Error('Invalid signature for ' + hash + ' of type ' + obj.getClassName());
                    }
                }
                if (context.resources !== undefined) {
                    obj.setResources(context.resources);
                }
                if (!await obj.validate(context.objects)) {
                    context.objects.delete(hash);
                    throw new Error('Validation failed for ' + hash + ' of type ' + obj.getClassName());
                }
                return obj;
            }
        }
        static fromContext(context, hash) {
            if (hash === undefined) {
                if (context.rootHashes.length === 0) {
                    throw new Error('Cannot deliteralize object because the hash was not provided, and there are no hashes in its literal representation.');
                }
                else if (context.rootHashes.length > 1) {
                    throw new Error('Cannot deliteralize object because the hash was not provided, and there are more than one hashes in its literal representation.');
                }
                hash = context.rootHashes[0];
            }
            HashedObject.deliteralizeInContext(hash, context);
            return context.objects.get(hash);
        }
        // deliteralizeInContext: take the literal with the given hash from the context,
        //                        recreate the object and insert it into the context
        //                        (be smart and only do it if it hasn't been done already)
        static deliteralizeInContext(hash, context) {
            var _a, _b;
            let hashedObject = context.objects.get(hash);
            if (hashedObject !== undefined) {
                return;
            }
            // check if we can extract the object from the shared context
            let sharedObject = (_b = (_a = context === null || context === void 0 ? void 0 : context.resources) === null || _a === void 0 ? void 0 : _a.aliasing) === null || _b === void 0 ? void 0 : _b.get(hash);
            if (sharedObject !== undefined) {
                context.objects.set(hash, sharedObject);
                return;
            }
            let literal = context.literals.get(hash);
            if (literal === undefined) {
                throw new Error("Can't deliteralize object with hash " + hash + " because its literal is missing from the received context");
            }
            const value = literal.value;
            // all the dependencies have been delieralized in the context
            if (value['_type'] !== 'hashed_object') {
                throw new Error("Missing 'hashed_object' type signature while attempting to deliteralize " + literal.hash);
            }
            let constr = HashedObject.lookupClass(value['_class']);
            if (constr === undefined) {
                throw new Error("A local implementation of class '" + value['_class'] + "' is necessary to deliteralize " + literal.hash);
            }
            else {
                hashedObject = new constr();
            }
            for (const [fieldName, fieldValue] of Object.entries(value['_fields'])) {
                if (fieldName.length > 0 && fieldName[0] !== '_') {
                    hashedObject[fieldName] = HashedObject.deliteralizeField(fieldValue, context);
                }
            }
            if (context.resources !== undefined) {
                hashedObject.setResources(context.resources);
            }
            hashedObject.setLastHash(hash);
            hashedObject.init();
            // check object signature if author is present
            if (hashedObject.author !== undefined) {
                // validation is asked for explicitly now, so the following does not 
                // belong here:
                /*
                if (literal.signature === undefined) {
                    throw new Error('Singature is missing for object ' + hash);
                }

                if (!hashedObject.author.verifySignature(hash, literal.signature)) {
                    throw new Error('Invalid signature for obejct ' + hash);
                }
                */
                hashedObject.setLastSignature(literal.signature);
            }
            context.objects.set(hash, hashedObject);
        }
        static deliteralizeField(value, context, validate = false) {
            let something;
            let typ = typeof (value);
            if (typ === 'boolean' || typ === 'number' || typ === 'string') {
                something = value;
            }
            else if (typ === 'object') {
                if (Array.isArray(value)) {
                    something = [];
                    for (const elmt of value) {
                        something.push(HashedObject.deliteralizeField(elmt, context, validate));
                    }
                }
                else if (value['_type'] === undefined) {
                    something = {};
                    for (const [fieldName, fieldValue] of Object.entries(value)) {
                        something[fieldName] = HashedObject.deliteralizeField(fieldValue, context, validate);
                    }
                }
                else {
                    if (value['_type'] === 'hashed_set') {
                        something = HashedSet.deliteralize(value, context, validate);
                    }
                    else if (value['_type'] === 'hashed_map') {
                        something = HashedMap.deliteralize(value, context);
                    }
                    else if (value['_type'] === 'hashed_object_reference') {
                        something = HashReference.deliteralize(value);
                    }
                    else if (value['_type'] === 'hashed_object_dependency') {
                        let hash = value['_hash'];
                        HashedObject.deliteralizeInContext(hash, context);
                        something = context.objects.get(hash);
                    }
                    else if (value['_type'] === 'hashed_object') {
                        throw new Error("Attempted to deliteralize embedded hashed object in literal (a hash reference should be used instead)");
                    }
                    else {
                        throw new Error("Unknown _type value found while attempting to deliteralize: " + value['_type']);
                    }
                }
            }
            else {
                throw Error("Unexpected type encountered while attempting to deliteralize: " + typ);
            }
            return something;
        }
        static collectChildDeps(parentDeps, childDeps) {
            for (const childDep of childDeps) {
                parentDeps.add(childDep);
            }
        }
        static generateIdForPath(parentId, path) {
            return Hashing.forValue('#' + parentId + '.' + path);
        }
        static hashElement(element) {
            let hash;
            if (element instanceof HashedObject) {
                hash = element.hash();
            }
            else {
                hash = Hashing.forValue(HashedObject.literalizeField('', element).value);
            }
            return hash;
        }
        // the following only for pretty printing.
        static stringifyLiteral(literal) {
            return HashedObject.stringifyLiteralWithIndent(literal, 0);
        }
        static stringifyLiteralWithIndent(literal, indent) {
            const value = literal['value'];
            const dependencies = literal['dependencies'];
            let something;
            let typ = typeof (value);
            let tab = '\n' + ' '.repeat(indent * 4);
            if (typ === 'boolean' || typ === 'number' || typ === 'string') {
                something = value;
            }
            else if (typ === 'object') {
                if (Array.isArray(value)) {
                    if (value.length > 0) {
                        something = tab + '[';
                        let first = true;
                        for (const elmt of value) {
                            if (!first) {
                                something = something + tab + ',';
                            }
                            first = false;
                            something = something + HashedObject.stringifyLiteralWithIndent({ value: elmt, dependencies: dependencies }, indent + 1);
                        }
                    }
                    else {
                        return '[]';
                    }
                    something = something + tab + ']';
                }
                else if (value['_type'] === 'hashed_set') {
                    something = tab + 'HashedSet =>';
                    something = something + HashedObject.stringifyLiteralWithIndent({ value: value['_elements'], dependencies: dependencies }, indent + 1);
                }
                else {
                    if (value['_type'] === 'hash') {
                        let hash = value['_content'];
                        something = HashedObject.stringifyLiteralWithIndent({ value: dependencies.get(hash), dependencies: dependencies }, indent);
                    }
                    else {
                        something = tab;
                        let contents;
                        if (value['_type'] === 'hashed_object') {
                            let constr = HashedObject.lookupClass(value['_class']);
                            if (constr === undefined) {
                                something = something + 'HashedObject: ';
                            }
                            else {
                                something = something + value['_class'] + ' ';
                            }
                            contents = value['_contents'];
                        }
                        else {
                            contents = value;
                        }
                        something = something + '{';
                        for (const [key, propValue] of Object.entries(contents)) {
                            something = something + tab + '  ' + key + ':' + HashedObject.stringifyLiteralWithIndent({ value: propValue, dependencies: dependencies }, indent + 1);
                        }
                        something = something + tab + '}';
                    }
                }
            }
            else {
                throw Error("Unexpected type encountered while attempting to deliteralize: " + typ);
            }
            return something;
        }
        static stringifyHashedLiterals(hashedLiterals) {
            let s = '';
            for (let hash of hashedLiterals['literals'].keys()) {
                s = s + hash + ' =>';
                s = s + HashedObject.stringifyLiteralWithIndent({ 'value': hashedLiterals['literals'].get(hash), dependencies: hashedLiterals['literals'] }, 1);
            }
            return s;
        }
    }
    HashedObject.knownClasses = new Map();

    class Identity extends HashedObject {
        constructor() {
            super();
        }
        static fromKeyPair(info, keyPair) {
            let id = Identity.fromPublicKey(info, keyPair.makePublicKey());
            id.addKeyPair(keyPair);
            return id;
        }
        static fromPublicKey(info, publicKey) {
            let id = new Identity();
            id.info = info;
            id.publicKey = publicKey;
            return id;
        }
        init() {
        }
        async validate() {
            return true;
        }
        getClassName() {
            return Identity.className;
        }
        verifySignature(text, signature) {
            if (this.publicKey === undefined) {
                throw new Error('Cannot verify signature, Identity is uninitialized');
            }
            return this.publicKey.verifySignature(text, signature);
        }
        encrypt(text) {
            if (this.publicKey === undefined) {
                throw new Error('Cannot ecnrypt, Identity is uninitialized');
            }
            return this.publicKey.encrypt(text);
        }
        getPublicKey() {
            return this.publicKey;
        }
        getKeyPairHash() {
            return this.getPublicKey().getKeyPairHash();
        }
        addKeyPair(keyPair) {
            if (keyPair.hash() !== this.getKeyPairHash()) {
                throw new Error('Trying to add key pair to identity, but it does not match identity public key');
            }
            this._keyPair = keyPair;
        }
        hasKeyPair() {
            return this._keyPair !== undefined;
        }
        sign(text) {
            if (this._keyPair === undefined) {
                throw new Error('Trying to sign using Identity object, but no keyPair has been loaded');
            }
            return this._keyPair.sign(text);
        }
        decrypt(text) {
            if (this._keyPair === undefined) {
                throw new Error('Trying to decrypt using Identity object, but no keyPair has been loaded');
            }
            return this._keyPair.decrypt(text);
        }
        clone() {
            const clone = super.clone();
            clone._keyPair = this._keyPair;
            return clone;
        }
    }
    Identity.className = 'hhs/v0/Identity';
    HashedObject.registerClass(Identity.className, Identity);

    if (globalThis.TextEncoder === undefined || globalThis.TextDecoder === undefined) {
        require('fast-text-encoding');
    }
    class WebCryptoConfig {
        static getSubtle() {
            var _a, _b;
            if (((_a = globalThis) === null || _a === void 0 ? void 0 : _a.webCryptoOverrideImpl) !== undefined) {
                return (_b = globalThis) === null || _b === void 0 ? void 0 : _b.webCryptoOverrideImpl;
            }
            else {
                return globalThis.crypto.subtle;
            }
        }
    }

    const ALGORITHM$1 = 'RSASSA-PKCS1-v1_5';
    class WebCryptoRSASigKP {
        async generateKey(params) {
            const modulusLength = (params === null || params === void 0 ? void 0 : params.b) || 2048;
            const hash = 'SHA-256';
            const keyPair = await WebCryptoConfig.getSubtle().generateKey({
                name: ALGORITHM$1,
                // Consider using a 4096-bit key for systems that require long-term security
                modulusLength: modulusLength,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: hash,
            }, true, ['sign', 'verify']);
            this.privateKey = keyPair.privateKey;
            const exportedPrivKey = await WebCryptoConfig.getSubtle().exportKey("pkcs8", keyPair.privateKey);
            this.privateKeyPEM = '-----BEGIN PRIVATE KEY-----\n' +
                btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(exportedPrivKey)))).match(/.{1,64}/g).join('\n') +
                '\n-----END PRIVATE KEY-----';
            this.publicKey = keyPair.publicKey;
            const exportedPubKey = await WebCryptoConfig.getSubtle().exportKey("spki", keyPair.publicKey);
            this.publicKeyPEM = '-----BEGIN PUBLIC KEY-----\n' +
                btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(exportedPubKey)))).match(/.{1,64}/g).join('\n') +
                '\n-----END PUBLIC KEY-----';
        }
        async loadKeyPair(publicKeyPEM, privateKeyPEM) {
            if (privateKeyPEM !== undefined) {
                const privPEMHeader = '-----BEGIN PRIVATE KEY-----';
                const privPEMFooter = '-----END PRIVATE KEY-----';
                const privPEMNoNewlines = privateKeyPEM.replace(/\r?\n|\r/g, '');
                const privPEMContents = privPEMNoNewlines.substring(privPEMHeader.length, privPEMNoNewlines.length - privPEMFooter.length);
                const binaryDerString = atob(privPEMContents);
                const binaryDer = Strings.stingToArrayBuffer(binaryDerString);
                const privateKey = await WebCryptoConfig.getSubtle().importKey('pkcs8', binaryDer, {
                    name: ALGORITHM$1,
                    hash: { name: 'SHA-256' },
                }, true, ['sign']);
                this.privateKeyPEM = privateKeyPEM;
                this.privateKey = privateKey;
            }
            const pemHeader = '-----BEGIN PUBLIC KEY-----';
            const pemFooter = '-----END PUBLIC KEY-----';
            const pemNoNewlines = publicKeyPEM.replace(/\r?\n|\r/g, '');
            const pemContents = pemNoNewlines.substring(pemHeader.length, pemNoNewlines.length - pemFooter.length);
            const binaryDerString = atob(pemContents);
            const binaryDer = Strings.stingToArrayBuffer(binaryDerString);
            const publicKey = await WebCryptoConfig.getSubtle().importKey('spki', binaryDer, {
                name: ALGORITHM$1,
                hash: { name: 'SHA-256' }
            }, true, ['verify']);
            this.publicKeyPEM = publicKeyPEM;
            this.publicKey = publicKey;
        }
        getPublicKey() {
            if (this.publicKeyPEM === undefined) {
                throw new Error('Attempted to export public key, but WebCrypto keypair is uninitialized.');
            }
            return this.publicKeyPEM;
        }
        getPrivateKey() {
            if (this.publicKeyPEM === undefined) {
                throw new Error('Attempted to export private key, but WebCrypto keypair is uninitialized.');
            }
            return this.privateKeyPEM;
        }
        async sign(text) {
            if (this.privateKey === undefined) {
                throw new Error('Attempted to export public key, but WebCrypto keypair is uninitialized.');
            }
            const signBuffer = await WebCryptoConfig.getSubtle().sign({
                name: "RSASSA-PKCS1-v1_5",
            }, this.privateKey, new TextEncoder().encode(text));
            const sign = Strings.Uint8arrayToBase64(new Uint8Array(signBuffer));
            return sign;
        }
        verify(text, signature) {
            if (this.publicKey === undefined) {
                throw new Error('Trying to verify signature with WebCrypto, but keypair is uninitialized');
            }
            let enc = new TextEncoder();
            return WebCryptoConfig.getSubtle().verify({ name: ALGORITHM$1 }, this.publicKey, Strings.base64ToUint8array(signature), enc.encode(text));
        }
    }

    const ALGORITHM = 'RSA-OAEP';
    class WebCryptoRSAEncKP {
        constructor() {
            this.encoder = new TextEncoder();
            this.decoder = new TextDecoder();
        }
        async generateKey(params) {
            const modulusLength = (params === null || params === void 0 ? void 0 : params.b) || 2048;
            const hash = 'SHA-256';
            const keyPair = await WebCryptoConfig.getSubtle().generateKey({
                name: ALGORITHM,
                // Consider using a 4096-bit key for systems that require long-term security
                modulusLength: modulusLength,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: hash,
            }, true, ['encrypt', 'decrypt']);
            this.privateKey = keyPair.privateKey;
            const exportedPrivKey = await WebCryptoConfig.getSubtle().exportKey("pkcs8", keyPair.privateKey);
            this.privateKeyPEM = '-----BEGIN PRIVATE KEY-----\n' +
                btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(exportedPrivKey)))).match(/.{1,64}/g).join('\n') +
                '\n-----END PRIVATE KEY-----';
            this.publicKey = keyPair.publicKey;
            const exportedPubKey = await WebCryptoConfig.getSubtle().exportKey("spki", keyPair.publicKey);
            this.publicKeyPEM = '-----BEGIN PUBLIC KEY-----\n' +
                btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(exportedPubKey)))).match(/.{1,64}/g).join('\n') +
                '\n-----END PUBLIC KEY-----';
        }
        async loadKeyPair(publicKeyPEM, privateKeyPEM) {
            if (privateKeyPEM !== undefined) {
                const privPEMHeader = '-----BEGIN PRIVATE KEY-----';
                const privPEMFooter = '-----END PRIVATE KEY-----';
                const privPEMNoNewlines = privateKeyPEM.replace(/\r?\n|\r/g, '');
                const privPEMContents = privPEMNoNewlines.substring(privPEMHeader.length, privPEMNoNewlines.length - privPEMFooter.length);
                const binaryDerString = atob(privPEMContents);
                const binaryDer = Strings.stingToArrayBuffer(binaryDerString);
                const privateKey = await WebCryptoConfig.getSubtle().importKey('pkcs8', binaryDer, {
                    name: ALGORITHM,
                    hash: 'SHA-256',
                }, true, ['decrypt']);
                this.privateKeyPEM = privateKeyPEM;
                this.privateKey = privateKey;
            }
            const pemHeader = '-----BEGIN PUBLIC KEY-----';
            const pemFooter = '-----END PUBLIC KEY-----';
            const pemNoNewlines = publicKeyPEM.replace(/\r?\n|\r/g, '');
            const pemContents = pemNoNewlines.substring(pemHeader.length, pemNoNewlines.length - pemFooter.length);
            const binaryDerString = atob(pemContents);
            const binaryDer = Strings.stingToArrayBuffer(binaryDerString);
            const publicKey = await WebCryptoConfig.getSubtle().importKey('spki', binaryDer, {
                name: ALGORITHM,
                hash: { name: 'SHA-256' }
            }, true, ['encrypt']);
            this.publicKeyPEM = publicKeyPEM;
            this.publicKey = publicKey;
        }
        getPublicKey() {
            if (this.publicKeyPEM === undefined) {
                throw new Error('Attempted to export public key, but WebCrypto keypair is uninitialized.');
            }
            return this.publicKeyPEM;
        }
        getPrivateKey() {
            if (this.publicKeyPEM === undefined) {
                throw new Error('Attempted to export private key, but WebCrypto keypair is uninitialized.');
            }
            return this.privateKeyPEM;
        }
        async encrypt(plainText) {
            if (this.publicKey === undefined) {
                throw new Error('Trying to encrypt with WebCrypto, but keypair is uninitialized');
            }
            const cypherBuf = await WebCryptoConfig.getSubtle().encrypt({
                name: ALGORITHM
            }, this.publicKey, this.encoder.encode(plainText));
            const cypherUint = new Uint8Array(cypherBuf);
            const cypher = Strings.Uint8arrayToBase64(cypherUint);
            return cypher;
        }
        async decrypt(cypherText) {
            if (this.privateKey === undefined) {
                throw new Error('Trying to decrypt with WebCrypto, but private key is missing');
            }
            const cypherTextRaw = atob(cypherText);
            const cypherTextBuffer = Strings.stingToArrayBuffer(cypherTextRaw);
            const plain = await WebCryptoConfig.getSubtle().decrypt({ name: ALGORITHM }, this.privateKey, cypherTextBuffer);
            return this.decoder.decode(plain);
        }
    }

    class DelegatingRSAImpl {
        constructor(encKeyPair, signKeyPair) {
            this.encKeyPair = encKeyPair;
            this.signKeyPair = signKeyPair;
            this.initialized = false;
        }
        async generateKey(bits) {
            await this.signKeyPair.generateKey({ b: bits });
            await this.encKeyPair.loadKeyPair(this.signKeyPair.getPublicKey(), this.signKeyPair.getPrivateKey());
            this.initialized = true;
        }
        async loadKeyPair(publicKey, privateKey) {
            if (this.initialized) {
                throw new Error('RSA key cannot be re-initialized.');
            }
            await this.signKeyPair.loadKeyPair(publicKey, privateKey);
            await this.encKeyPair.loadKeyPair(publicKey, privateKey);
            this.initialized = true;
        }
        getPublicKey() {
            if (!this.initialized) {
                throw new Error('Trying to retrieve public key from uninitialized WebCrypto RSA KeyPair wrapper.');
            }
            return this.signKeyPair.getPublicKey();
        }
        getPrivateKey() {
            if (!this.initialized) {
                throw new Error('Trying to retrieve private key from uninitialized WebCrypto RSA KeyPair wrapper.');
            }
            return this.signKeyPair.getPrivateKey();
        }
        async sign(text) {
            var _a;
            if (!this.initialized) {
                throw new Error('Trying to create signature using uninitialized WebCrypto RSA KeyPair wrapper.');
            }
            return (_a = this.signKeyPair) === null || _a === void 0 ? void 0 : _a.sign(text);
        }
        async verify(text, signature) {
            if (!this.initialized) {
                throw new Error('Trying to verify signature using uninitialized WebCrypto RSA KeyPair wrapper.');
            }
            return this.signKeyPair.verify(text, signature);
        }
        async encrypt(plainText) {
            if (!this.initialized) {
                throw new Error('Trying to encrypt using uninitialized WebCrypto RSA KeyPair wrapper.');
            }
            return this.encKeyPair.encrypt(plainText);
        }
        async decrypt(cypherText) {
            if (!this.initialized) {
                throw new Error('Trying to decrypt using uninitialized WebCrypto RSA KeyPair wrapper.');
            }
            return this.encKeyPair.decrypt(cypherText);
        }
    }

    class WebCryptoRSA extends DelegatingRSAImpl {
        constructor() {
            super(new WebCryptoRSAEncKP(), new WebCryptoRSASigKP);
        }
    }

    //import { JSEncryptRSA } from './JSEncryptRSA';
    class RSADefaults {
    }
    //static impl: new () => RSA = globalThis?.crypto?.subtle !== undefined ? WebCryptoRSA : NodeRSA;
    RSADefaults.impl = WebCryptoRSA;

    var nanoassert = assert$1;

    class AssertionError extends Error {}
    AssertionError.prototype.name = 'AssertionError';

    /**
     * Minimal assert function
     * @param  {any} t Value to check if falsy
     * @param  {string=} m Optional assertion error message
     * @throws {AssertionError}
     */
    function assert$1 (t, m) {
      if (!t) {
        var err = new AssertionError(m);
        if (Error.captureStackTrace) Error.captureStackTrace(err, assert$1);
        throw err
      }
    }

    const assert = nanoassert;

    var chacha20Universal = Chacha20;

    const constant = [1634760805, 857760878, 2036477234, 1797285236];

    function Chacha20 (nonce, key, counter) {
      assert(key.byteLength === 32);
      assert(nonce.byteLength === 8 || nonce.byteLength === 12);

      const n = new Uint32Array(nonce.buffer, nonce.byteOffset, nonce.byteLength / 4);
      const k = new Uint32Array(key.buffer, key.byteOffset, key.byteLength / 4);

      if (!counter) counter = 0;
      assert(counter < Number.MAX_SAFE_INTEGER);

      this.finalized = false;
      this.pos = 0;
      this.state = new Uint32Array(16);

      for (let i = 0; i < 4; i++) this.state[i] = constant[i];
      for (let i = 0; i < 8; i++) this.state[4 + i] = k[i];

      this.state[12] = counter & 0xffffffff;

      if (n.byteLength === 8) {
        this.state[13] = (counter && 0xffffffff00000000) >> 32;
        this.state[14] = n[0];
        this.state[15] = n[1];
      } else {
        this.state[13] = n[0];
        this.state[14] = n[1];
        this.state[15] = n[2];
      }

      return this
    }

    Chacha20.prototype.update = function (output, input) {
      assert(!this.finalized, 'cipher finalized.');
      assert(output.byteLength >= input.byteLength,
        'output cannot be shorter than input.');

      let len = input.length;
      let offset = this.pos % 64;
      this.pos += len;

      // input position
      let j = 0;

      let keyStream = chacha20Block(this.state);

      // try to finsih the current block
      while (offset > 0 && len > 0) {
        output[j] = input[j++] ^ keyStream[offset];
        offset = (offset + 1) & 0x3f;
        if (!offset) this.state[12]++;
        len--;
      }

      // encrypt rest block at a time
      while (len > 0) {
        keyStream = chacha20Block(this.state);

        // less than a full block remaining
        if (len < 64) {
          for (let i = 0; i < len; i++) {
            output[j] = input[j++] ^ keyStream[offset++];
            offset &= 0x3f;
          }

          return
        }

        for (; offset < 64;) {
          output[j] = input[j++] ^ keyStream[offset++];
        }

        this.state[12]++;
        offset = 0;
        len -= 64;
      }
    };

    Chacha20.prototype.final = function () {
      this.state.fill(0);
      this.pos = 0;
      this.finalized = true;
    };

    function chacha20Block (state) {
      // working state
      const ws = new Uint32Array(16);
      for (let i = 16; i--;) ws[i] = state[i];

      for (let i = 0; i < 20; i += 2) {
        QR(ws, 0, 4, 8, 12); // column 0
        QR(ws, 1, 5, 9, 13); // column 1
        QR(ws, 2, 6, 10, 14); // column 2
        QR(ws, 3, 7, 11, 15); // column 3

        QR(ws, 0, 5, 10, 15); // diagonal 1 (main diagonal)
        QR(ws, 1, 6, 11, 12); // diagonal 2
        QR(ws, 2, 7, 8, 13); // diagonal 3
        QR(ws, 3, 4, 9, 14); // diagonal 4
      }

      for (let i = 0; i < 16; i++) {
        ws[i] += state[i];
      }

      return new Uint8Array(ws.buffer, ws.byteOffset, ws.byteLength)
    }

    function rotl (a, b) {
      return ((a << b) | (a >>> (32 - b)))
    }

    function QR (obj, a, b, c, d) {
      obj[a] += obj[b];
      obj[d] ^= obj[a];
      obj[d] = rotl(obj[d], 16);

      obj[c] += obj[d];
      obj[b] ^= obj[c];
      obj[b] = rotl(obj[b], 12);

      obj[a] += obj[b];
      obj[d] ^= obj[a];
      obj[d] = rotl(obj[d], 8);

      obj[c] += obj[d];
      obj[b] ^= obj[c];
      obj[b] = rotl(obj[b], 7);
    }

    //var chacha = require('chacha20-universal');
    class ChaCha20Universal {
        encryptHex(message, key, nonce) {
            let keyBuf = Buffer.from(key, 'hex');
            let nonceBuf = Buffer.from(nonce, 'hex');
            return this.encrypt(message, keyBuf, nonceBuf, 'utf8', 'hex');
        }
        decryptHex(ciphertext, key, nonce) {
            let keyBuf = Buffer.from(key, 'hex');
            let nonceBuf = Buffer.from(nonce, 'hex');
            return this.decrypt(ciphertext, keyBuf, nonceBuf, 'hex', 'utf8');
        }
        encryptBase64(message, key, nonce) {
            let keyBuf = Buffer.from(Strings.base64toHex(key), 'hex');
            let nonceBuf = Buffer.from(Strings.base64toHex(nonce), 'hex');
            return this.encrypt(message, keyBuf, nonceBuf, 'utf8', 'base64');
        }
        decryptBase64(ciphertext, key, nonce) {
            let keyBuf = Buffer.from(Strings.base64toHex(key), 'hex');
            let nonceBuf = Buffer.from(Strings.base64toHex(nonce), 'hex');
            return this.decrypt(ciphertext, keyBuf, nonceBuf, 'base64', 'utf8');
        }
        encrypt(message, key, nonce, inputFmt, outputFmt) {
            let cipher = new chacha20Universal(nonce, key);
            let input = Buffer.from(message, inputFmt);
            let output = Buffer.alloc(input.byteLength);
            cipher.update(output, input);
            cipher.final();
            return output.toString(outputFmt);
        }
        decrypt(message, key, nonce, inputFmt, outputFmt) {
            let decipher = new chacha20Universal(nonce, key);
            let input = Buffer.from(message, inputFmt);
            let output = Buffer.alloc(input.byteLength);
            decipher.update(output, input);
            decipher.final();
            return output.toString(outputFmt);
        }
    }

    class RSAPublicKey extends HashedObject {
        constructor() {
            super();
        }
        static fromKeys(publicKey) {
            let pk = new RSAPublicKey();
            pk.publicKey = publicKey;
            pk.init();
            return pk;
        }
        init() {
            this._rsaPromise = this.initRSA();
        }
        async initRSA() {
            const _rsa = new RSADefaults.impl();
            await _rsa.loadKeyPair(this.getPublicKey());
            return _rsa;
        }
        async validate() {
            // TODO: self sign??
            return true;
        }
        getClassName() {
            return RSAPublicKey.className;
        }
        getPublicKey() {
            return this.publicKey;
        }
        getKeyPairHash() {
            return RSAKeyPair.hashPublicKeyPart(this.publicKey);
        }
        async verifySignature(text, signature) {
            if (this._rsaPromise === undefined) {
                throw new Error('RSA public key is empty, cannot verify signature');
            }
            return (await this._rsaPromise).verify(text, signature);
        }
        async encrypt(plainText) {
            if (this._rsaPromise === undefined) {
                throw new Error('RSA public key is empty, cannot encrypt');
            }
            return (await this._rsaPromise).encrypt(plainText);
        }
    }
    RSAPublicKey.className = 'hhs/v0/RSAPublicKey';
    HashedObject.registerClass(RSAPublicKey.className, RSAPublicKey);

    // Note: this classs uses a custom hash function that omits the private key,
    //       using only the public part, thus allowing a public key to generate
    //       the hash of its corresponding key-pair.
    //       Since only the public key is verified by the hash, we also self-sign
    //       the private key, a signature that can be verified using the public
    //       key (that was hashed).
    class RSAKeyPair extends HashedObject {
        constructor() {
            super();
        }
        static async generate(bits) {
            let rsa = new RSADefaults.impl();
            await rsa.generateKey(bits);
            return RSAKeyPair.fromKeys(rsa.getPublicKey(), rsa.getPrivateKey());
        }
        static async fromKeys(publicKey, privateKey) {
            let keyPair = new RSAKeyPair();
            keyPair.publicKey = publicKey;
            keyPair.privateKey = privateKey;
            keyPair.init();
            await keyPair.selfSign();
            return keyPair;
        }
        init() {
            this._rsaPromise = this.initRSA();
        }
        async validate() {
            return this.checkSelfSignature();
        }
        async initRSA() {
            const _rsa = new RSADefaults.impl();
            await _rsa.loadKeyPair(this.getPublicKey(), this.getPrivateKey());
            return _rsa;
        }
        async selfSign() {
            if (this._rsaPromise === undefined) {
                throw new Error('Attempting to self sign keypair, but RSA has not been initialized.');
            }
            this.privateKeySignature = await (await this._rsaPromise).sign(this.privateKey);
        }
        checkSelfSignature() {
            return this.makePublicKey().verifySignature(this.privateKey, this.privateKeySignature);
        }
        getClassName() {
            return RSAKeyPair.className;
        }
        customHash(seed) {
            return RSAKeyPair.hashPublicKeyPart(this.publicKey, seed);
        }
        getPublicKey() {
            return this.publicKey;
        }
        getPrivateKey() {
            return this.privateKey;
        }
        makePublicKey() {
            return RSAPublicKey.fromKeys(this.getPublicKey());
        }
        async sign(text) {
            if (this._rsaPromise === undefined) {
                throw new Error('Attempting to create signature, but RSA has not been initialized.');
            }
            return (await this._rsaPromise).sign(text);
        }
        async verifySignature(text, signature) {
            if (this._rsaPromise === undefined) {
                throw new Error('Attempting to verify signature, but RSA has not been initialized.');
            }
            return (await this._rsaPromise).verify(text, signature);
        }
        async encrypt(plainText) {
            if (this._rsaPromise === undefined) {
                throw new Error('Attempting to encrypt, but RSA has not been initialized.');
            }
            return (await this._rsaPromise).encrypt(plainText);
        }
        async decrypt(cypherText) {
            if (this._rsaPromise === undefined) {
                throw new Error('Attempting to decrypt, but RSA has not been initialized.');
            }
            return (await this._rsaPromise).decrypt(cypherText);
        }
        static hashPublicKeyPart(publicKey, seed) {
            return Hashing.forValue({ '_type': 'custom_hashed_object', '_class': RSAKeyPair.className, '_contents': { 'publicKey': publicKey } }, seed);
        }
    }
    RSAKeyPair.className = 'hhs/v0/RSAKeyPair';
    HashedObject.registerClass(RSAKeyPair.className, RSAKeyPair);

    class OpHeader {
        constructor(opOrLiteral, prevOpHeaders) {
            var _a;
            if (opOrLiteral instanceof MutationOp) {
                const op = opOrLiteral;
                this.opHash = op.hash();
                if (prevOpHeaders === undefined) {
                    throw new Error('Parameter prevOpCausalHistories is mandatory to create an OpCausalHistory from a MutationOp');
                }
                if (op.prevOps === undefined) {
                    throw new Error('Operation has no prevOps (they are undefined)');
                }
                this.prevOpHeaders = new Set();
                for (const prevOpRef of (_a = op.prevOps) === null || _a === void 0 ? void 0 : _a.values()) {
                    const opHeader = prevOpHeaders.get(prevOpRef.hash);
                    if (opHeader === undefined) {
                        throw new Error('Cannot create header for op ' + op.hash() + ', causal history for prevOp ' + prevOpRef.hash + ' is missing.');
                    }
                    this.prevOpHeaders.add(opHeader.headerHash);
                }
                this.headerProps = op.getHeaderProps(prevOpHeaders);
                if (prevOpHeaders === undefined) {
                    throw new Error('Cannot create OpCausalHistory for op, prevOpCausalHistories is missing.');
                }
                else {
                    this.computedProps = OpHeader.computeProps(prevOpHeaders);
                }
                this.headerHash = this.hash();
            }
            else {
                const literal = opOrLiteral;
                OpHeader.checkLiteralFormat(literal);
                this.headerHash = literal.headerHash;
                this.opHash = literal.opHash;
                this.prevOpHeaders = new Set(literal.prevOpHeaders);
                this.headerProps = new Map();
                if (literal.headerProps !== undefined) {
                    for (const key of Object.keys(literal.headerProps)) {
                        this.headerProps.set(key, literal.headerProps[key]);
                    }
                }
                this.computedProps = { height: literal.computedHeight, size: literal.computedSize };
                if (this.hash() !== literal.headerHash) {
                    throw new Error('Received OpCausalHistory literal has wrong hash');
                }
            }
        }
        verifyOpMatch(op, prevOpCausalHistories) {
            if (op.hash() !== this.opHash) {
                return false;
            }
            const receivedProps = new HashedMap();
            for (const [propName, propVal] of op.getHeaderProps(prevOpCausalHistories).entries()) {
                receivedProps.set(propName, propVal);
            }
            const expectedProps = new HashedMap();
            for (const [propName, propVal] of this.headerProps.entries()) {
                expectedProps.set(propName, propVal);
            }
            if (!receivedProps.equals(expectedProps)) {
                return false;
            }
            const receivedHistories = new HashedSet();
            for (const prevOpRef of op.getPrevOps()) {
                const prevOpHistory = prevOpCausalHistories.get(prevOpRef.hash);
                if (prevOpHistory === undefined) {
                    return false;
                }
                receivedHistories.add(prevOpHistory.headerHash);
            }
            const expectedHistories = new HashedSet(this.prevOpHeaders.values());
            if (!receivedHistories.equals(expectedHistories)) {
                return false;
            }
            const computed = OpHeader.computeProps(prevOpCausalHistories);
            if (computed.size !== this.computedProps.size || computed.height !== this.computedProps.height) {
                return false;
            }
            return true;
        }
        hash() {
            const sortedCausalHistoryHashes = Array.from(this.prevOpHeaders.values());
            sortedCausalHistoryHashes.sort();
            const p = {};
            for (const propName of Object.keys(this.headerProps)) {
                p[propName] = this.headerProps.get(propName);
            }
            return Hashing.forValue({ opHash: this.opHash, history: sortedCausalHistoryHashes, props: p, computedProps: this.computedProps });
        }
        literalize() {
            const literal = {
                headerHash: this.headerHash,
                opHash: this.opHash,
                prevOpHeaders: Array.from(this.prevOpHeaders),
                computedHeight: this.computedProps.height,
                computedSize: this.computedProps.size
            };
            if (this.headerProps.size > 0) {
                literal.headerProps = {};
                for (const [key, val] of this.headerProps.entries()) {
                    literal.headerProps[key] = val;
                }
            }
            return literal;
        }
        static computeProps(prevOpCausalHistories) {
            let height = 1;
            let size = 1;
            for (const prevOpHistory of prevOpCausalHistories.values()) {
                if (prevOpHistory instanceof OpHeader && prevOpHistory.computedProps !== undefined) {
                    if (prevOpHistory.computedProps.height + 1 > height) {
                        height = prevOpHistory.computedProps.height + 1;
                    }
                    size = size + prevOpHistory.computedProps.size;
                }
                else {
                    throw new Error('Missing prevOpCausalHistories, cannot create OpCausalHistory object.');
                }
            }
            return { height: height, size: size };
        }
        static checkLiteralFormat(literal) {
            const propTypes = { headerHash: 'string', opHash: 'string', prevOpHeaders: 'object', computedHeight: 'number', computedSize: 'number' };
            for (const propName of ['headerHash', 'opHash', 'prevOpHeaders']) {
                const prop = literal[propName];
                if (prop === undefined) {
                    throw new Error('OpHeader literal is missing property: ' + propName);
                }
                if (typeof (prop) !== propTypes[propName]) {
                    throw new Error('OpHeader literal property ' + propName + ' has the wrong type, expected ' + propTypes[propName] + ' but found ' + typeof (prop));
                }
            }
            if (!Array.isArray(literal.prevOpHeaders)) {
                throw new Error('OpHeader prevOpHeaders should be an array');
            }
            for (const hash of literal.prevOpHeaders) {
                if (typeof (hash) !== 'string') {
                    throw new Error('OpHeader prevOpHeaders should contain only strings, found ' + typeof (hash) + ' instead');
                }
            }
            if (literal.headerProps !== undefined) {
                if (typeof (literal.headerProps) !== 'object') {
                    throw new Error('OpHeader literal property headerProps has the wrong type, expected object but found ' + typeof (literal.headerProps));
                }
                const keys = Object.keys(literal.headerProps);
                if (keys.length === 0) {
                    throw new Error('OpCausalHistory literal property opProps is empty, it should either be missing altogether or be non-empty.');
                }
                const customPropTypes = ['string', 'number'];
                for (const customPropName of Object.keys(literal.headerProps)) {
                    if (customPropTypes.indexOf(typeof (literal.headerProps[customPropName])) < 0) {
                        throw new Error('Unexpected type found in OpCausalHistory literal opProps: ' + typeof (literal.headerProps[customPropName] + ' (expected string or number)'));
                    }
                }
            }
            if (Object.keys(literal).length !== Object.keys(propTypes).length + (literal.headerProps === undefined ? 0 : 1)) {
                throw new Error('OpHeader literal has more properties than it should');
            }
        }
    }

    class MutationOp extends HashedObject {
        constructor(targetObject) {
            super();
            if (targetObject !== undefined) {
                this.targetObject = targetObject;
            }
        }
        async validate(references) {
            if (this.targetObject === undefined) {
                return false;
            }
            if (!(this.targetObject instanceof MutableObject)) {
                return false;
            }
            if (this.prevOps === undefined) {
                return false;
            }
            if (!(this.prevOps instanceof HashedSet)) {
                return false;
            }
            for (const prevOpRef of this.prevOps.values()) {
                const prevOp = references.get(prevOpRef.hash);
                if (prevOp === undefined) {
                    return false;
                }
                else if (!(prevOp instanceof MutationOp)) {
                    return false;
                }
                else if (!prevOp.targetObject.equals(this.targetObject)) {
                    return false;
                }
            }
            if (!this.targetObject.supportsUndo() && this.causalOps !== undefined) {
                return false;
            }
            if (this.causalOps !== undefined) {
                if (!(this.causalOps instanceof HashedSet)) {
                    return false;
                }
                for (const causalOp of this.causalOps.values()) {
                    if (causalOp === undefined) {
                        return false;
                    }
                    else if (!(causalOp instanceof MutationOp)) {
                        return false;
                    }
                }
            }
            if (!this.targetObject.shouldAcceptMutationOp(this, references)) {
                return false;
            }
            return true;
        }
        setCausalOps(causalOps) {
            this.causalOps = new HashedSet(causalOps);
            if (this.causalOps.size() === 0) {
                this.causalOps = undefined;
            }
        }
        getCausalOps() {
            if (this.causalOps === undefined) {
                throw new Error('Called getCausalOps, but this.causalOps is undefined.');
            }
            return this.causalOps;
        }
        addCausalOp(causalOp) {
            if (this.causalOps === undefined) {
                this.causalOps = new HashedSet([causalOp].values());
            }
            else {
                this.causalOps.add(causalOp);
            }
        }
        getTargetObject() {
            return this.targetObject;
        }
        setTargetObject(target) {
            this.targetObject = target;
        }
        getPrevOps() {
            return this.prevOps.values();
        }
        getPrevOpsIfPresent() {
            if (this.prevOps === undefined) {
                return undefined;
            }
            else {
                return this.prevOps.values();
            }
        }
        setPrevOps(prevOps) {
            this.prevOps = new HashedSet(Array.from(prevOps).map((op) => op.createReference()).values());
        }
        literalizeInContext(context, path, flags) {
            if (flags === undefined) {
                flags = [];
            }
            flags.push('op');
            return super.literalizeInContext(context, path, flags);
        }
        getHeader(prevOpHeaders) {
            return new OpHeader(this, prevOpHeaders);
        }
        getHeaderProps(prevOpHeaders) {
            return new Map();
        }
        hasCausalOps() {
            return this.causalOps !== undefined;
        }
        nonCausalHash() {
            const currentCausalOps = this.causalOps;
            this.causalOps = undefined;
            const nonCausalHash = this.hash();
            this.causalOps = currentCausalOps;
            return nonCausalHash;
        }
    }

    var LogLevel;
    (function (LogLevel) {
        LogLevel[LogLevel["TRACE"] = 0] = "TRACE";
        LogLevel[LogLevel["DEBUG"] = 1] = "DEBUG";
        LogLevel[LogLevel["INFO"] = 2] = "INFO";
        LogLevel[LogLevel["WARNING"] = 3] = "WARNING";
        LogLevel[LogLevel["ERROR"] = 4] = "ERROR";
    })(LogLevel || (LogLevel = {}));
    class Logger {
        constructor(className, level = LogLevel.INFO) {
            this.className = className;
            this.level = level;
        }
        setLevel(level) {
            this.level = level;
        }
        trace(msg, obj) { this.log(msg, LogLevel.TRACE, obj); }
        debug(msg, obj) { this.log(msg, LogLevel.DEBUG, obj); }
        info(msg, obj) { this.log(msg, LogLevel.INFO, obj); }
        warning(msg, obj) { this.log(msg, LogLevel.WARNING, obj); }
        error(msg, obj) { this.log(msg, LogLevel.ERROR, obj); }
        log(msg, level, obj) {
            if (level >= this.level) {
                let className = 'Not within class';
                if (this.className)
                    className = this.className;
                const d = new Date();
                if (typeof (msg) === 'function') {
                    msg = msg();
                }
                console.log('[' + className + ' ' + d.getHours() + ':' + d.getMinutes() + ' ' + d.getSeconds() + '.' + d.getMilliseconds().toString().padStart(3, '0') + ']: ' + msg);
                if (obj !== undefined) {
                    console.log(obj);
                }
                if (level >= LogLevel.WARNING) {
                    var err = new Error();
                    console.log(err.stack);
                }
            }
            else if (this.chained !== undefined) {
                // in case another logger in the chain has a more verbose log level.
                this.chained.log(msg, level);
            }
        }
        chain(logger) {
            this.chained = logger;
        }
    }

    class PeeringAgentBase {
        constructor(peerGroupAgent) {
            this.peerGroupAgent = peerGroupAgent;
        }
        receiveLocalEvent(ev) {
        }
        getPeerControl() {
            return this.peerGroupAgent;
        }
        sendMessageToPeer(destination, agentId, content) {
            if (content === undefined) {
                throw new Error('Missing message content');
            }
            return this.peerGroupAgent.sendToPeer(destination, agentId, content);
        }
        sendingQueueToPeerIsEmpty(destination) {
            return this.peerGroupAgent.peerSendBufferIsEmpty(destination);
        }
    }

    var AgentPodEventType;
    (function (AgentPodEventType) {
        AgentPodEventType["AgentSetChange"] = "agent-set-change";
        AgentPodEventType["ConnectionStatusChange"] = "connection-status-change";
        AgentPodEventType["RemoteAddressListening"] = "remote-address-listening";
    })(AgentPodEventType || (AgentPodEventType = {}));
    exports.AgentSetChange = void 0;
    (function (AgentSetChange) {
        AgentSetChange["Addition"] = "addition";
        AgentSetChange["Removal"] = "removal";
    })(exports.AgentSetChange || (exports.AgentSetChange = {}));
    class AgentPod {
        constructor() {
            this.agents = new Map();
        }
        // locally running agent set management
        registerAgent(agent) {
            this.agents.set(agent.getAgentId(), agent);
            agent.ready(this);
            const ev = {
                type: AgentPodEventType.AgentSetChange,
                content: {
                    agentId: agent.getAgentId(),
                    change: exports.AgentSetChange.Addition
                }
            };
            this.broadcastEvent(ev);
        }
        deregisterAgent(agent) {
            this.deregisterAgentById(agent.getAgentId());
        }
        deregisterAgentById(id) {
            let agent = this.agents.get(id);
            if (agent !== undefined) {
                const ev = {
                    type: AgentPodEventType.AgentSetChange,
                    content: {
                        agentId: id,
                        change: exports.AgentSetChange.Removal
                    }
                };
                this.broadcastEvent(ev);
                agent.shutdown();
                this.agents.delete(id);
            }
        }
        getAgent(id) {
            return this.agents.get(id);
        }
        getAgentIdSet() {
            return new Set(this.agents.keys());
        }
        // send an event that will be received by all local agents
        broadcastEvent(ev) {
            AgentPod.logger.trace('EventPod broadcasting event ' + ev.type + ' with content ' + JSON.stringify(ev.content));
            for (const agent of this.agents.values()) {
                agent.receiveLocalEvent(ev);
            }
        }
        shutdown() {
            for (const agent of this.agents.values()) {
                agent.shutdown();
            }
        }
    }
    AgentPod.logger = new Logger(AgentPod.name, LogLevel.INFO);

    class Shuffle {
        static array(arr) {
            let idx = arr.length;
            while (0 !== idx) {
                let rndIdx = Math.floor(Math.random() * idx);
                idx -= 1;
                // swap
                let tmp = arr[idx];
                arr[idx] = arr[rndIdx];
                arr[rndIdx] = tmp;
            }
        }
    }

    class LinkupAddress {
        constructor(serverURL, linkupId) {
            if (serverURL[serverURL.length - 1] === '/') {
                serverURL = serverURL.substring(0, serverURL.length - 1);
            }
            this.serverURL = serverURL;
            this.linkupId = linkupId;
        }
        url() {
            return this.serverURL + '/' + this.linkupId;
        }
        static fromURL(url) {
            if (url[url.length - 1] === '/') {
                url = url.substring(0, url.length - 1);
            }
            let urlParts = url.split('/');
            let linkupId = urlParts.pop();
            urlParts.push('');
            let serverUrl = urlParts.join('/');
            return new LinkupAddress(serverUrl, linkupId);
        }
    }

    const CONN_BACKOFF_TIME = 15000;
    class SignallingServerConnection {
        constructor(serverURL) {
            if (!SignallingServerConnection.isWebRTCBased(serverURL)) {
                throw new Error('LinkupServerConnection expects a URL that starts with "' + SignallingServerConnection.WRTC_URL_PREFIX + '", bailing out.');
            }
            this.serverURL = serverURL;
            this.ws = null;
            this.rawMessageCallbacks = new Map();
            this.newCallMessageCallbacks = new Map();
            this.messageCallbacks = new Map();
            this.linkupIdsToListen = new Set();
            this.messageQueue = [];
            this.checkWebsocket();
        }
        static isWebRTCBased(serverURL) {
            return serverURL.startsWith(SignallingServerConnection.WRTC_URL_PREFIX);
        }
        static getRealServerURL(serverURL) {
            return serverURL.slice(SignallingServerConnection.WRTC_URL_PREFIX.length);
        }
        listenForMessagesNewCall(recipient, callback) {
            if (recipient.serverURL !== this.serverURL) {
                let e = new Error('Trying to listen for calls to ' +
                    recipient.serverURL +
                    ' but this is a connection to ' +
                    this.serverURL);
                SignallingServerConnection.logger.error(e);
                throw e;
            }
            let recipientCallCallbacks = this.newCallMessageCallbacks.get(recipient.linkupId);
            if (recipientCallCallbacks === undefined) {
                recipientCallCallbacks = new Set();
                this.newCallMessageCallbacks.set(recipient.linkupId, recipientCallCallbacks);
            }
            recipientCallCallbacks.add(callback);
            this.setUpListenerIfNew(recipient.linkupId);
        }
        listenForRawMessages(recipient, callback) {
            if (recipient.serverURL !== this.serverURL) {
                let e = new Error('Trying to listen for raw messages to server ' +
                    recipient.serverURL +
                    ' but this is a connection to ' +
                    this.serverURL);
                SignallingServerConnection.logger.error(e);
                throw e;
            }
            let recipientRawCallbacks = this.rawMessageCallbacks.get(recipient.linkupId);
            if (recipientRawCallbacks === undefined) {
                recipientRawCallbacks = new Set();
                this.rawMessageCallbacks.set(recipient.linkupId, recipientRawCallbacks);
            }
            recipientRawCallbacks.add(callback);
            this.setUpListenerIfNew(recipient.linkupId);
        }
        listenForMessagesOnCall(recipient, callId, callback) {
            if (recipient.serverURL !== this.serverURL) {
                let e = new Error('Trying to listen for messages to ' +
                    recipient.serverURL +
                    ' but this is a connection to ' +
                    this.serverURL);
                SignallingServerConnection.logger.error(e);
                throw e;
            }
            let linkupIdCalls = this.messageCallbacks.get(recipient.linkupId);
            if (linkupIdCalls === undefined) {
                linkupIdCalls = new Map();
                this.messageCallbacks.set(recipient.linkupId, linkupIdCalls);
            }
            let messageCallbacks = linkupIdCalls.get(callId);
            if (messageCallbacks === undefined) {
                messageCallbacks = new Set();
                linkupIdCalls.set(callId, messageCallbacks);
            }
            messageCallbacks.add(callback);
            this.setUpListenerIfNew(recipient.linkupId);
        }
        listenForLinkupAddressQueries(callback) {
            this.listeningAddressesQueryCallback = callback;
        }
        sendMessage(sender, recipient, callId, data) {
            if (recipient.serverURL !== this.serverURL) {
                let e = new Error('Trying to send a linkup message to ' +
                    recipient.serverURL +
                    ' but this is a connection to ' +
                    this.serverURL);
                SignallingServerConnection.logger.error(e);
                throw e;
            }
            var message = {
                'action': 'send',
                'linkupId': recipient.linkupId,
                'callId': callId,
                'data': data,
                'replyServerUrl': sender.serverURL,
                'replyLinkupId': sender.linkupId,
            };
            this.enqueueAndSend(JSON.stringify(message));
        }
        sendRawMessage(sender, recipient, data, sendLimit) {
            if (recipient.serverURL !== this.serverURL) {
                let e = new Error('Trying to send a linkup message to ' +
                    recipient.serverURL +
                    ' but this is a connection to ' +
                    this.serverURL);
                SignallingServerConnection.logger.error(e);
                throw e;
            }
            var message = {
                'action': 'send',
                'linkupId': recipient.linkupId,
                'raw': 'true',
                'data': data,
                'replyServerUrl': sender.serverURL,
                'replyLinkupId': sender.linkupId,
            };
            if (sendLimit !== undefined) {
                message['limit'] = sendLimit;
            }
            this.enqueueAndSend(JSON.stringify(message));
        }
        sendListeningAddressesQuery(queryId, addresses) {
            let linkupIds = new Array();
            for (const address of addresses) {
                if (address.serverURL !== this.serverURL) {
                    let e = new Error('Trying to send an address query for ' +
                        address.serverURL +
                        ' but this is a connection to ' +
                        this.serverURL);
                    SignallingServerConnection.logger.error(e);
                    throw e;
                }
                linkupIds.push(address.linkupId);
            }
            var message = {
                'action': 'query',
                'linkupIds': linkupIds,
                'queryId': queryId
            };
            this.enqueueAndSend(JSON.stringify(message));
        }
        checkWebsocket() {
            if (this.ws !== null && this.ws.readyState === WebSocket.OPEN) {
                return true;
            }
            else {
                if ((this.ws === null ||
                    (this.ws.readyState === WebSocket.CLOSING ||
                        this.ws.readyState === WebSocket.CLOSED))
                    &&
                        (this.lastConnectionAttempt === undefined ||
                            (Date.now() > this.lastConnectionAttempt + CONN_BACKOFF_TIME))) {
                    this.lastConnectionAttempt = Date.now();
                    SignallingServerConnection.logger.debug('creating websocket to server ' + this.serverURL);
                    try {
                        this.ws = new WebSocket(SignallingServerConnection.getRealServerURL(this.serverURL));
                    }
                    catch (e) {
                        this.ws = null;
                        SignallingServerConnection.logger.warning('Unexpected error while creating websocket to signalling server ' + this.serverURL);
                        SignallingServerConnection.logger.error(e);
                    }
                    if (this.ws !== null) {
                        this.ws.onmessage = (ev) => {
                            const message = JSON.parse(ev.data);
                            const ws = this.ws;
                            if (message['action'] === 'ping') {
                                SignallingServerConnection.logger.trace('sending pong to ' + this.serverURL);
                                if (this.ws !== null && this.ws.readyState === this.ws.OPEN) {
                                    try {
                                        ws.send(JSON.stringify({ 'action': 'pong' }));
                                    }
                                    catch (e) {
                                        SignallingServerConnection.logger.warning('Error while sending pong to ' + this.serverURL, e);
                                    }
                                }
                                else {
                                    SignallingServerConnection.logger.debug('not sending pong to ' + this.serverURL + ': connection is not open');
                                }
                            }
                            else if (message['action'] === 'send') {
                                const linkupId = message['linkupId'];
                                const callId = message['callId'];
                                const raw = message['raw'];
                                if (callId !== undefined) {
                                    const linkupIdCalls = this.messageCallbacks.get(linkupId);
                                    let found = false;
                                    if (linkupIdCalls !== undefined) {
                                        let callMessageCallbacks = linkupIdCalls.get(callId);
                                        if (callMessageCallbacks !== undefined) {
                                            callMessageCallbacks.forEach((callback) => {
                                                SignallingServerConnection.logger.debug('Delivering linkup message to ' + linkupId + ' on call ' + message['callId']);
                                                callback(message['data']);
                                                found = true;
                                            });
                                        }
                                    }
                                    if (!found) {
                                        found = false;
                                        let linkupIdCallbacks = this.newCallMessageCallbacks.get(linkupId);
                                        if (linkupIdCallbacks !== undefined) {
                                            linkupIdCallbacks.forEach((callback) => {
                                                SignallingServerConnection.logger.debug('Calling default callback for linkupId ' + linkupId + ', unlistened callId is ' + callId);
                                                callback(new LinkupAddress(message['replyServerUrl'], message['replyLinkupId']), new LinkupAddress(this.serverURL, linkupId), callId, message['data']);
                                                found = true;
                                            });
                                        }
                                        if (!found) {
                                            SignallingServerConnection.logger.warning('Received message for unlistened linkupId: ' + linkupId, message);
                                        }
                                    }
                                }
                                else if (raw !== undefined && raw === 'true') {
                                    let callbacks = this.rawMessageCallbacks.get(linkupId);
                                    if (callbacks !== undefined) {
                                        callbacks.forEach((callback) => {
                                            SignallingServerConnection.logger.debug('Calling raw message callback for linkupId ' + linkupId);
                                            callback(new LinkupAddress(message['replyServerUrl'], message['replyLinkupId']), new LinkupAddress(this.serverURL, linkupId), message['data']);
                                        });
                                    }
                                }
                            }
                            else if (message['action'] === 'query-reply') {
                                const queryId = message['queryId'];
                                const hits = message['hits'];
                                let callback = this.listeningAddressesQueryCallback;
                                if (callback !== undefined) {
                                    let matchingLinkupAddresses = new Array();
                                    for (const linkupId of hits) {
                                        matchingLinkupAddresses.push(new LinkupAddress(this.serverURL, linkupId));
                                    }
                                    callback(queryId, matchingLinkupAddresses);
                                }
                            }
                            else {
                                SignallingServerConnection.logger.info('received unknown message on ' + this.serverURL + ': ' + ev.data);
                            }
                        };
                        this.ws.onopen = () => {
                            SignallingServerConnection.logger.debug('done creating websocket to URL ' + this.serverURL);
                            this.setUpListeners();
                            this.emptyMessageQueue();
                        };
                        this.ws.onerror = (ev) => {
                            SignallingServerConnection.logger.debug('Error in websocket for server ' + this.serverURL + ':');
                            //SignallingServerConnection.logger.error(ev);
                        };
                    }
                }
                return false;
            }
        }
        setUpListeners() {
            for (let linkupId of this.linkupIdsToListen) {
                this.setUpListener(linkupId);
            }
        }
        setUpListenerIfNew(linkupId) {
            if (!this.linkupIdsToListen.has(linkupId)) {
                this.setUpListener(linkupId);
                this.linkupIdsToListen.add(linkupId);
            }
        }
        // Notice this function is idempotent
        setUpListener(linkupId) {
            // check if we need to send a LISTEN message
            if (this.ws !== null && this.ws.readyState === this.ws.OPEN) {
                try {
                    SignallingServerConnection.logger.debug('sending listen command through websocket for linkupId ' + linkupId);
                    this.ws.send(JSON.stringify({ 'action': 'listen', 'linkupId': linkupId }));
                }
                catch (e) {
                    SignallingServerConnection.logger.warning('Error while trying to set up listener for ' + linkupId + ' for linkup server ' + this.serverURL);
                    SignallingServerConnection.logger.error(e);
                    // this.checkWebsocket(); // I'm afraid this may cause a loop
                }
            }
        }
        emptyMessageQueue() {
            if (this.checkWebsocket()) {
                SignallingServerConnection.logger.debug('about to empty message queue to ' +
                    this.serverURL + ' (' + this.messageQueue.length +
                    ' messages to send)');
                while (this.messageQueue.length > 0) {
                    let message = this.messageQueue.shift();
                    let ws = this.ws;
                    SignallingServerConnection.logger.trace('about to send this to ' + this.serverURL);
                    SignallingServerConnection.logger.trace(message);
                    try {
                        ws.send(message);
                    }
                    catch (e) {
                        SignallingServerConnection.logger.warning('Could not send message to signalling server ' + this.serverURL + ' - will retry.');
                        SignallingServerConnection.logger.error(e);
                        this.messageQueue.unshift(message);
                        break;
                    }
                }
            }
        }
        enqueueAndSend(message) {
            this.messageQueue.push(message);
            this.emptyMessageQueue();
        }
        close() {
            var _a;
            (_a = this.ws) === null || _a === void 0 ? void 0 : _a.close();
        }
    }
    SignallingServerConnection.logger = new Logger(SignallingServerConnection.name, LogLevel.ERROR);
    SignallingServerConnection.WRTC_URL_PREFIX = 'wrtc+';

    class MultiMap {
        constructor() {
            this.inner = new Map();
            this.size = 0;
        }
        add(key, value) {
            let s = this.inner.get(key);
            if (s === undefined) {
                s = new Set();
                this.inner.set(key, s);
            }
            if (!s.has(value)) {
                s.add(value);
                this.size = this.size + 1;
            }
        }
        delete(key, value) {
            let s = this.inner.get(key);
            if (s === undefined) {
                return false;
            }
            let ret = s.delete(value);
            if (s.size === 0) {
                this.inner.delete(key);
            }
            if (ret) {
                this.size = this.size - 1;
            }
            return ret;
        }
        deleteKey(key) {
            const vals = this.inner.get(key);
            if (vals !== undefined) {
                this.size = this.size - vals.size;
            }
            return this.inner.delete(key);
        }
        get(key) {
            let result = this.inner.get(key);
            if (result === undefined) {
                return new Set();
            }
            else {
                return new Set(result);
            }
        }
        hasKey(key) {
            return this.inner.has(key);
        }
        has(key, value) {
            const kv = this.inner.get(key);
            return kv !== undefined && kv.has(value);
        }
        asMap() {
            return new Map(this.inner.entries());
        }
        keys() {
            return this.inner.keys();
        }
        values() {
            return this.inner.values();
        }
        entries() {
            return this.inner.entries();
        }
        clone() {
            const clone = new MultiMap();
            for (const [k, s] of this.inner.entries()) {
                clone.inner.set(k, new Set(s));
            }
            return clone;
        }
    }

    var Params;
    (function (Params) {
        Params["CONN_ID"] = "connId";
        Params["SENDER"] = "sender";
        Params["RECIPIENT"] = "recipient";
        Params["REVERSE"] = "reverse";
    })(Params || (Params = {}));
    class WebSocketListener {
        constructor(serverUrl) {
            if (!WebSocketListener.isAvailable()) {
                throw new Error('WebSocketServer is not available in this platform');
            }
            let parsed = new URL(serverUrl);
            this.serverUrl = serverUrl;
            this.host = parsed.hostname;
            this.port = Number.parseInt(parsed.port);
            this.listener = new global.WebSocketServerImpl({ host: this.host, port: this.port });
            this.newCallMessageCallbacks = new MultiMap();
            this.onConnection = (socket, url) => {
                try {
                    let parseOK = false;
                    const parts = url.split('?');
                    const params = {};
                    if (parts !== undefined && parts.length === 2) {
                        for (const param of parts[1].split('&')) {
                            const d = param.split('=');
                            if (d.length > 0) {
                                const key = d[0];
                                const value = d.length > 1 ? decodeURIComponent(d[1]) : undefined;
                                params[key] = value;
                            }
                        }
                    }
                    if (params[Params.CONN_ID] !== undefined &&
                        params[Params.SENDER] !== undefined &&
                        params[Params.RECIPIENT] !== undefined) {
                        const connId = decodeURIComponent(params[Params.CONN_ID]);
                        const sender = LinkupAddress.fromURL(decodeURIComponent(params[Params.SENDER]));
                        const recipient = LinkupAddress.fromURL(decodeURIComponent(params[Params.RECIPIENT]));
                        const reverse = params[Params.REVERSE];
                        if (recipient.serverURL === this.serverUrl) {
                            let callbacks = this.newCallMessageCallbacks.get(recipient.linkupId);
                            if (callbacks.size > 0) {
                                for (const callback of callbacks) {
                                    callback(sender, recipient, connId, { ws: socket, reverse: reverse });
                                    parseOK = true;
                                }
                            }
                            else {
                                WebSocketListener.logger.debug('Received websocket request for linkupId ' + recipient.linkupId + ' but there are no registered listeners for it.');
                            }
                        }
                        else {
                            WebSocketListener.logger.warning('Received websocket request for server ' + recipient.serverURL + ', but this is ' + this.serverUrl + ', rejecting.');
                        }
                    }
                    if (!parseOK) {
                        WebSocketListener.logger.error('Could not parse websocket request with url ' + url);
                        socket.close();
                    }
                }
                catch (e) {
                    WebSocketListener.logger.error('Error configuring websocket connection, url was: ' + url + ', error: ' + e);
                    socket.close();
                }
            };
            this.listener.onConnection = this.onConnection;
        }
        static isAvailable() {
            return (global !== undefined && global.WebSocketServerImpl !== undefined);
        }
        listenForMessagesNewCall(recipient, callback) {
            if (recipient.serverURL !== this.serverUrl) {
                throw new Error('Asked to listen for connections for server ' + recipient.serverURL + ' but this is ' + this.serverUrl);
            }
            this.newCallMessageCallbacks.add(recipient.linkupId, callback);
        }
        listenForMessagesOnCall(_recipient, _callId, _callback) {
            throw new Error("WebSocket-based connections don't need out-of-band connection establishment messages, and they are not supported. Just use the connection messaging methods!");
        }
        listenForLinkupAddressQueries(_callback) {
            throw new Error("Listening address queries are not supported on plain websocket listeners, just try to connect and see if it works.");
        }
        sendMessage(_sender, _recipient, _callId, _data) {
            throw new Error("WebSocket-based connections don't need out-of-band connection establishment messages, and they are not supported. Just use the connection messaging methods!");
        }
        sendListeningAddressesQuery(_queryId, _addresses) {
            throw new Error("Listening address queries are not supported on plain websocket listeners, just try to connect and see if it works.");
        }
        listenForRawMessages(_recipient, _callback) {
            throw new Error("Listening for raw messages is not supported in WebSocket-listener based LinkupServers");
        }
        sendRawMessage(_sender, _recipient, _data, _sendLimit) {
            throw new Error("Sending raw messages is not supported in WebSocket-listener based LinkupServers");
        }
        close() {
            this.listener.close();
        }
    }
    WebSocketListener.logger = new Logger(WebSocketListener.name, LogLevel.INFO);

    class LinkupManager {
        constructor() {
            this.serverConnections = new Map();
            this.queryCallbacks = new Map();
            this.serverQueryCallback = (queryId, matches) => {
                let queryCallback = this.queryCallbacks.get(queryId);
                if (queryCallback !== undefined) {
                    queryCallback(queryId, matches);
                }
            };
        }
        listenForMessagesNewCall(recipient, callback) {
            let connection = this.getLinkupServer(recipient.serverURL);
            connection.listenForMessagesNewCall(recipient, callback);
        }
        listenForMessagesOnCall(recipient, callId, callback) {
            let connection = this.getLinkupServer(recipient.serverURL);
            connection.listenForMessagesOnCall(recipient, callId, callback);
        }
        listenForRawMessages(recipient, callback) {
            let connection = this.getLinkupServer(recipient.serverURL);
            connection.listenForRawMessages(recipient, callback);
        }
        sendMessageOnCall(sender, recipient, callId, data) {
            let connection = this.getLinkupServer(recipient.serverURL);
            connection.sendMessage(sender, recipient, callId, data);
        }
        sendRawMessage(sender, recipient, data, sendLimit) {
            let connection = this.getLinkupServer(recipient.serverURL);
            connection.sendRawMessage(sender, recipient, data, sendLimit);
        }
        listenForQueryResponses(queryId, callback) {
            this.queryCallbacks.set(queryId, callback);
        }
        queryForListeningAddresses(queryId, addresses) {
            let queries = new Map();
            let direct = [];
            for (const address of addresses) {
                if (SignallingServerConnection.isWebRTCBased(address.serverURL)) {
                    let q = queries.get(address.serverURL);
                    if (q === undefined) {
                        q = new Array();
                        queries.set(address.serverURL, q);
                    }
                    q.push(address);
                }
                else {
                    direct.push(address);
                }
            }
            for (const [serverURL, addresses] of queries.entries()) {
                let serverConnection = this.getLinkupServer(serverURL);
                LinkupManager.logger.trace(() => 'Sending query for listening addresses to ' + serverURL + ' for ' + addresses);
                serverConnection.sendListeningAddressesQuery(queryId, addresses);
            }
            const callback = this.queryCallbacks.get(queryId);
            if (callback !== undefined && direct.length > 0) {
                LinkupManager.logger.trace(() => 'Reporting websocket addresses as listening:' + JSON.stringify(direct));
                callback(queryId, direct);
            }
        }
        getLinkupServer(serverURL) {
            let serverConnection = this.serverConnections.get(serverURL);
            if (serverConnection === undefined) {
                if (SignallingServerConnection.isWebRTCBased(serverURL)) {
                    serverConnection = new SignallingServerConnection(serverURL);
                    serverConnection.listenForLinkupAddressQueries(this.serverQueryCallback);
                }
                else {
                    serverConnection = new WebSocketListener(serverURL);
                }
                this.serverConnections.set(serverURL, serverConnection);
            }
            return serverConnection;
        }
        shutdown() {
            for (const serverConn of this.serverConnections.values()) {
                serverConn.close();
            }
        }
    }
    LinkupManager.logger = new Logger(LinkupManager.name, LogLevel.INFO);
    LinkupManager.defaultLinkupServer = 'wrtc+wss://mypeer.net:443';

    /* A WebRTC Connection is used to create a bi-directional
       DataChannel between two hosts. A LinkupManager object
       is used to send signalling messages between the two parties
       in order to establish the browser-to-browser connection. */
    const RTC_CONN_DESCRIPTION = 'RTC_CONN_DESCRIPTION';
    const ICE_CANDIDATE = 'ICE_CANDIDATE';
    class WebRTCConnection {
        constructor(linkupManager, local, remote, callId, readyCallback, channelStatusChangeCallback) {
            this.linkupManager = linkupManager;
            this.localAddress = local;
            this.remoteAddress = remote;
            this.callId = callId;
            this.initiator = false;
            this.gatheredICE = false;
            this.readyCallback = readyCallback;
            this.messageCallback = undefined;
            this.bufferedAmountLowCallback = undefined;
            this.incomingMessages = [];
            this.onmessage = (ev) => {
                var _a, _b;
                WebRTCConnection.logger.debug(((_a = this.localAddress) === null || _a === void 0 ? void 0 : _a.linkupId) + ' received message from ' + ((_b = this.remoteAddress) === null || _b === void 0 ? void 0 : _b.linkupId) + ' on call ' + this.callId);
                WebRTCConnection.logger.trace('message is ' + ev.data);
                if (this.messageCallback != undefined) {
                    this.messageCallback(ev.data, this);
                }
                else {
                    this.incomingMessages.push(ev);
                }
            };
            this.onready = () => {
                var _a, _b;
                WebRTCConnection.logger.debug('connection from ' + ((_a = this.localAddress) === null || _a === void 0 ? void 0 : _a.linkupId) + ' to ' + ((_b = this.remoteAddress) === null || _b === void 0 ? void 0 : _b.linkupId) + ' is ready for call ' + this.callId);
                this.readyCallback(this);
            };
            this.channelStatusChangeCallback = channelStatusChangeCallback;
            this.handleSignallingMessage = (message) => {
                var _a, _b;
                var signal = message['signal'];
                var data = message['data'];
                WebRTCConnection.logger.debug(((_a = this.localAddress) === null || _a === void 0 ? void 0 : _a.linkupId) + ' is handling ' + signal + ' from ' + ((_b = this.remoteAddress) === null || _b === void 0 ? void 0 : _b.serverURL) + ' on call ' + data['callId']);
                WebRTCConnection.logger.trace('received data is ' + JSON.stringify(data));
                switch (signal) {
                    case RTC_CONN_DESCRIPTION:
                        this.handleReceiveConnectionDescription(data['callId'], data['channelName'], data['description']);
                        break;
                    case ICE_CANDIDATE:
                        WebRTCConnection.iceLogger.debug('received ICE candidate:');
                        WebRTCConnection.iceLogger.debug(data['candidate']);
                        this.handleReceiveIceCandidate(data['candidate']);
                        break;
                }
            };
        }
        getConnectionId() {
            return this.callId;
        }
        initiatedLocally() {
            return this.initiator;
        }
        // possible values: 'unknown', 'connecting', 'open', 'closed', 'closing';
        channelStatus() {
            if (this.channel === undefined) {
                return 'unknown';
            }
            else {
                return this.channel.readyState;
            }
        }
        channelIsOperational() {
            return this.channel !== undefined && this.channel.readyState === 'open';
        }
        setMessageCallback(messageCallback) {
            this.messageCallback = messageCallback;
            if (messageCallback != undefined) {
                while (this.incomingMessages.length > 0) {
                    var ev = this.incomingMessages.shift();
                    messageCallback(ev.data, this);
                }
            }
        }
        /* To initiate a connection, an external entity must create
            a WebRTCConnection object and call the open() method. */
        open(channelName = 'mesh-network-channel') {
            var _a, _b;
            this.init();
            this.initiator = true;
            this.channelName = channelName;
            this.setUpLinkupListener();
            this.channel =
                (_a = this.connection) === null || _a === void 0 ? void 0 : _a.createDataChannel(channelName);
            if (this.connection === undefined) {
                WebRTCConnection.logger.error('Failed to create data channel, connection is undefined');
            }
            this.setUpChannel();
            (_b = this.connection) === null || _b === void 0 ? void 0 : _b.createOffer().then((description) => {
                var _a, _b;
                if (((_a = this.connection) === null || _a === void 0 ? void 0 : _a.signalingState) !== 'closed') {
                    (_b = this.connection) === null || _b === void 0 ? void 0 : _b.setLocalDescription(description);
                }
                this.signalConnectionDescription(description);
            }, (error) => {
                WebRTCConnection.logger.error('error creating offer: ' + error);
            });
        }
        /* Upon receiving a connection request, an external entity
           must create a connection and pass the received message,
           alongisde the LinkupListener and LinkupCaller to be used
           for signalling, to the answer() method. After receiving
           the initial message, the connection will configure the
           listener to pass along all following signalling messages. */
        answer(message) {
            this.init();
            this.initiator = false;
            this.handleSignallingMessage(message);
        }
        /* Sometimes the receiving end defers accepting the connection a bit,
           and several signalling messages crop up. */
        receiveSignallingMessage(message) {
            this.handleSignallingMessage(message);
        }
        close() {
            WebRTCConnection.logger.debug('Closing connection ' + this.callId);
            if (this.connection !== undefined) {
                this.connection.close();
            }
        }
        send(message) {
            var _a, _b;
            WebRTCConnection.logger.debug(((_a = this.localAddress) === null || _a === void 0 ? void 0 : _a.linkupId) + ' sending msg to ' + ((_b = this.remoteAddress) === null || _b === void 0 ? void 0 : _b.linkupId) + ' through channel ' + this.channelName + ' on call ' + this.callId);
            if (this.channel === undefined) {
                WebRTCConnection.logger.warning('Attemting to send over missing channel in connection ' + this.callId + ' at ' + Date.now());
                throw new Error('Attemting to send over missing channel in connection ' + this.callId + ' at ' + Date.now());
            }
            this.channel.send(message);
            WebRTCConnection.logger.trace('Done sending msg');
        }
        bufferedAmount() {
            if (this.channel !== undefined) {
                return this.channel.bufferedAmount;
            }
            else {
                return 0;
            }
        }
        setBufferedAmountLowCallback(callback, bufferedAmountLowThreshold = 0) {
            this.bufferedAmountLowCallback = callback;
            this.bufferedAmountLowThreshold = bufferedAmountLowThreshold;
        }
        init(ICEServers) {
            let servers = ICEServers === undefined ? { iceServers: [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }] } : ICEServers;
            this.connection = new RTCPeerConnection(servers); //WebRTCShim.getNewRTCPeerConnection(servers);
            this.gatheredICE = false;
            this.connection.onicecandidate = (ev) => {
                WebRTCConnection.iceLogger.debug('onicecandidate was called with:');
                WebRTCConnection.iceLogger.debug(JSON.stringify(ev.candidate));
                if (ev.candidate == null) {
                    this.gatheredICE = true;
                    WebRTCConnection.logger.debug(this.callId + ' is done gathering ICE candiadtes');
                }
                else {
                    this.signalIceCandidate(ev.candidate);
                }
            };
        }
        setUpLinkupListener() {
            this.linkupManager.listenForMessagesOnCall(this.localAddress, this.callId, this.handleSignallingMessage);
        }
        signalConnectionDescription(description) {
            this.signalSomething(RTC_CONN_DESCRIPTION, { 'callId': this.callId,
                'channelName': this.channelName,
                'description': description
            });
        }
        signalIceCandidate(candidate) {
            WebRTCConnection.iceLogger.debug('sending ice:');
            WebRTCConnection.iceLogger.debug(candidate);
            this.signalSomething(ICE_CANDIDATE, { 'callId': this.callId,
                'channelName': this.channelName,
                'candidate': candidate
            });
        }
        signalSomething(signal, data) {
            WebRTCConnection.logger.debug(this.localAddress.linkupId + ' signalling to ' + this.remoteAddress.linkupId + ' on call ' + this.callId + ' (' + signal + ')');
            WebRTCConnection.logger.trace('sent data is ' + JSON.stringify(data));
            let envelope = { 'signal': signal,
                'data': data };
            this.linkupManager.sendMessageOnCall(this.localAddress, this.remoteAddress, this.callId, envelope);
        }
        handleReceiveConnectionDescription(callId, channelName, description) {
            var _a;
            if (callId === this.callId) {
                if (this.channelName === undefined) {
                    this.channelName = channelName;
                }
            }
            else {
                WebRTCConnection.logger.error('Received message for callId ' + callId + ' but expected ' + this.callId);
            }
            if (this.connection !== undefined) {
                if (this.connection.signalingState !== 'closed') {
                    this.connection.ondatachannel = (ev) => {
                        WebRTCConnection.logger.debug(this.localAddress.linkupId + ' received DataChannel from ' + this.remoteAddress.linkupId + ' on call ' + this.callId);
                        this.channel = ev.channel;
                        this.setUpChannel();
                    };
                    this.connection.setRemoteDescription(description).catch((reason) => {
                        WebRTCConnection.logger.warning('Failed to set remote description, reason: ' + JSON.stringify(reason));
                    });
                }
                else {
                    WebRTCConnection.logger.debug('A remote description arrived untimely (signalingState=="closed") and will be ignored.');
                }
            }
            else {
                WebRTCConnection.logger.error('Received message for callId ' + callId + ' but connection was undefined on ' + this.localAddress.linkupId);
            }
            if (!this.initiator) {
                this.setUpLinkupListener();
                (_a = this.connection) === null || _a === void 0 ? void 0 : _a.createAnswer().then((description) => {
                    var _a;
                    try {
                        (_a = this.connection) === null || _a === void 0 ? void 0 : _a.setLocalDescription(description);
                    }
                    catch (e) {
                        WebRTCConnection.logger.warning('Failed to set local description, error:', e);
                        WebRTCConnection.logger.warning('Description object was:', description);
                    }
                    this.signalConnectionDescription(description);
                }, (error) => {
                    WebRTCConnection.logger.error('error generating answer: ' + error + ' for callId ' + this.callId + ' on ' + this.localAddress.linkupId);
                });
            }
        }
        handleReceiveIceCandidate(candidate) {
            var _a;
            (_a = this.connection) === null || _a === void 0 ? void 0 : _a.addIceCandidate(candidate).catch((reason) => {
                WebRTCConnection.logger.debug('Failed to set ICE candidate, reason: ' + JSON.stringify(reason));
            });
        }
        setUpChannel() {
            let stateChange = () => {
                var _a, _b, _c;
                WebRTCConnection.logger.debug(this.callId + ' readyState now is ' + ((_a = this.channel) === null || _a === void 0 ? void 0 : _a.readyState));
                if (((_b = this.channel) === null || _b === void 0 ? void 0 : _b.readyState) === 'open') {
                    this.onready();
                }
                if (this.channelStatusChangeCallback !== undefined) {
                    this.channelStatusChangeCallback(((_c = this.channel) === null || _c === void 0 ? void 0 : _c.readyState) || 'unknown', this);
                }
            };
            let bufferAmountLow = () => {
                WebRTCConnection.logger.trace(this.callId + ' bufferedAmountLow reached');
                if (this.bufferedAmountLowCallback !== undefined) {
                    this.bufferedAmountLowCallback(this);
                }
            };
            if (this.channel !== undefined) {
                this.channel.onmessage = this.onmessage;
                this.channel.onopen = stateChange;
                this.channel.onclose = stateChange;
                this.channel.onbufferedamountlow = bufferAmountLow;
                if (this.bufferedAmountLowThreshold !== undefined) {
                    this.channel.bufferedAmountLowThreshold = this.bufferedAmountLowThreshold;
                }
            }
        }
    }
    WebRTCConnection.logger = new Logger(WebRTCConnection.name, LogLevel.INFO);
    WebRTCConnection.iceLogger = new Logger(WebRTCConnection.name, LogLevel.INFO);

    class WebSocketConnection {
        constructor(connectionId, localAddress, remoteAddress, readyCallback, linkupManager) {
            this.linkupManager = linkupManager;
            this.localAddress = localAddress;
            this.remoteAddress = remoteAddress;
            this.connectionId = connectionId;
            this.readyCallback = readyCallback;
            this.initiated = false;
            this.reverse = false;
            this.incomingMessages = [];
            this.onmessage = (ev) => {
                //WebRTCConnection.logger.debug(this.localAddress?.linkupId + ' received message from ' + this.remoteAddress?.linkupId + ' on call ' + this.callId);
                //WebRTCConnection.logger.trace('message is ' + ev.data);
                if (this.messageCallback != null) {
                    this.messageCallback(ev.data, this);
                }
                else {
                    this.incomingMessages.push(ev);
                }
            };
            this.onopen = () => {
                //WebRTCConnection.logger.debug('connection from ' + this.localAddress?.linkupId + ' to ' + this.remoteAddress?.linkupId + ' is ready for call ' + this.callId);
                this.readyCallback(this);
            };
        }
        open() {
            this.initiated = true;
            if (SignallingServerConnection.isWebRTCBased(this.remoteAddress.url())) {
                if (this.linkupManager !== undefined) {
                    this.reverse = true;
                    this.linkupManager.sendMessageOnCall(this.localAddress, this.remoteAddress, this.connectionId, { reverseconnection: 'true' });
                    WebSocketConnection.logger.trace(() => 'Starting reverse connection cycle from ' + this.localAddress.url() + ' to ' + this.remoteAddress.url());
                }
                else {
                    WebSocketConnection.logger.warning(() => 'Trying to connect to ' + this.remoteAddress.url() + ' form a websocket connection, but no linkupServer was provided. This is not possible - ignoring.');
                }
            }
            else {
                this.createWebsocket();
                WebSocketConnection.logger.trace('Starting websocket connection from ' + this.localAddress.url() + ' to ' + this.remoteAddress.url());
            }
        }
        createWebsocket(reverse = false) {
            this.ws = new WebSocket(this.remoteAddress.url() + '?' +
                Params.CONN_ID + '=' + encodeURIComponent(this.connectionId) + '&' +
                Params.SENDER + '=' + encodeURIComponent(this.localAddress.url()) + '&' +
                Params.RECIPIENT + '=' + encodeURIComponent(this.remoteAddress.url()) +
                (reverse ? '&' + Params.REVERSE + '=true' : ''));
            this.ws.onopen = this.onopen;
            this.ws.onmessage = this.onmessage;
        }
        answer(message) {
            if (this.ws === undefined) {
                if (!this.reverse &&
                    SignallingServerConnection.isWebRTCBased(this.localAddress.url()) &&
                    message.reverseconnection !== undefined &&
                    message.reverseconnection === 'true') {
                    WebSocketConnection.logger.trace(() => 'Creating websocket to ' + this.remoteAddress.url() + ' for reverse connection');
                    this.reverse = true;
                    this.initiated = false;
                    this.createWebsocket(true);
                }
                if (message.ws !== undefined) {
                    this.ws = message.ws;
                    this.ws.onmessage = this.onmessage;
                    this.readyCallback(this);
                    if (!this.reverse) {
                        this.initiated = false;
                        WebSocketConnection.logger.trace(() => 'Received websocket connection from ' + this.remoteAddress.url());
                    }
                    else {
                        WebSocketConnection.logger.trace(() => 'Received reverse websocket connection back at origin');
                    }
                }
            }
        }
        getConnectionId() {
            return this.connectionId;
        }
        initiatedLocally() {
            return this.initiated;
        }
        setMessageCallback(messageCallback) {
            this.messageCallback = messageCallback;
            if (messageCallback != null) {
                while (this.incomingMessages.length > 0) {
                    var ev = this.incomingMessages.shift();
                    messageCallback(ev.data, this);
                }
            }
        }
        channelIsOperational() {
            return this.ws !== undefined && this.ws.readyState === WebSocket.OPEN;
        }
        close() {
            var _a;
            (_a = this.ws) === null || _a === void 0 ? void 0 : _a.close();
        }
        send(message) {
            if (this.ws === undefined) {
                throw new Error('Trying to send a message through a websocket that is not yet ready.');
            }
            this.ws.send(message);
            if (this.ws.readyState !== WebSocket.OPEN) {
                throw new Error('Error while trying to send a message through WebSocket');
            }
        }
        bufferedAmount() {
            var _a;
            if (this.ws !== undefined) {
                return (_a = this.ws) === null || _a === void 0 ? void 0 : _a.bufferedAmount;
            }
            else {
                return 0;
            }
        }
    }
    WebSocketConnection.logger = new Logger(WebSocketConnection.name, LogLevel.INFO);

    class LinkupManagerProxy {
        constructor(commandForwardingFn) {
            this.commandForwardingFn = commandForwardingFn;
            this.messagesNewCallCallbacks = new MultiMap();
            this.messagesOnCallCallbacks = new MultiMap();
            this.rawMessageCallbacks = new MultiMap();
            this.queryResponseCallbacks = new MultiMap();
            this.linkupManagerEventIngestFn = (ev) => {
                if (ev.type === 'new-call-message') {
                    const newCall = ev;
                    for (const cb of this.messagesNewCallCallbacks.get(newCall.recipient)) {
                        const sender = LinkupAddress.fromURL(newCall.sender);
                        const recipient = LinkupAddress.fromURL(newCall.recipient);
                        try {
                            cb(sender, recipient, newCall.callId, newCall.message);
                        }
                        catch (e) {
                            console.log('Error in callback invocation within LinkupManagerProxy: ', e);
                        }
                    }
                }
                else if (ev.type === 'raw-message-event') {
                    const raw = ev;
                    for (const cb of this.rawMessageCallbacks.get(raw.recipient)) {
                        const sender = LinkupAddress.fromURL(raw.sender);
                        const recipient = LinkupAddress.fromURL(raw.recipient);
                        try {
                            cb(sender, recipient, raw.message);
                        }
                        catch (e) {
                            console.log('Error in callback invocation within LinkupManagerProxy: ', e);
                        }
                    }
                }
                else if (ev.type === 'listening-addresses-query-response') {
                    const response = ev;
                    for (const cb of this.queryResponseCallbacks.get(response.queryId)) {
                        const listening = response.matches.map((ep) => LinkupAddress.fromURL(ep));
                        try {
                            cb(response.queryId, listening);
                        }
                        catch (e) {
                            console.log('Error in callback invocation within LinkupManagerProxy: ', e);
                        }
                    }
                }
                else if (ev.type === 'message-on-call') {
                    const msg = ev;
                    for (const cb of this.messagesOnCallCallbacks.get(msg.recipient + '/' + msg.callId)) {
                        try {
                            cb(msg.message);
                        }
                        catch (e) {
                            console.log('Error in callback invocation within LinkupManagerProxy: ', e);
                        }
                    }
                }
            };
        }
        listenForMessagesNewCall(recipient, callback) {
            const cmd = {
                type: 'listen-for-messages-new-call',
                recipient: recipient.url()
            };
            this.messagesNewCallCallbacks.add(cmd.recipient, callback);
            this.commandForwardingFn(cmd);
        }
        listenForMessagesOnCall(recipient, callId, callback) {
            const cmd = {
                type: 'listen-for-messages-on-call',
                recipient: recipient.url(),
                callId: callId
            };
            this.messagesOnCallCallbacks.add(cmd.recipient + '/' + callId, callback);
            this.commandForwardingFn(cmd);
        }
        listenForRawMessages(recipient, callback) {
            const cmd = {
                type: 'listen-for-raw-messages',
                recipient: recipient.url()
            };
            this.rawMessageCallbacks.add(cmd.recipient, callback);
            this.commandForwardingFn(cmd);
        }
        sendMessageOnCall(sender, recipient, callId, data) {
            const cmd = {
                type: 'send-message-on-call',
                sender: sender.url(),
                recipient: recipient.url(),
                callId: callId,
                data: JSON.parse(JSON.stringify(data))
            };
            this.commandForwardingFn(cmd);
        }
        sendRawMessage(sender, recipient, data, sendLimit) {
            const cmd = {
                type: 'send-raw-message',
                sender: sender.url(),
                recipient: recipient.url(),
                data: data,
                sendLimit: sendLimit
            };
            this.commandForwardingFn(cmd);
        }
        listenForQueryResponses(queryId, callback) {
            const cmd = {
                type: 'listen-for-query-responses',
                queryId: queryId
            };
            this.queryResponseCallbacks.add(queryId, callback);
            this.commandForwardingFn(cmd);
        }
        queryForListeningAddresses(queryId, addresses) {
            const cmd = {
                type: 'query-for-listening-addresses',
                queryId: queryId,
                addresses: addresses.map((addr) => addr.url())
            };
            this.commandForwardingFn(cmd);
        }
    }

    class LinkupManagerHost {
        constructor(eventCallback, linkup) {
            this.linkup = linkup || new LinkupManager();
            this.eventCallback = eventCallback;
            this.newCallMessageCallback =
                (sender, recipient, callId, message) => {
                    const ev = {
                        type: 'new-call-message',
                        sender: sender.url(),
                        recipient: recipient.url(),
                        callId: callId,
                        message: message
                    };
                    this.eventCallback(ev);
                };
            this.messageCallabcks = new Map();
            this.rawMessageCallback = (sender, recipient, message) => {
                const ev = {
                    type: 'raw-message-event',
                    sender: sender.url(),
                    recipient: recipient.url(),
                    message: message
                };
                this.eventCallback(ev);
            };
            this.listeningAddressesQueryCallback = (queryId, matches) => {
                const ev = {
                    type: 'listening-addresses-query-response',
                    queryId: queryId,
                    matches: matches.map((addr) => addr.url())
                };
                this.eventCallback(ev);
            };
        }
        static isCommand(msg) {
            const type = msg === null || msg === void 0 ? void 0 : msg.type;
            return (type === 'listen-for-messages-new-call' ||
                type === 'listen-for-messages-on-call' ||
                type === 'listen-for-raw-messages' ||
                type === 'send-message-on-call' ||
                type === 'send-raw-message' ||
                type === 'listen-for-query-responses' ||
                type === 'query-for-listening-addresses');
        }
        static isEvent(msg) {
            const type = msg === null || msg === void 0 ? void 0 : msg.type;
            return (type === 'new-call-message' ||
                type === 'raw-message-event' ||
                type === 'listening-addresses-query-response' ||
                type === 'message-on-call');
        }
        execute(cmd) {
            if (cmd.type === 'listen-for-messages-new-call') {
                const listen = cmd;
                this.linkup.listenForMessagesNewCall(LinkupAddress.fromURL(listen.recipient), this.newCallMessageCallback);
            }
            else if (cmd.type === 'listen-for-messages-on-call') {
                const listen = cmd;
                const callback = (msg) => {
                    const ev = {
                        type: 'message-on-call',
                        recipient: listen.recipient,
                        callId: listen.callId,
                        message: msg
                    };
                    this.eventCallback(ev);
                };
                this.linkup.listenForMessagesOnCall(LinkupAddress.fromURL(listen.recipient), listen.callId, callback);
            }
            else if (cmd.type === 'listen-for-raw-messages') {
                const listen = cmd;
                this.linkup.listenForRawMessages(LinkupAddress.fromURL(listen.recipient), this.rawMessageCallback);
            }
            else if (cmd.type === 'send-message-on-call') {
                const send = cmd;
                const sender = LinkupAddress.fromURL(send.sender);
                const recipient = LinkupAddress.fromURL(send.recipient);
                this.linkup.sendMessageOnCall(sender, recipient, send.callId, send.data);
            }
            else if (cmd.type === 'send-raw-message') {
                const send = cmd;
                const sender = LinkupAddress.fromURL(send.sender);
                const recipient = LinkupAddress.fromURL(send.recipient);
                this.linkup.sendRawMessage(sender, recipient, send.data, send.sendLimit);
            }
            else if (cmd.type === 'listen-for-query-responses') {
                const listen = cmd;
                this.linkup.listenForQueryResponses(listen.queryId, this.listeningAddressesQueryCallback);
            }
            else if (cmd.type === 'query-for-listening-addresses') {
                let query = cmd;
                this.linkup.queryForListeningAddresses(query.queryId, query.addresses.map((ep) => LinkupAddress.fromURL(ep)));
            }
        }
    }

    /* functions that actually used:

    new
    getConnectionId
    channelIsOperational
    close
    setMessageCallback
    answer
    receiveSignallingMessage

    */
    class WebRTCConnectionProxy {
        constructor(local, remote, callId, readyCallback, commandForwardingFn) {
            this.commandForwardingFn = commandForwardingFn;
            this.localAddress = local;
            this.remoteAddress = remote;
            this.initiator = false;
            this.callId = callId;
            this.readyCallback = readyCallback;
            this.cachedChannelStatus = 'unknown';
            this.closed = false;
            this.lastKnownBufferedAmount = 0;
            this.connectionEventIngestFn = (ev) => {
                if (ev.connId === this.callId) {
                    if (ev.type === 'connection-ready') {
                        this.readyCallback(this);
                    }
                    else if (ev.type === 'connection-status-change') {
                        const change = ev;
                        this.cachedChannelStatus = change.status;
                    }
                    else if (ev.type === 'message-received') {
                        const msg = ev;
                        // this check should be unnecessary, because the WebRTCConnectionProvider
                        // won't start forwarding messages until it has been informed by this class
                        // that the messageCallback was installed.
                        if (this.messageCallback !== undefined) {
                            this.messageCallback(msg.data, this);
                        }
                        else {
                            console.log('WARNING: lost message due to missing callback in WebRTCConnectionProxy for ' + msg.connId);
                        }
                    }
                    else if (ev.type === 'update-buffered-amount') {
                        const msg = ev;
                        this.lastKnownBufferedAmount = msg.bufferedAmount;
                    }
                }
            };
            const msg = {
                type: 'create-connection',
                connId: callId,
                localEndpoint: local.url(),
                remoteEndpoint: remote.url()
            };
            this.commandForwardingFn(msg);
        }
        getConnectionId() {
            return this.callId;
        }
        initiatedLocally() {
            throw new Error('Method not implemented.');
        }
        setMessageCallback(messageCallback) {
            this.messageCallback = messageCallback;
            if (messageCallback !== undefined) {
                const cmd = {
                    type: 'message-callback-set',
                    connId: this.callId
                };
                this.commandForwardingFn(cmd);
            }
        }
        // possible values: 'unknown', 'connecting', 'open', 'closed', 'closing';
        channelStatus() {
            return this.cachedChannelStatus;
        }
        channelIsOperational() {
            return this.cachedChannelStatus === 'open';
        }
        open(channelName = 'mesh-network-channel') {
            const cmd = {
                type: 'open-connection',
                connId: this.callId,
                channelName: channelName
            };
            this.commandForwardingFn(cmd);
        }
        answer(message) {
            const cmd = {
                type: 'answer-connection',
                connId: this.callId,
                message: message
            };
            this.commandForwardingFn(cmd);
        }
        receiveSignallingMessage(message) {
            const cmd = {
                type: 'receive-signalling',
                connId: this.callId,
                message: message
            };
            this.commandForwardingFn(cmd);
        }
        close() {
            this.closed = true;
            const cmd = {
                type: 'close-connection',
                connId: this.callId
            };
            this.commandForwardingFn(cmd);
        }
        send(message) {
            const cmd = {
                type: 'send-message',
                connId: this.callId,
                contents: message
            };
            this.commandForwardingFn(cmd);
        }
        bufferedAmount() {
            return this.lastKnownBufferedAmount;
        }
    }

    class WebRTCConnectionsHost {
        constructor(eventCallback, linkup) {
            this.connections = new Map();
            this.linkup = linkup || new LinkupManager();
            this.eventCallback = eventCallback;
            this.messageCallback = (data, conn) => {
                let ev = {
                    type: 'message-received',
                    connId: conn.getConnectionId(),
                    data: data
                };
                this.eventCallback(ev);
            };
            this.connectionReadyCallback = (conn) => {
                let ev = {
                    type: 'connection-ready',
                    connId: conn.getConnectionId()
                };
                this.eventCallback(ev);
            };
            this.connectionStatusChangeCallback = (status, conn) => {
                let ev = {
                    type: 'connection-status-change',
                    connId: conn.getConnectionId(),
                    status: status
                };
                this.eventCallback(ev);
            };
            this.emptyBufferCallback = (conn) => {
                let ev = {
                    type: 'update-buffered-amount',
                    connId: conn.getConnectionId(),
                    bufferedAmount: conn.bufferedAmount()
                };
                this.eventCallback(ev);
            };
        }
        static isEvent(msg) {
            const type = msg === null || msg === void 0 ? void 0 : msg.type;
            return (type === 'connection-ready' ||
                type === 'connection-status-change' ||
                type === 'message-received' ||
                type === 'update-buffered-amount');
        }
        static isCommand(msg) {
            const type = msg === null || msg === void 0 ? void 0 : msg.type;
            return (type === 'create-connection' ||
                type === 'message-callback-set' ||
                type === 'open-connection' ||
                type === 'answer-connection' ||
                type === 'receive-signalling' ||
                type === 'close-connection' ||
                type === 'send-message');
        }
        execute(cmd) {
            var _a, _b, _c, _d, _e;
            if (cmd.type === 'create-connection') {
                const create = cmd;
                const local = LinkupAddress.fromURL(create.localEndpoint);
                const remote = LinkupAddress.fromURL(create.remoteEndpoint);
                const callId = create.connId;
                if (!this.connections.has(callId)) {
                    const conn = new WebRTCConnection(this.linkup, local, remote, callId, this.connectionReadyCallback, this.connectionStatusChangeCallback);
                    this.connections.set(callId, conn);
                }
            }
            else if (cmd.type === 'message-callback-set') {
                (_a = this.connections.get(cmd.connId)) === null || _a === void 0 ? void 0 : _a.setMessageCallback(this.messageCallback);
            }
            else if (cmd.type === 'open-connection') {
                (_b = this.connections.get(cmd.connId)) === null || _b === void 0 ? void 0 : _b.open(cmd.channelName);
            }
            else if (cmd.type === 'answer-connection') {
                (_c = this.connections.get(cmd.connId)) === null || _c === void 0 ? void 0 : _c.answer(cmd.message);
            }
            else if (cmd.type === 'receive-signalling') {
                (_d = this.connections.get(cmd.connId)) === null || _d === void 0 ? void 0 : _d.receiveSignallingMessage(cmd.message);
            }
            else if (cmd.type === 'close-connection') {
                (_e = this.connections.get(cmd.connId)) === null || _e === void 0 ? void 0 : _e.close();
                this.connections.delete(cmd.connId);
            }
            else if (cmd.type === 'send-message') {
                if (!this.connections.has(cmd.connId)) {
                    console.log('WARNING: trying to send message on ' + cmd.connId + ', but there is no such connection.');
                }
                const conn = this.connections.get(cmd.connId);
                if (conn !== undefined) {
                    conn.send(cmd.contents);
                    const ev = {
                        type: 'update-buffered-amount',
                        connId: cmd.connId,
                        bufferedAmount: conn.bufferedAmount()
                    };
                    this.eventCallback(ev);
                }
            }
        }
    }

    const BITS_FOR_CONN_ID = 128;
    exports.NetworkEventType = void 0;
    (function (NetworkEventType) {
        NetworkEventType["ConnectionStatusChange"] = "connection-status-change";
        NetworkEventType["RemoteAddressListening"] = "remote-address-listening";
        NetworkEventType["MessageReceived"] = "message-received";
        NetworkEventType["LinkupMessageReceived"] = "linkup-message-received";
    })(exports.NetworkEventType || (exports.NetworkEventType = {}));
    exports.ConnectionStatus = void 0;
    (function (ConnectionStatus) {
        ConnectionStatus["Received"] = "received";
        ConnectionStatus["Establishing"] = "establishing";
        ConnectionStatus["Ready"] = "ready";
        ConnectionStatus["Closed"] = "closed";
    })(exports.ConnectionStatus || (exports.ConnectionStatus = {}));
    // all the following in seconds
    const TickInterval = 5;
    const ConnectionEstablishmentTimeout = 10;
    class NetworkAgent {
        constructor(linkupManager = new LinkupManager(), proxyConfig) {
            this.testingMode = false;
            this.logger = NetworkAgent.logger;
            this.connLogger = NetworkAgent.connLogger;
            this.messageLogger = NetworkAgent.messageLogger;
            this.linkupManager = linkupManager;
            this.proxyConfig = proxyConfig;
            this.listening = new Set();
            this.linkupMessageListening = new Set();
            this.connections = new Map();
            this.connectionInfo = new Map();
            this.deferredInitialMessages = new Map();
            this.messageCallback = (data, conn) => {
                this.messageLogger.debug(() => { var _a, _b; return 'Endpoint ' + ((_a = this.connectionInfo.get(conn.getConnectionId())) === null || _a === void 0 ? void 0 : _a.localEndpoint) + ' received message from ' + ((_b = this.connectionInfo.get(conn.getConnectionId())) === null || _b === void 0 ? void 0 : _b.remoteEndpoint) + ':\n' + data; });
                const connectionId = conn.getConnectionId();
                const connInfo = this.connectionInfo.get(connectionId);
                try {
                    const message = JSON.parse(data);
                    if (connInfo !== undefined) {
                        if (connInfo.status !== exports.ConnectionStatus.Ready) {
                            this.connectionReadyCallback(conn);
                        }
                        if (message.connectionId !== undefined) {
                            // plain message, not peer to peer yet.
                            const msg = message;
                            if (msg.connectionId === connectionId &&
                                msg.source === connInfo.remoteEndpoint &&
                                msg.destination === connInfo.localEndpoint)
                                this.receiveMessage(msg);
                        }
                    }
                }
                catch (e) {
                    if (!this.testingMode) {
                        this.messageLogger.warning(() => { var _a, _b; return 'Endpoint ' + ((_a = this.connectionInfo.get(conn.getConnectionId())) === null || _a === void 0 ? void 0 : _a.localEndpoint) + ' could not process received message from ' + ((_b = this.connectionInfo.get(conn.getConnectionId())) === null || _b === void 0 ? void 0 : _b.remoteEndpoint) + ', error is:\n'; }, e);
                        this.messageLogger.warning('full message content follows:', data);
                    }
                }
            };
            this.connectionReadyCallback = (conn) => {
                var _a;
                const connectionId = conn.getConnectionId();
                const connInfo = this.connectionInfo.get(connectionId);
                if (connInfo === undefined) {
                    NetworkAgent.connLogger.trace(() => 'Connection ready callback invoked for ' + connectionId + ', but conn. info not present. Attempting to close.');
                    conn.close();
                }
                else {
                    NetworkAgent.connLogger.trace(() => 'Connection ready callback invoked for ' + connectionId + ', status was ' + connInfo.status + ' in ' + connInfo.localEndpoint);
                    if (connInfo.status !== exports.ConnectionStatus.Ready) {
                        this.connections.set(connectionId, conn);
                        connInfo.status = exports.ConnectionStatus.Ready;
                        const ev = {
                            type: exports.NetworkEventType.ConnectionStatusChange,
                            content: {
                                connId: connectionId,
                                localEndpoint: connInfo.localEndpoint,
                                remoteEndpoint: connInfo.remoteEndpoint,
                                status: exports.ConnectionStatus.Ready
                            }
                        };
                        NetworkAgent.connLogger.trace(() => 'Broadcasting connection readiness for ' + connectionId + ', status now is ' + connInfo.status + ' in ' + connInfo.localEndpoint);
                        (_a = this.pod) === null || _a === void 0 ? void 0 : _a.broadcastEvent(ev);
                    }
                }
            };
            this.newConnectionRequestCallback = (sender, receiver, connectionId, message) => {
                var _a;
                let connInfo = this.connectionInfo.get(connectionId);
                let isNew = connInfo === undefined;
                if (connInfo === undefined) {
                    connInfo = {
                        localEndpoint: receiver.url(),
                        remoteEndpoint: sender.url(),
                        connId: connectionId,
                        status: exports.ConnectionStatus.Received,
                        timestamp: Date.now(),
                        requestedBy: new Set()
                    };
                    this.connectionInfo.set(connectionId, connInfo);
                }
                if (connInfo.localEndpoint === receiver.url() &&
                    connInfo.remoteEndpoint === sender.url()) {
                    if (connInfo.status === exports.ConnectionStatus.Establishing) {
                        this.acceptReceivedConnectionMessages(connectionId, message);
                    }
                    else if (connInfo.status === exports.ConnectionStatus.Received) {
                        this.deferReceivedConnectionMessage(connectionId, message);
                        if (isNew) {
                            let ev = {
                                type: exports.NetworkEventType.ConnectionStatusChange,
                                content: {
                                    connId: connectionId,
                                    localEndpoint: connInfo.localEndpoint,
                                    remoteEndpoint: connInfo.remoteEndpoint,
                                    status: exports.ConnectionStatus.Received
                                }
                            };
                            (_a = this.pod) === null || _a === void 0 ? void 0 : _a.broadcastEvent(ev);
                        }
                    }
                }
            };
            this.linkupMessageCallback = (sender, receiver, message) => {
                var _a;
                if (this.linkupMessageListening.has(receiver.url())) {
                    const msg = message;
                    if (sender.url() === msg.source && receiver.url() === msg.destination) {
                        const destAgentId = msg.agentId;
                        const destAgent = (_a = this.pod) === null || _a === void 0 ? void 0 : _a.getAgent(destAgentId);
                        if (destAgent !== undefined) {
                            let ev = {
                                type: exports.NetworkEventType.LinkupMessageReceived,
                                content: msg
                            };
                            destAgent.receiveLocalEvent(ev);
                        }
                    }
                }
            };
            this.tick = () => {
                let toCleanUp = new Array();
                // check connection health / startup timeouts
                // check agent set request timeout if connection is healthy
                for (const conn of this.connections.values()) {
                    let callId = conn.getConnectionId();
                    let info = this.connectionInfo.get(callId);
                    if (info.status === exports.ConnectionStatus.Received || info.status === exports.ConnectionStatus.Establishing) {
                        if (Date.now() > info.timestamp + (1000 * ConnectionEstablishmentTimeout)) {
                            toCleanUp.push(callId);
                            NetworkAgent.connLogger.trace(() => 'Cleaning up connection (establishment timeout reached): ' + info.connId + ', remote ep is ' + info.remoteEndpoint);
                        }
                    }
                    else if (!conn.channelIsOperational()) {
                        toCleanUp.push(callId);
                        NetworkAgent.connLogger.trace(() => 'Cleaning up connection (channel is not operational): ' + info.connId + ', remote ep is ' + info.remoteEndpoint);
                    }
                }
                for (const connectionId of toCleanUp) {
                    let conn = this.connections.get(connectionId);
                    this.connectionCloseCleanup(connectionId);
                    try {
                        conn === null || conn === void 0 ? void 0 : conn.close();
                    }
                    catch (e) {
                        //
                    }
                }
            };
            if ((proxyConfig === null || proxyConfig === void 0 ? void 0 : proxyConfig.linkupEventIngestFn) !== undefined) {
                this.linkupManagerHost = new LinkupManagerHost(proxyConfig.linkupEventIngestFn, this.linkupManager);
            }
            if ((proxyConfig === null || proxyConfig === void 0 ? void 0 : proxyConfig.webRTCCommandFn) !== undefined) {
                this.connProxies = new Map();
                this.webRTCConnEventIngestFn = (ev) => {
                    var _a, _b;
                    const proxy = (_a = this.connProxies) === null || _a === void 0 ? void 0 : _a.get(ev.connId);
                    if (proxy === undefined) {
                        this.logger.warning('Receivd connection event for ' + ev.connId + ', but there is no registered proxy.');
                    }
                    proxy === null || proxy === void 0 ? void 0 : proxy.connectionEventIngestFn(ev);
                    if (ev.type === 'connection-status-change' && ev.status === 'closed') {
                        (_b = this.connProxies) === null || _b === void 0 ? void 0 : _b.delete(ev.connId);
                    }
                };
            }
            /*
            this.worker = globalThis.process?.versions?.node === undefined && globalThis.document === undefined;

            if (this.worker) {

                const eventCallback = (ev: LinkupManagerEvent) => {
                    (globalThis as any as ServiceWorker).postMessage(ev);
                }

                this.linkupManagerHost = new LinkupManagerProxyHost(eventCallback, this.linkupManager);
            
                const sendToWebRTCProxyHost = (cmd: WebRTCConnectionCommand) => {
                    globalThis.postMessage(cmd);
                };

            }
            */
        }
        getAgentId() {
            return NetworkAgent.AgentId;
        }
        /*
        public linkupManagerHostCommand(cmd: LinkupManagerCommand) {
            this.linkupManagerHost?.execute(cmd);
        }

        public createWebRTCConnectionProxy() {
            globalThis.postMessage
        }
        */
        acceptReceivedConnectionMessages(connId, message) {
            var _a, _b, _c;
            let messages = this.deferredInitialMessages.get(connId);
            if (messages === undefined) {
                messages = [];
            }
            if (message !== undefined) {
                messages.push(message);
            }
            for (const message of messages) {
                let conn = this.connections.get(connId);
                if (conn === undefined) {
                    let connInfo = this.connectionInfo.get(connId);
                    if (connInfo !== undefined) {
                        const receiver = LinkupAddress.fromURL(connInfo.localEndpoint);
                        const sender = LinkupAddress.fromURL(connInfo.remoteEndpoint);
                        if (SignallingServerConnection.isWebRTCBased(connInfo.remoteEndpoint)) {
                            if (SignallingServerConnection.isWebRTCBased(connInfo.localEndpoint)) {
                                if (((_a = this.proxyConfig) === null || _a === void 0 ? void 0 : _a.webRTCCommandFn) === undefined) {
                                    conn = new WebRTCConnection(this.linkupManager, receiver, sender, connId, this.connectionReadyCallback);
                                }
                                else {
                                    const connProxy = new WebRTCConnectionProxy(receiver, sender, connId, this.connectionReadyCallback, (_b = this.proxyConfig) === null || _b === void 0 ? void 0 : _b.webRTCCommandFn);
                                    (_c = this.connProxies) === null || _c === void 0 ? void 0 : _c.set(connId, connProxy);
                                    conn = connProxy;
                                }
                            }
                            else {
                                conn = new WebSocketConnection(connId, receiver, sender, this.connectionReadyCallback);
                            }
                        }
                        else {
                            conn = new WebSocketConnection(connId, receiver, sender, this.connectionReadyCallback);
                        }
                    }
                    if (conn instanceof WebRTCConnection || conn instanceof WebRTCConnectionProxy || conn instanceof WebSocketConnection) {
                        conn.setMessageCallback(this.messageCallback);
                        conn.answer(message);
                    }
                }
                else {
                    if (conn instanceof WebRTCConnection || conn instanceof WebRTCConnectionProxy) {
                        conn.receiveSignallingMessage(message);
                    }
                    else if (conn instanceof WebSocketConnection) {
                        conn.answer(message);
                    }
                }
                if (conn !== undefined) {
                    this.connections.set(connId, conn);
                }
            }
        }
        deferReceivedConnectionMessage(connId, message) {
            let messages = this.deferredInitialMessages.get(connId);
            if (messages === undefined) {
                messages = new Array();
                this.deferredInitialMessages.set(connId, messages);
            }
            messages.push(message);
        }
        // Network listen, shutdown
        listen(endpoint) {
            let address = LinkupAddress.fromURL(endpoint);
            this.listening.add(endpoint);
            this.linkupManager.listenForQueryResponses(endpoint, (ep, addresses) => {
                var _a;
                if (this.listening.has(ep)) {
                    this.connLogger.debug(ep + ' received listening notice of ' + addresses.map((l) => l.url()));
                    for (const address of addresses) {
                        let ev = {
                            type: exports.NetworkEventType.RemoteAddressListening,
                            content: {
                                remoteEndpoint: address.url()
                            }
                        };
                        (_a = this.pod) === null || _a === void 0 ? void 0 : _a.broadcastEvent(ev);
                    }
                }
                else {
                    this.connLogger.debug('received wrongly addressed listenForQueryResponse message, was meant for ' + ep + ' which is not listening in this network node.');
                }
            });
            this.logger.debug('Listening for endpoint ' + endpoint);
            this.linkupManager.listenForMessagesNewCall(address, this.newConnectionRequestCallback);
        }
        listenForLinkupMessages(endpoint) {
            let address = LinkupAddress.fromURL(endpoint);
            this.linkupMessageListening.add(endpoint);
            this.linkupManager.listenForRawMessages(address, this.linkupMessageCallback);
        }
        //FIXME: remainder: do ws cleanup for not-yet-accepted connections here as well.
        shutdown() {
            this.linkupManager.shutdown();
            if (this.intervalRef !== undefined) {
                clearInterval(this.intervalRef);
                this.intervalRef = undefined;
            }
            for (const conn of this.connections.values()) {
                this.connectionInfo.delete(conn.getConnectionId());
                this.connections.delete(conn.getConnectionId());
                conn.close();
            }
        }
        // Connection management: connect-disconnect, find out which addresses are online
        //                        at the moment, recover the endpoint for a current callId.
        connect(local, remote, requestedBy) {
            var _a, _b, _c;
            this.connLogger.debug(local + ' is asking for connection to ' + remote);
            const localAddress = LinkupAddress.fromURL(local);
            const remoteAddress = LinkupAddress.fromURL(remote);
            const callId = new BrowserRNG().randomHexString(BITS_FOR_CONN_ID);
            this.connectionInfo.set(callId, {
                localEndpoint: local,
                remoteEndpoint: remote,
                connId: callId, status: exports.ConnectionStatus.Establishing,
                timestamp: Date.now(),
                requestedBy: new Set([requestedBy])
            });
            let conn;
            if (SignallingServerConnection.isWebRTCBased(remoteAddress.url())) {
                if (SignallingServerConnection.isWebRTCBased(localAddress.url())) {
                    if (((_a = this.proxyConfig) === null || _a === void 0 ? void 0 : _a.webRTCCommandFn) === undefined) {
                        conn = new WebRTCConnection(this.linkupManager, localAddress, remoteAddress, callId, this.connectionReadyCallback);
                    }
                    else {
                        const connProxy = new WebRTCConnectionProxy(localAddress, remoteAddress, callId, this.connectionReadyCallback, (_b = this.proxyConfig) === null || _b === void 0 ? void 0 : _b.webRTCCommandFn);
                        (_c = this.connProxies) === null || _c === void 0 ? void 0 : _c.set(callId, connProxy);
                        conn = connProxy;
                    }
                }
                else {
                    conn = new WebSocketConnection(callId, localAddress, remoteAddress, this.connectionReadyCallback, this.linkupManager);
                }
            }
            else {
                conn = new WebSocketConnection(callId, localAddress, remoteAddress, this.connectionReadyCallback);
            }
            conn.setMessageCallback(this.messageCallback);
            this.connections.set(callId, conn);
            conn.open();
            return callId;
        }
        acceptConnection(connId, requestedBy) {
            let connInfo = this.connectionInfo.get(connId);
            if (connInfo === undefined) {
                throw new Error('Connection with id ' + connId + ' no longer exists (if it ever did).');
            }
            if (connInfo.status === exports.ConnectionStatus.Received) {
                // FIRST set connection status to Establishing
                connInfo.status = exports.ConnectionStatus.Establishing;
                // THEN invoke accept (since it may set status to something else, like Ready)
                this.acceptReceivedConnectionMessages(connId);
            }
            if (connInfo.status !== exports.ConnectionStatus.Closed) {
                connInfo.requestedBy.add(requestedBy);
            }
        }
        releaseConnectionIfExists(id, requestedBy) {
            try {
                this.releaseConnection(id, requestedBy);
            }
            catch (e) {
                // pass
            }
        }
        releaseConnection(id, requestedBy) {
            const conn = this.connections.get(id);
            if (conn === undefined) {
                throw new Error('Asked to disconnect callId ' + id + ' but there is no such connection.');
            }
            let connInfo = this.connectionInfo.get(id);
            this.connLogger.debug('connection ' + id + ' is being released by agent ' + requestedBy + ' on ' + (connInfo === null || connInfo === void 0 ? void 0 : connInfo.localEndpoint));
            connInfo === null || connInfo === void 0 ? void 0 : connInfo.requestedBy.delete(requestedBy);
            if ((connInfo === null || connInfo === void 0 ? void 0 : connInfo.requestedBy.size) === 0) {
                this.connLogger.debug('connection ' + id + ' is no longer being used on ' + (connInfo === null || connInfo === void 0 ? void 0 : connInfo.localEndpoint) + ', closing');
                conn.close();
                this.connectionCloseCleanup(id);
            }
        }
        checkConnection(id) {
            var _a;
            if (this.connectionIsReady(id)) {
                let operational = (_a = this.connections.get(id)) === null || _a === void 0 ? void 0 : _a.channelIsOperational();
                if (!operational) {
                    this.connectionCloseCleanup(id);
                }
                return operational;
            }
            else {
                return false;
            }
        }
        queryForListeningAddresses(source, targets) {
            if (this.listening.has(source.url())) {
                this.connLogger.log(source.url() + ' asking if any is online: ' + targets.map((l) => l.url()), LogLevel.DEBUG);
                this.linkupManager.queryForListeningAddresses(source.url(), targets);
            }
            else {
                this.connLogger.error(source.url() + ' is querying for online addresses, but it is not listening on this network.');
                throw new Error('Looking for online targets for endpoint ' + source.url() + ' but that endpoint is not listening on this network.');
            }
        }
        getAllConnectionsInfo() {
            return Array.from(this.connectionInfo.values()).map((ci) => Object.assign({}, ci));
        }
        getConnectionInfo(id) {
            let ci = this.connectionInfo.get(id);
            if (ci !== undefined) {
                ci = Object.assign({}, ci);
            }
            return ci;
        }
        connectionIsReady(id) {
            var _a;
            return ((_a = this.connectionInfo.get(id)) === null || _a === void 0 ? void 0 : _a.status) === exports.ConnectionStatus.Ready;
        }
        connectionSendBufferIsEmpty(id) {
            const conn = this.connections.get(id);
            if (conn !== undefined) {
                return conn.bufferedAmount() === 0;
            }
            else {
                return false;
            }
        }
        getConnIdsForEndpoints(local, remote) {
            let connIds = new Set();
            for (const connInfo of this.connectionInfo.values()) {
                if (connInfo.localEndpoint === local && connInfo.remoteEndpoint === remote) {
                    connIds.add(connInfo.connId);
                    break;
                }
            }
            return connIds;
        }
        // Sends a cleartext message, even if no peer has been configured for that connection.
        // Meant to be used in peer authentication & set up.
        sendMessage(connId, agentId, content) {
            this.messageLogger.trace(() => { var _a, _b; return 'Endpoint ' + ((_a = this.connectionInfo.get(connId)) === null || _a === void 0 ? void 0 : _a.localEndpoint) + ' is sending message to ' + ((_b = this.connectionInfo.get(connId)) === null || _b === void 0 ? void 0 : _b.remoteEndpoint) + ':\n' + JSON.stringify(content); });
            const conn = this.connections.get(connId);
            const connInfo = this.connectionInfo.get(connId);
            if (conn === undefined || connInfo === undefined) {
                throw new Error('Attempted to send message on connection ' + connId + ', but the connection is no longer available.');
            }
            let message = {
                connectionId: connId,
                source: connInfo.localEndpoint,
                destination: connInfo.remoteEndpoint,
                agentId: agentId,
                content: content
            };
            if (this.testingMode) {
                const dice = Math.random();
                if (dice < 0.01) ;
                else if (dice < 0.02) {
                    // delay
                    const delay = Math.random() * 5000;
                    new Promise(r => setTimeout(r, delay)).then(() => { conn.send(JSON.stringify(message)); }).catch(() => { });
                }
                else if (dice < 0.03) {
                    // truncate
                    conn.send(JSON.stringify(message).substring(0, 100));
                }
                else {
                    // send allright
                    conn.send(JSON.stringify(message));
                }
                return;
            }
            conn.send(JSON.stringify(message));
        }
        sendLinkupMessage(sourceAddress, destinationAddress, agentId, content, sendLimit) {
            let linkupMessage = {
                source: sourceAddress.url(),
                destination: destinationAddress.url(),
                agentId: agentId,
                content: content
            };
            this.linkupManager.sendRawMessage(sourceAddress, destinationAddress, linkupMessage, sendLimit);
        }
        connectionCloseCleanup(id) {
            var _a;
            let connInfo = this.connectionInfo.get(id);
            let ev = {
                type: exports.NetworkEventType.ConnectionStatusChange,
                content: {
                    connId: id,
                    localEndpoint: connInfo.localEndpoint,
                    remoteEndpoint: connInfo.remoteEndpoint,
                    status: exports.ConnectionStatus.Closed
                }
            };
            (_a = this.pod) === null || _a === void 0 ? void 0 : _a.broadcastEvent(ev);
            this.connectionInfo.delete(id);
            this.connections.delete(id);
            this.deferredInitialMessages.delete(id);
        }
        ready(pod) {
            this.pod = pod;
            this.intervalRef = setInterval(this.tick, TickInterval * 1000);
        }
        receiveLocalEvent(ev) {
        }
        receiveMessage(msg) {
            var _a;
            let ev = {
                type: exports.NetworkEventType.MessageReceived,
                content: msg
            };
            const agent = (_a = this.pod) === null || _a === void 0 ? void 0 : _a.getAgent(msg.agentId);
            if (agent !== undefined) {
                agent.receiveLocalEvent(ev);
            }
        }
    }
    NetworkAgent.AgentId = 'network-agent';
    NetworkAgent.logger = new Logger(NetworkAgent.name, LogLevel.INFO);
    NetworkAgent.connLogger = new Logger(NetworkAgent.name + ' conn', LogLevel.INFO);
    NetworkAgent.messageLogger = new Logger(NetworkAgent.name + ' msg', LogLevel.INFO);

    class HMAC {
        hmacSHA256hex(message, key) {
            const sha = new JSHashesSHA();
            const blockLengthHex = 128;
            //const digestLengthHex = 64;
            let shortKey = key;
            if (key.length > blockLengthHex) {
                shortKey = sha.sha256hex(key);
            }
            let ipad = '';
            let opad = '';
            let ipadConst = 0x36;
            let opadConst = 0x5c;
            for (let i = 0; i < blockLengthHex; i++) {
                let ipadVal = ipadConst;
                let opadVal = opadConst;
                if (i < shortKey.length) {
                    const keyVal = Number.parseInt(shortKey[i], 16);
                    ipadVal = ipadVal ^ keyVal;
                    opadVal = opadVal ^ keyVal;
                }
                ipad = ipad + ipadVal.toString(16).padStart(2, '0');
                opad = opad + opadVal.toString(16).padStart(2, '0');
            }
            const hash1 = sha.sha256hex(ipad + message);
            const hash2 = sha.sha256hex(opad + hash1);
            return hash2;
        }
    }

    var IdHolderStatus;
    (function (IdHolderStatus) {
        IdHolderStatus["ExpectingChallenge"] = "expecting-challenge";
        IdHolderStatus["ReceivedUnexpectedChallenge"] = "received-unexpected-challenge";
        IdHolderStatus["ReceivedUnexpectedIdentityRequest"] = "received-unexpected-identity-request";
        IdHolderStatus["SentIdentity"] = "sent-identity";
        IdHolderStatus["SentChallengeAnswer"] = "sent-challenge-answer";
        IdHolderStatus["IdentityVerified"] = "identity-verified";
        IdHolderStatus["IdentityRejected"] = "identity-rejected";
    })(IdHolderStatus || (IdHolderStatus = {}));
    var IdChallengerStatus;
    (function (IdChallengerStatus) {
        IdChallengerStatus["WaitingToChallenge"] = "waiting-to-challenge";
        IdChallengerStatus["SentIdentityRequest"] = "sent-identity-request";
        IdChallengerStatus["SentChallenge"] = "sent-challenge";
        IdChallengerStatus["IdentityVerified"] = "identity-verified";
        IdChallengerStatus["IdentityRejected"] = "identity-rejected";
    })(IdChallengerStatus || (IdChallengerStatus = {}));
    // The following state machine models conneciton validation:
    // id holder:
    // nil -> 'received-unexpected-identity-request'     on 'request-identity' message reception
    // nil -> 'received-unexpected-challenge'            on 'send-challenge'   message reception
    // nil -> 'expecting-challenge'                      on answerIdentityChallenge() call
    // 'expecting-challenge' -> 'sent-identity'          on 'request-identity' message reception
    // 'sent-identity'       -> 'sent-challenge-answer'  on 'send-challenge'   message reception
    // 'expecting-challenge' -> 'sent-challenge-answer'  on 'send-challenge'   message reception
    // 'sent-challenge-answer' -> 'identity-verified'    on 'challenge-result' message reception (accepted)
    // 'sent-challenge-answer' -> 'identity-rejected'    on 'challenge-result' message reception (rejected)
    // id challenger:
    // nil -> 'waiting-to-challenge'      on sendIdentityChallenge() call (connection not ready yet)
    // nil -> 'sent-identity-request'     on sendIdentityChallenge() call, without identity (connected)
    // nil -> 'sent-challenge'            on sendIdentityChallenge() call, with identity    (connected)
    // 'waiting-to-challenge'  -> 'sent-identity-request' on connection ready, no identity
    // 'waiting-to-challenge'  -> 'sent-challenge'        on connection ready, identity present
    // 'sent-identity-request' -> 'sent-challenge'     on 'send-identity' message reception
    // 'sent-challente'        -> 'identity-verified'  on 'answer-challenge' message reception (accepted)
    // 'sent-challenge'        -> 'identity-rejected'  on 'answer-challenge'  message reception (rejected)
    var MessageType;
    (function (MessageType) {
        MessageType["RequestIdentity"] = "request-identity";
        MessageType["SendIdentity"] = "send-identity";
        MessageType["SendChallenge"] = "send-challenge";
        MessageType["AnswerChallenge"] = "answer-challenge";
        MessageType["ChallengeResult"] = "challenge-result";
        MessageType["SecureMessage"] = "secure-message";
    })(MessageType || (MessageType = {}));
    exports.SecureNetworkEventType = void 0;
    (function (SecureNetworkEventType) {
        SecureNetworkEventType["SecureMessageReceived"] = "secure-message-received";
        SecureNetworkEventType["ConnectionIdentityAuth"] = "connection-identity-auth";
    })(exports.SecureNetworkEventType || (exports.SecureNetworkEventType = {}));
    exports.IdentityAuthStatus = void 0;
    (function (IdentityAuthStatus) {
        IdentityAuthStatus["Accepted"] = "accepted";
        IdentityAuthStatus["Rejected"] = "rejected";
        IdentityAuthStatus["Requested"] = "requested";
    })(exports.IdentityAuthStatus || (exports.IdentityAuthStatus = {}));
    exports.IdentityLocation = void 0;
    (function (IdentityLocation) {
        IdentityLocation["Local"] = "local";
        IdentityLocation["Remote"] = "remote";
    })(exports.IdentityLocation || (exports.IdentityLocation = {}));
    class OneWaySecuredConnection {
        constructor(connectionId, identityHash) {
            this.connId = connectionId;
            this.identityHash = identityHash;
        }
        verified() {
            return this.status === IdHolderStatus.IdentityVerified;
        }
        generateSecret() {
            this.secret = new BrowserRNG().randomHexString(256);
            // use 256 bits so it can be use as a ChaCha20 key
        }
        async encryptSecret() {
            if (this.secret === undefined) {
                throw new Error('Attempted to encrypt connection secret before generating it.');
            }
            if (this.identity === undefined) {
                throw new Error('Attempted to encrypt connection secret, but identity is missing.');
            }
            const encryptedSecret = new Array();
            for (const chunk of Strings.chunk(this.secret, 32)) {
                encryptedSecret.push(await this.identity.encrypt(chunk));
            }
            this.encryptedSecret = encryptedSecret;
        }
        async decryptSecret() {
            if (this.identity === undefined) {
                throw new Error('Secured connection cannot decrypt received secret: identity is missing');
            }
            if (!this.identity.hasKeyPair()) {
                throw new Error('Secured connection cannot decrypt received secret: using an identity without a key pair');
            }
            if (this.encryptedSecret === undefined) {
                throw new Error('Secured connection cannot decrypt received secret: it is missing');
            }
            const chunks = new Array();
            for (const encryptedChunk of this.encryptedSecret) {
                chunks.push(await this.identity.decrypt(encryptedChunk));
            }
            this.secret = Strings.unchunk(chunks);
        }
        computeSecretHash() {
            if (this.secret === undefined) {
                throw new Error('Cannot hash secret: it is missing');
            }
            return Hashing.forString(this.secret);
        }
        setTimeout(seconds) {
            this.timeout = new Date().getTime() + seconds * 1000;
        }
        encode() {
            return OneWaySecuredConnection.encode(this.connId, this.identityHash);
        }
        static encode(connectionId, identity) {
            return connectionId + OneWaySecuredConnection.Separator + identity;
        }
        static decode(encoded) {
            const parts = encoded.split(OneWaySecuredConnection.Separator);
            return new OneWaySecuredConnection(parts[0], parts[1]);
        }
    }
    OneWaySecuredConnection.Separator = '__';
    class ConnectionSecuredForReceiving extends OneWaySecuredConnection {
        constructor(connectionId, identityHash) {
            super(connectionId, identityHash);
        }
    }
    class ConnectionSecuredForSending extends OneWaySecuredConnection {
        constructor(connectionId, identityHash) {
            super(connectionId, identityHash);
        }
    }
    const DEFAULT_TIMEOUT = 15;
    const MAX_PAYLOAD_SIZE = 32 * 1024;
    const MAX_MESSAGE_FRAGMENTS = 64;
    const FRAGMENT_ASSEMBLY_TIMEOUT_FREQ = 2;
    class SecureNetworkAgent {
        constructor() {
            this.remoteIdentities = new Map();
            this.localIdentities = new Map();
            this.messageFragments = new Map();
            this.fragmentAssemblyInterval = undefined;
            this.fragmentAssemblyTimeouts = this.fragmentAssemblyTimeouts.bind(this);
        }
        checkFragmentAssemblyInterval() {
            if (this.messageFragments.size === 0) {
                if (this.fragmentAssemblyInterval !== undefined) {
                    clearInterval(this.fragmentAssemblyInterval);
                }
            }
            else {
                if (this.fragmentAssemblyInterval === undefined) {
                    setInterval(this.fragmentAssemblyTimeouts, FRAGMENT_ASSEMBLY_TIMEOUT_FREQ * 1000);
                }
            }
        }
        fragmentAssemblyTimeouts() {
            const toRemove = new Array();
            for (const [id, partialMsg] of this.messageFragments.entries()) {
                const timeout = Math.max(12000, 600 * partialMsg.fragCount) + partialMsg.created;
                const updateTimeout = Math.max(timeout, 6000 + partialMsg.updated);
                const now = Date.now();
                if (now > timeout && now > updateTimeout) {
                    toRemove.push(id);
                    SecureNetworkAgent.logger.warning('Removed message ' + id + ' due to re-assembly timeout!');
                }
            }
            for (const id of toRemove) {
                this.messageFragments.delete(id);
            }
            if (toRemove.length > 0) {
                this.checkFragmentAssemblyInterval();
            }
        }
        getAgentId() {
            return SecureNetworkAgent.Id;
        }
        ready(pod) {
            this.pod = pod;
        }
        receiveLocalEvent(ev) {
            if (ev.type === exports.NetworkEventType.ConnectionStatusChange) {
                let connEv = ev;
                if (connEv.content.status === exports.ConnectionStatus.Closed) {
                    this.removeIdentitiesForConnection(ev.content.connId);
                }
                else if (connEv.content.status === exports.ConnectionStatus.Ready) {
                    for (const secured of this.remoteIdentities.values()) {
                        if (secured.connId === connEv.content.localEndpoint &&
                            secured.status === IdChallengerStatus.WaitingToChallenge) {
                            this.sendChallengeMessage(secured);
                        }
                    }
                }
            }
            else if (ev.type === exports.NetworkEventType.MessageReceived) {
                let msgEv = ev;
                this.receiveMessage(msgEv.content.connectionId, msgEv.content.source, msgEv.content.destination, msgEv.content.content);
            }
        }
        // for identity holder:
        secureForReceiving(connId, localIdentity, timeout = DEFAULT_TIMEOUT) {
            SecureNetworkAgent.logger.trace('Asked to verify ' + connId + ' for receiving with ' + localIdentity.hash());
            const identityHash = localIdentity.hash();
            let secured = this.getOrCreateConnectionSecuredForReceiving(connId, identityHash);
            secured.identity = localIdentity;
            secured.setTimeout(timeout);
            if (secured.status === IdHolderStatus.ReceivedUnexpectedIdentityRequest) {
                this.sendIdentity(connId, localIdentity, identityHash);
                secured.status = IdHolderStatus.SentIdentity;
            }
            else if (secured.status === IdHolderStatus.ReceivedUnexpectedChallenge) {
                secured.decryptSecret().then(() => {
                    //TODO: see if we have introduced a race condition by making decryptSecret async.
                    this.answerReceivedChallenge(connId, identityHash, secured.computeSecretHash());
                    secured.status = IdHolderStatus.SentChallengeAnswer;
                });
            }
            else if (secured.status === undefined) {
                secured.status = IdHolderStatus.ExpectingChallenge;
            } // else, negotiation is already running, just let it run its course
        }
        // for identity challenger:
        secureForSending(connId, remoteIdentityHash, remoteIdentity, timeout = DEFAULT_TIMEOUT) {
            let connInfo = this.getNetworkAgent().getConnectionInfo(connId);
            if ((connInfo === null || connInfo === void 0 ? void 0 : connInfo.status) !== exports.ConnectionStatus.Closed) {
                let secured = this.getOrCreateConnectionSecuredForSending(connId, remoteIdentityHash);
                secured.setTimeout(timeout);
                if (secured.identity === undefined) {
                    secured.identity = remoteIdentity;
                }
                if ((connInfo === null || connInfo === void 0 ? void 0 : connInfo.status) === exports.ConnectionStatus.Ready) {
                    if (secured.status === undefined || secured.status === 'identity-rejected') {
                        this.sendChallengeMessage(secured);
                    } // else, negotiation is already running, just let it run its course
                }
                else if ((connInfo === null || connInfo === void 0 ? void 0 : connInfo.status) === exports.ConnectionStatus.Received ||
                    (connInfo === null || connInfo === void 0 ? void 0 : connInfo.status) === exports.ConnectionStatus.Establishing) {
                    secured.status = IdChallengerStatus.WaitingToChallenge;
                }
            }
        }
        sendChallengeMessage(secured) {
            if (secured.identity === undefined) {
                this.sendIdentityRequest(secured.connId, secured.identityHash);
                secured.status = IdChallengerStatus.SentIdentityRequest;
                SecureNetworkAgent.logger.trace('Sent identity request for ' + secured.identityHash + ' through connection ' + secured.connId);
            }
            else {
                SecureNetworkAgent.logger.trace('Sending identity challenge for ' + secured.identityHash + ' through connection ' + secured.connId);
                secured.generateSecret();
                //TODO: see if we have introduced a race condition by making encryptSecret async
                secured.encryptSecret().then(() => {
                    this.sendKnownIdentityChallenge(secured.connId, secured.identityHash, secured.encryptedSecret);
                    secured.status = IdChallengerStatus.SentChallenge;
                });
            }
        }
        // query for already verified local or remote identities
        getLocalVerifiedIdentity(connId, identityHash) {
            return this.getVerifiedIdentity(connId, identityHash, true);
        }
        getRemoteVerifiedIdentity(connId, identityHash) {
            return this.getVerifiedIdentity(connId, identityHash, false);
        }
        // messaging, usable once both supplied identities (sender & recipient) 
        // have been verified on that connection
        sendSecurely(connId, sender, recipient, agentId, content) {
            let remote = this.getConnectionSecuredForSending(connId, recipient);
            let local = this.getConnectionSecuredForReceiving(connId, sender);
            if ((remote === null || remote === void 0 ? void 0 : remote.verified()) && (local === null || local === void 0 ? void 0 : local.verified())) {
                let secureMessagePayload = {
                    senderIdentityHash: sender,
                    agentId: agentId,
                    content: content
                };
                let plaintext = JSON.stringify(secureMessagePayload);
                let nonce = new BrowserRNG().randomHexString(96);
                let payload = new ChaCha20Universal().encryptHex(plaintext, remote.secret, nonce);
                let hmac = new HMAC().hmacSHA256hex(payload, local.secret);
                if (plaintext.length < MAX_PAYLOAD_SIZE) {
                    let secureMessage = {
                        type: MessageType.SecureMessage,
                        identityHash: recipient,
                        nonce: nonce,
                        payload: payload,
                        hmac: hmac
                    };
                    this.getNetworkAgent().sendMessage(connId, SecureNetworkAgent.Id, secureMessage);
                }
                else {
                    let chunks = Strings.chunk(payload, MAX_PAYLOAD_SIZE);
                    let msgId = new BrowserRNG().randomHexString(128);
                    let seq = 0;
                    if (chunks.length <= MAX_MESSAGE_FRAGMENTS) {
                        for (const chunk of chunks) {
                            let secureMessage = {
                                type: MessageType.SecureMessage,
                                identityHash: recipient,
                                nonce: nonce,
                                payload: chunk,
                                hmac: hmac,
                                id: msgId,
                                fragSeq: seq,
                                fragCount: chunks.length
                            };
                            this.getNetworkAgent().sendMessage(connId, SecureNetworkAgent.Id, secureMessage);
                            seq = seq + 1;
                        }
                    }
                    else {
                        SecureNetworkAgent.logger.error('Cannot send message! It needs ' + chunks.length + ' fragments and the max allowed is ' + MAX_MESSAGE_FRAGMENTS + '.');
                    }
                }
            }
            else {
                throw new Error('Connection ' + connId + ' still has not verified both sender ' + sender + ' and recipient ' + recipient + '.');
            }
        }
        // incoming message processing
        receiveMessage(connId, source, destination, content) {
            var _a;
            let controlMessage = content;
            let identityHash = controlMessage.identityHash;
            SecureNetworkAgent.logger.trace(() => 'Received message ' + JSON.stringify(content));
            // for id holder:
            if (controlMessage.type === MessageType.RequestIdentity) {
                let secured = this.getOrCreateConnectionSecuredForReceiving(connId, identityHash);
                if (secured.status === IdHolderStatus.ExpectingChallenge) {
                    this.sendIdentity(connId, secured.identity, identityHash);
                    secured.status = IdHolderStatus.SentIdentity;
                }
                else if (secured.status === undefined) {
                    secured.status = IdHolderStatus.ReceivedUnexpectedIdentityRequest;
                    this.sendAuthEvent(connId, exports.IdentityLocation.Local, identityHash, exports.IdentityAuthStatus.Requested, secured.identity);
                }
            }
            else if (controlMessage.type === MessageType.SendChallenge) {
                let sendChallengeMessage = content;
                let secured = this.getOrCreateConnectionSecuredForReceiving(connId, identityHash);
                if (secured.status === IdHolderStatus.ExpectingChallenge ||
                    secured.status === IdHolderStatus.SentIdentity) {
                    secured.encryptedSecret = sendChallengeMessage.encrypedSecret;
                    secured.decryptSecret().then(() => {
                        //TODO: see if we have introduced a race condition by making decryptSecret async.
                        this.answerReceivedChallenge(connId, identityHash, secured.computeSecretHash());
                        secured.status = IdHolderStatus.SentChallengeAnswer;
                    });
                }
                else if (secured.status === undefined) {
                    secured.encryptedSecret = sendChallengeMessage.encrypedSecret;
                    secured.status = IdHolderStatus.ReceivedUnexpectedChallenge;
                    this.sendAuthEvent(connId, exports.IdentityLocation.Local, identityHash, exports.IdentityAuthStatus.Requested, secured.identity);
                }
            }
            else if (controlMessage.type === MessageType.ChallengeResult) {
                let challengeResultMessage = content;
                let secured = this.getOrCreateConnectionSecuredForReceiving(connId, identityHash);
                if (secured.status === IdHolderStatus.SentChallengeAnswer) {
                    if (challengeResultMessage.result) {
                        secured.status = IdHolderStatus.IdentityVerified;
                    }
                    else {
                        secured.status = IdHolderStatus.IdentityRejected;
                    }
                    const authStatus = challengeResultMessage.result ? exports.IdentityAuthStatus.Accepted : exports.IdentityAuthStatus.Rejected;
                    this.sendAuthEvent(connId, exports.IdentityLocation.Local, secured.identityHash, authStatus, secured.identity);
                }
            }
            // for id challenger:
            else if (controlMessage.type === MessageType.SendIdentity) {
                let sendIdentityMessage = content;
                let secured = this.getOrCreateConnectionSecuredForSending(connId, identityHash);
                if (secured.status === IdChallengerStatus.SentIdentityRequest) {
                    let identity = HashedObject.fromLiteralContext(sendIdentityMessage.identity);
                    if (identity.hash() === identityHash && identity instanceof Identity) {
                        secured.identity = identity;
                        secured.generateSecret();
                        //TODO: see if we have introduced a race condition by making encryptSecret async
                        secured.encryptSecret().then(() => {
                            this.sendKnownIdentityChallenge(connId, identityHash, secured.encryptedSecret);
                            secured.status = IdChallengerStatus.SentChallenge;
                        });
                    }
                    else {
                        secured.status = IdChallengerStatus.IdentityRejected;
                    }
                }
            }
            else if (controlMessage.type === MessageType.AnswerChallenge) {
                let answerChallengeMessage = content;
                let secured = this.getOrCreateConnectionSecuredForSending(connId, identityHash);
                if (secured.status === IdChallengerStatus.SentChallenge) {
                    let accepted = answerChallengeMessage.secretHash === secured.computeSecretHash();
                    if (accepted) {
                        this.sendChallengeResult(connId, identityHash, true);
                        secured.status = IdChallengerStatus.IdentityVerified;
                    }
                    else {
                        this.sendChallengeResult(connId, identityHash, false);
                        secured.status = IdChallengerStatus.IdentityRejected;
                    }
                    const authStatus = accepted ? exports.IdentityAuthStatus.Accepted : exports.IdentityAuthStatus.Rejected;
                    this.sendAuthEvent(connId, exports.IdentityLocation.Remote, secured.identityHash, authStatus, secured.identity);
                }
            }
            // for both:
            else if (controlMessage.type === MessageType.SecureMessage) {
                let secureMessage = content;
                let local = this.getConnectionSecuredForReceiving(connId, secureMessage.identityHash);
                if (local === null || local === void 0 ? void 0 : local.verified()) {
                    let cyphertext = undefined;
                    if (secureMessage.id === undefined) {
                        cyphertext = secureMessage.payload;
                    }
                    else {
                        if (secureMessage.fragSeq !== undefined && secureMessage.fragCount !== undefined &&
                            secureMessage.fragCount <= MAX_MESSAGE_FRAGMENTS && secureMessage.fragSeq % 1 === 0 &&
                            0 <= secureMessage.fragSeq && secureMessage.fragSeq < secureMessage.fragCount) {
                            let partialMsg = this.messageFragments.get(secureMessage.id);
                            if (partialMsg === undefined) {
                                partialMsg = {
                                    created: Date.now(),
                                    updated: Date.now(),
                                    connId: connId,
                                    recipient: secureMessage.identityHash,
                                    fragCount: secureMessage.fragCount,
                                    fragments: new Map()
                                };
                                this.messageFragments.set(secureMessage.id, partialMsg);
                                this.checkFragmentAssemblyInterval();
                            }
                            else {
                                partialMsg.updated = Date.now();
                            }
                            if (partialMsg.connId === connId &&
                                partialMsg.recipient === secureMessage.identityHash &&
                                partialMsg.fragCount === secureMessage.fragCount &&
                                secureMessage.fragSeq < secureMessage.fragCount) {
                                partialMsg.fragments.set(secureMessage.fragSeq, secureMessage.payload);
                                if (partialMsg.fragments.size === partialMsg.fragCount) {
                                    const chunks = new Array();
                                    for (let i = 0; i < partialMsg.fragCount; i++) {
                                        const chunk = partialMsg.fragments.get(i);
                                        if (chunk !== undefined) {
                                            chunks.push(chunk);
                                        }
                                    }
                                    if (chunks.length === partialMsg.fragCount) {
                                        cyphertext = Strings.unchunk(chunks);
                                        this.messageFragments.delete(secureMessage.id);
                                        this.checkFragmentAssemblyInterval();
                                    }
                                    else {
                                        SecureNetworkAgent.logger.warning('Error reassembling msg ' + secureMessage.id);
                                    }
                                }
                            }
                        }
                        else {
                            SecureNetworkAgent.logger.warning('Incomplete message fragment: seq or fragments fields are missing or incorrect for ' + secureMessage.id + ': fragCount=' + secureMessage.fragCount + ', fragSeq=' + secureMessage.fragSeq + ' (sender is ' + source + ')');
                        }
                    }
                    if (cyphertext !== undefined) {
                        let payload = new ChaCha20Universal().decryptHex(cyphertext, local.secret, secureMessage.nonce);
                        let secureMessagePayload = JSON.parse(payload);
                        let remote = this.getConnectionSecuredForSending(connId, secureMessagePayload.senderIdentityHash);
                        if (remote === null || remote === void 0 ? void 0 : remote.verified()) {
                            let hmac = new HMAC().hmacSHA256hex(cyphertext, remote.secret);
                            if (secureMessage.hmac === hmac) {
                                let agent = (_a = this.pod) === null || _a === void 0 ? void 0 : _a.getAgent(secureMessagePayload.agentId);
                                if (agent !== undefined) {
                                    let event = {
                                        type: exports.SecureNetworkEventType.SecureMessageReceived,
                                        content: {
                                            connId: connId,
                                            sender: secureMessagePayload.senderIdentityHash,
                                            recipient: secureMessage.identityHash,
                                            payload: secureMessagePayload.content
                                        }
                                    };
                                    agent.receiveLocalEvent(event);
                                }
                            }
                            else {
                                SecureNetworkAgent.logger.warning('HMAC mismatch on received message on connection ' + connId);
                            }
                        }
                    }
                }
            }
        }
        shutdown() {
        }
        sendAuthEvent(connId, identityLocation, identityHash, status, identity) {
            var _a;
            let ev = {
                type: exports.SecureNetworkEventType.ConnectionIdentityAuth,
                content: {
                    connId: connId,
                    identityLocation: identityLocation,
                    identityHash: identityHash,
                    identity: identity,
                    status: status
                }
            };
            (_a = this.pod) === null || _a === void 0 ? void 0 : _a.broadcastEvent(ev);
        }
        sendIdentity(connId, identity, identityHash) {
            if (identityHash === undefined) {
                identityHash = identity.hash();
            }
            let content = {
                type: MessageType.SendIdentity,
                identityHash: identityHash,
                identity: identity.toLiteralContext()
            };
            SecureNetworkAgent.logger.trace('Sending id ' + identityHash + ' on ' + connId);
            this.sendControlMessage(connId, content);
        }
        answerReceivedChallenge(connId, identityHash, secretHash) {
            let content = {
                type: MessageType.AnswerChallenge,
                identityHash: identityHash,
                secretHash: secretHash
            };
            this.sendControlMessage(connId, content);
        }
        sendIdentityRequest(connId, identityHash) {
            let content = {
                type: MessageType.RequestIdentity,
                identityHash: identityHash
            };
            this.sendControlMessage(connId, content);
        }
        sendKnownIdentityChallenge(connId, identityHash, encryptedSecret) {
            let content = {
                type: MessageType.SendChallenge,
                identityHash: identityHash,
                encrypedSecret: encryptedSecret
            };
            this.sendControlMessage(connId, content);
        }
        sendChallengeResult(connId, identityHash, verified) {
            let content = {
                type: MessageType.ChallengeResult,
                identityHash: identityHash,
                result: verified
            };
            this.sendControlMessage(connId, content);
        }
        sendControlMessage(connId, content) {
            this.getNetworkAgent().sendMessage(connId, SecureNetworkAgent.Id, content);
        }
        getOrCreateConnectionSecuredForSending(connId, identityHash) {
            return this.getOneWaySecuredConnection(connId, identityHash, false, true);
        }
        getOrCreateConnectionSecuredForReceiving(connId, identityHash) {
            return this.getOneWaySecuredConnection(connId, identityHash, true, true);
        }
        getConnectionSecuredForSending(connId, identityHash) {
            return this.getOneWaySecuredConnection(connId, identityHash, false, false);
        }
        getConnectionSecuredForReceiving(connId, identityHash) {
            return this.getOneWaySecuredConnection(connId, identityHash, true, false);
        }
        getOneWaySecuredConnection(connId, identityHash, sender, create) {
            let key = OneWaySecuredConnection.encode(connId, identityHash);
            let map;
            if (sender) {
                map = this.localIdentities;
            }
            else {
                map = this.remoteIdentities;
            }
            let secured = map.get(key);
            if (create && secured === undefined) {
                if (sender) {
                    secured = new ConnectionSecuredForReceiving(connId, identityHash);
                }
                else {
                    secured = new ConnectionSecuredForSending(connId, identityHash);
                }
                secured.setTimeout(DEFAULT_TIMEOUT);
                map.set(key, secured);
            }
            return secured;
        }
        getVerifiedIdentity(connId, identityHash, local) {
            let sid = this.getOneWaySecuredConnection(connId, identityHash, local, false);
            let identity = undefined;
            if (sid !== undefined && sid.verified()) {
                identity = sid.identity;
            }
            return identity;
        }
        removeIdentitiesForConnection(id) {
            var _a;
            for (const verifiedIdentities of [this.remoteIdentities, this.localIdentities]) {
                const toRemove = new Array();
                for (const [k, v] of verifiedIdentities.entries()) {
                    if (v.connId === id) {
                        toRemove.push(k);
                    }
                }
                for (const k of toRemove) {
                    SecureNetworkAgent.logger.trace('Removing identity' + ((_a = verifiedIdentities.get(k)) === null || _a === void 0 ? void 0 : _a.identityHash) + ' from connection ' + id + ': it is being closed.');
                    verifiedIdentities.delete(k);
                }
            }
        }
        getNetworkAgent() {
            return this.pod.getAgent(NetworkAgent.AgentId);
        }
    }
    SecureNetworkAgent.logger = new Logger(SecureNetworkAgent.name, LogLevel.INFO);
    SecureNetworkAgent.Id = 'secure-connection-agent';

    var PeerConnectionStatus;
    (function (PeerConnectionStatus) {
        PeerConnectionStatus["Connecting"] = "connecting";
        PeerConnectionStatus["ReceivingConnection"] = "receiving-connection";
        PeerConnectionStatus["WaitingForOffer"] = "waiting-for-offer";
        PeerConnectionStatus["OfferSent"] = "offer-sent";
        PeerConnectionStatus["OfferAccepted"] = "offer-accepted";
        PeerConnectionStatus["Ready"] = "ready";
    })(PeerConnectionStatus || (PeerConnectionStatus = {}));
    // messages using during negotiation, before a connection has been secured:
    // (i.e. both parties have proved they have the right identity for this peer group)
    var PeerMeshAgentMessageType;
    (function (PeerMeshAgentMessageType) {
        PeerMeshAgentMessageType["PeeringOffer"] = "peering-offer";
        PeerMeshAgentMessageType["PeeringOfferReply"] = "peering-offer-reply";
    })(PeerMeshAgentMessageType || (PeerMeshAgentMessageType = {}));
    // secured connection: 
    var SecureMessageTypes;
    (function (SecureMessageTypes) {
        SecureMessageTypes["PeerMessage"] = "peer-message";
        SecureMessageTypes["ChooseConnection"] = "choose-connection";
        SecureMessageTypes["ConfirmChosenConnection"] = "confirm-chosen-connection";
    })(SecureMessageTypes || (SecureMessageTypes = {}));
    exports.PeerMeshEventType = void 0;
    (function (PeerMeshEventType) {
        PeerMeshEventType["NewPeer"] = "new-peer";
        PeerMeshEventType["LostPeer"] = "lost-peer";
    })(exports.PeerMeshEventType || (exports.PeerMeshEventType = {}));
    class PeerGroupAgent {
        constructor(peerGroupId, localPeer, peerSource, params) {
            this.controlLog = PeerGroupAgent.controlLog;
            this.peerGroupId = peerGroupId;
            this.localPeer = localPeer;
            this.peerSource = peerSource;
            this.connections = new Map();
            this.connectionsPerEndpoint = new Map();
            this.connectionAttemptTimestamps = new Map();
            this.onlineQueryTimestamps = new Map();
            this.chosenForDeduplication = new Map();
            if (params === undefined) {
                params = {};
            }
            this.params = {
                minPeers: params.minPeers || 6,
                maxPeers: params.maxPeers || 12,
                peerConnectionTimeout: params.peerConnectionTimeout || 20,
                peerConnectionAttemptInterval: params.peerConnectionAttemptInterval || 20,
                tickInterval: params.tickInterval || 5
            };
            this.tick = async () => {
                this.cleanUp();
                this.queryForOnlinePeers();
                this.deduplicateConnections();
            };
            this.stats = { connectionInit: 0, connectionAccpt: 0, connectionTimeouts: 0 };
        }
        getAgentId() {
            return PeerGroupAgent.agentIdForPeerGroup(this.peerGroupId);
        }
        getTopic() {
            return this.peerGroupId;
        }
        getLocalPeer() {
            return this.localPeer;
        }
        ready(pod) {
            this.controlLog.debug('Started PeerControlAgent on local ' + this.localPeer.endpoint + ' (id=' + this.localPeer.identityHash + ') for peerGroupId ' + this.peerGroupId);
            this.pod = pod;
            this.init();
        }
        async init() {
            const networkAgent = this.getNetworkAgent();
            networkAgent.listen(this.localPeer.endpoint);
            for (const ci of this.getNetworkAgent().getAllConnectionsInfo()) {
                if (ci.localEndpoint === this.localPeer.endpoint &&
                    this.getNetworkAgent().checkConnection(ci.connId)) {
                    let peer = await this.peerSource.getPeerForEndpoint(ci.remoteEndpoint);
                    if (this.shouldConnectToPeer(peer)) {
                        this.getNetworkAgent().acceptConnection(ci.connId, this.getAgentId());
                        let pc = this.addPeerConnection(ci.connId, peer, PeerConnectionStatus.OfferSent);
                        this.sendOffer(pc);
                    }
                }
            }
            this.queryForOnlinePeers();
            this.tickTimerRef = setInterval(this.tick, this.params.tickInterval * 1000);
        }
        getPeers() {
            let seen = new Set();
            let unique = new Array();
            for (const pc of this.connections.values()) {
                if (pc.status === PeerConnectionStatus.Ready && !seen.has(pc.peer.endpoint)) {
                    unique.push(pc.peer);
                    seen.add(pc.peer.endpoint);
                }
            }
            return unique;
        }
        validateConnectedPeer(ep) {
            let connId = this.findWorkingConnectionId(ep);
            return connId !== undefined;
        }
        // Peer messaging functions, to be used by other local agents:
        sendToAllPeers(agentId, content) {
            let count = 0;
            for (let ep of this.connectionsPerEndpoint.keys()) {
                if (this.sendToPeer(ep, agentId, content)) {
                    count = count + 1;
                }
            }
            this.controlLog.trace(this.localPeer.endpoint + ' sending message to all (' + count + ') peers.');
            return count;
        }
        sendToPeer(ep, agentId, content) {
            let connId = this.findWorkingConnectionId(ep);
            if (connId !== undefined) {
                try {
                    let pc = this.connections.get(connId);
                    let peerMsg = {
                        type: SecureMessageTypes.PeerMessage,
                        peerGroupId: this.peerGroupId,
                        agentId: agentId,
                        content: content
                    };
                    let secureConnAgent = this.getSecureConnAgent();
                    secureConnAgent.sendSecurely(connId, this.localPeer.identityHash, pc.peer.identityHash, this.getAgentId(), peerMsg);
                    this.controlLog.trace(this.localPeer.endpoint + ' sending peer message to ' + ep);
                    return true;
                }
                catch (e) {
                    this.controlLog.warning('Could not send message', e);
                    return false;
                }
            }
            else {
                this.controlLog.trace(this.localPeer.endpoint + ' could not send peer message to ' + ep);
                return false;
            }
        }
        peerSendBufferIsEmpty(ep) {
            let connId = this.findWorkingConnectionId(ep);
            if (connId !== undefined) {
                return this.getNetworkAgent().connectionSendBufferIsEmpty(connId);
            }
            else {
                return false;
            }
        }
        getStats() {
            let stats = {
                peers: 0,
                connections: this.connections.size,
                connectionsPerStatus: new Map()
            };
            for (const ep of this.connectionsPerEndpoint.keys()) {
                if (this.findWorkingConnectionId(ep) !== undefined) {
                    stats.peers += 1;
                }
            }
            for (const conn of this.connections.values()) {
                let c = stats.connectionsPerStatus.get(conn.status);
                if (c === undefined) {
                    c = 0;
                }
                stats.connectionsPerStatus.set(conn.status, c + 1);
            }
            return stats;
        }
        // Clean-up & new connection starting functions, called from the periodic tick
        cleanUp() {
            let now = Date.now();
            // Remove connections that:
            //   1. are ready, but the connection has been lost
            //   2. are not ready, and the connection timeout has elapsed
            for (const pc of Array.from(this.connections.values())) {
                if (pc.status === PeerConnectionStatus.Ready) {
                    if (!this.getNetworkAgent().checkConnection(pc.connId)) {
                        this.removePeerConnection(pc.connId);
                    }
                }
                else {
                    if (now > pc.timestamp + this.params.peerConnectionTimeout * 1000) {
                        this.stats.connectionTimeouts += 1;
                        this.removePeerConnection(pc.connId);
                    }
                }
            }
            // Remove connection attempt timestamps that are too old to make a difference.
            // (i.e. peerConnectionAttemptInterval has already elapsed and we can try to reconnect)
            for (const [endpoint, timestamp] of Array.from(this.connectionAttemptTimestamps.entries())) {
                if (now > timestamp + this.params.peerConnectionAttemptInterval * 1000) {
                    this.connectionAttemptTimestamps.delete(endpoint);
                }
            }
        }
        async queryForOnlinePeers() {
            PeerGroupAgent.peersLog.trace("Considering querying for peers on " + this.peerGroupId);
            if (this.connectionsPerEndpoint.size < this.params.minPeers) {
                let candidates = await this.peerSource.getPeers(this.params.minPeers * 5);
                let endpoints = new Array();
                let fallbackEndpoints = new Array();
                const now = Date.now();
                PeerGroupAgent.peersLog.debug('Looking for peers, got ' + candidates.length + ' candidates');
                for (const candidate of candidates) {
                    if (this.localPeer.endpoint === candidate.endpoint) {
                        continue;
                    }
                    if (this.connectionsPerEndpoint.get(candidate.endpoint) !== undefined) {
                        continue;
                    }
                    const lastQueryTimestamp = this.onlineQueryTimestamps.get(candidate.endpoint);
                    if (lastQueryTimestamp !== undefined &&
                        now < lastQueryTimestamp + this.params.peerConnectionAttemptInterval * 1000) {
                        continue;
                    }
                    const lastAttemptTimestamp = this.connectionAttemptTimestamps.get(candidate.endpoint);
                    if (fallbackEndpoints.length < this.params.minPeers - this.connectionsPerEndpoint.size) {
                        fallbackEndpoints.push(candidate.endpoint);
                    }
                    if (lastAttemptTimestamp !== undefined &&
                        now < lastAttemptTimestamp + this.params.peerConnectionAttemptInterval * 1000) {
                        continue;
                    }
                    // we haven't queried nor attempted to connect to this endpoint recently, 
                    // and we are not connected / connecting now, so query:
                    endpoints.push(candidate.endpoint);
                    if (endpoints.length >= this.params.minPeers - this.connectionsPerEndpoint.size) {
                        break;
                    }
                }
                if (endpoints.length < this.params.minPeers) {
                    endpoints = fallbackEndpoints;
                }
                for (const endpoint of endpoints) {
                    this.onlineQueryTimestamps.set(endpoint, now);
                }
                if (endpoints.length > 0) {
                    PeerGroupAgent.peersLog.debug('Querying for online endpoints: ' + endpoints);
                    this.getNetworkAgent().queryForListeningAddresses(LinkupAddress.fromURL(this.localPeer.endpoint), endpoints.map((ep) => LinkupAddress.fromURL(ep)));
                }
            }
            else {
                PeerGroupAgent.peersLog.trace('Skipping querying for peers on ' + this.peerGroupId);
            }
        }
        // Connection deduplication logic.
        deduplicateConnections() {
            for (const [endpoint, connIds] of this.connectionsPerEndpoint.entries()) {
                if (connIds.length > 1) {
                    // Check if there was a chosen connection.
                    let chosenConnId = this.chosenForDeduplication.get(endpoint);
                    // And in that case, if it is still working.
                    if (chosenConnId !== undefined &&
                        !this.getNetworkAgent().checkConnection(chosenConnId)) {
                        chosenConnId = undefined;
                        this.chosenForDeduplication.delete(endpoint);
                    }
                    if (chosenConnId === undefined) {
                        let ready = [];
                        for (const connId of connIds) {
                            let pc = this.connections.get(connId);
                            if (pc !== undefined && pc.status === PeerConnectionStatus.Ready &&
                                this.getNetworkAgent().checkConnection(connId)) {
                                ready.push(connId);
                            }
                        }
                        if (ready.length > 1) {
                            PeerGroupAgent.controlLog.trace('Connection duplication detecetd (' + ready.length + ') to ' + endpoint);
                            ready.sort();
                            chosenConnId = ready[0];
                            this.chosenForDeduplication.set(endpoint, chosenConnId);
                            this.sendChosenConnection(chosenConnId);
                        }
                    }
                }
            }
        }
        shutdown() {
            if (this.tickTimerRef !== undefined) {
                clearInterval(this.tickTimerRef);
                this.tickTimerRef = undefined;
            }
        }
        // Deduplication messages.
        sendChosenConnection(chosenConnId) {
            this.sendConnectionSelectionMessage(chosenConnId, SecureMessageTypes.ChooseConnection);
        }
        sendChosenConnectionConfirmation(chosenConnId) {
            this.sendConnectionSelectionMessage(chosenConnId, SecureMessageTypes.ConfirmChosenConnection);
        }
        sendConnectionSelectionMessage(chosenConnId, type) {
            let connSelectionMsg = {
                type: type,
                peerGroupId: this.peerGroupId,
            };
            let pc = this.connections.get(chosenConnId);
            let secureConnAgent = this.getSecureConnAgent();
            secureConnAgent.sendSecurely(chosenConnId, this.localPeer.identityHash, pc.peer.identityHash, this.getAgentId(), connSelectionMsg);
        }
        // Actual deduplication, when peers have agreed on which connection to keep.
        chooseConnection(chosenConnId) {
            let pc = this.connections.get(chosenConnId);
            let allConnIds = this.connectionsPerEndpoint.get(pc.peer.endpoint);
            if (allConnIds !== undefined) {
                for (const connId of allConnIds) {
                    if (connId !== chosenConnId) {
                        PeerGroupAgent.controlLog.debug(() => 'Closing connection due to deduplication: ' + connId + ' (the chosen one is ' + chosenConnId + ')');
                        this.getNetworkAgent().releaseConnection(connId, this.getAgentId());
                        this.removePeerConnection(connId);
                    }
                }
            }
        }
        // Connection handling: find a working connecton to an ep, decide whether to connect to or accept a
        //                      connection from a potential peer.
        findWorkingConnectionId(ep) {
            let connIds = this.connectionsPerEndpoint.get(ep);
            if (connIds !== undefined) {
                for (let connId of connIds) {
                    let pc = this.connections.get(connId);
                    if (pc !== undefined &&
                        pc.status === PeerConnectionStatus.Ready &&
                        this.getNetworkAgent().checkConnection(connId)) {
                        return connId;
                    }
                }
            }
            return undefined; // no luck
        }
        // Returns a peer corresponding to ep if we should connect, undefined otherwse.
        shouldConnectToPeer(p) {
            if (p !== undefined && // - p is a peer
                this.connectionsPerEndpoint.size < this.params.minPeers && // - we're below minimum peers
                this.connectionsPerEndpoint.get(p.endpoint) === undefined && // - we're not connect[ed/ing] to ep
                this.localPeer.endpoint !== p.endpoint) { // - ep is not us
                // ====> then init conn. to ep
                const lastAttemptTimestamp = this.connectionAttemptTimestamps.get(p.endpoint);
                const now = Date.now();
                // check if we have to wait because we've attempted to connect to ep recently.
                if (lastAttemptTimestamp === undefined ||
                    now > lastAttemptTimestamp + this.params.peerConnectionAttemptInterval * 1000) {
                    // OK just do it.
                    return true;
                }
                else {
                    PeerGroupAgent.controlLog.trace('Will not connect, there is a recent connection attempt to the same endpoint.');
                }
            }
            else {
                PeerGroupAgent.controlLog.trace(() => 'will not connect, resons: ' +
                    '\np!==undefined => ' + (p !== undefined) +
                    '\nthis.connectionsPerEndpoint.size < this.params.minPeers => ' + (this.connectionsPerEndpoint.size < this.params.minPeers) +
                    '\nthis.connectionsPerEndpoint.get(p.endpoint) === undefined => ' + (p !== undefined && this.connectionsPerEndpoint.get(p.endpoint) === undefined) +
                    '\nthis.localPeer.endpoint !== p.endpoint => ' + (p !== undefined && this.localPeer.endpoint !== p.endpoint));
            }
            // if conditions above are not met, don't connect.
            return false;
        }
        // Returns a peer corresponding to ep if we should accept the connection, undefined otherwise
        async shouldAcceptPeerConnection(p) {
            if (p === undefined) {
                return false;
            }
            else {
                const conns = this.connectionsPerEndpoint.get(p.endpoint);
                const alreadyConnected = conns !== undefined && conns.length > 0;
                return (this.connectionsPerEndpoint.size + (alreadyConnected ? 0 : 1) <= this.params.maxPeers && // - we're below maximum peers
                    this.findWorkingConnectionId(p.endpoint) === undefined && // - there's not a working conn to ep
                    this.localPeer.endpoint !== p.endpoint); // - ep is not us);
            }
        }
        // Connection metadata: create / destroy a new PeerConnection
        addPeerConnection(connId, peer, status) {
            if (this.connections.get(connId) !== undefined) {
                PeerGroupAgent.controlLog.warning(() => 'Trying to add connection ' + connId + ', but it already exists.');
                throw new Error('Trying to add connection ' + connId + ', but it already exists.');
            }
            let pc = {
                connId: connId,
                peer: peer,
                status: status,
                timestamp: Date.now()
            };
            this.connections.set(connId, pc);
            let conns = this.connectionsPerEndpoint.get(peer.endpoint);
            if (conns === undefined) {
                conns = [];
                this.connectionsPerEndpoint.set(peer.endpoint, conns);
            }
            conns.unshift(connId);
            return pc;
        }
        removePeerConnection(connId) {
            let pc = this.connections.get(connId);
            if (pc !== undefined) {
                this.connections.delete(connId);
                let conns = this.connectionsPerEndpoint.get(pc.peer.endpoint);
                if (conns !== undefined) {
                    let idx = conns.indexOf(connId);
                    if (idx >= 0) {
                        conns.splice(idx, 1);
                    }
                    if (conns.length === 0) {
                        this.connectionsPerEndpoint.delete(pc.peer.endpoint);
                        conns = undefined;
                    }
                }
                if (pc.status === PeerConnectionStatus.Ready && conns === undefined) {
                    this.broadcastLostPeerEvent(pc.peer);
                }
            }
        }
        // Ask SecureConnectionAgent to secure a connection, given local and remote identities
        secureConnection(pc) {
            const secureConnAgent = this.getSecureConnAgent();
            secureConnAgent.secureForReceiving(pc.connId, this.localPeer.identity);
            secureConnAgent.secureForSending(pc.connId, pc.peer.identityHash, pc.peer.identity);
        }
        checkSecuredConnection(pc) {
            const secureConnAgent = this.getSecureConnAgent();
            let localId = secureConnAgent.getLocalVerifiedIdentity(pc.connId, this.localPeer.identityHash);
            let remoteId = secureConnAgent.getRemoteVerifiedIdentity(pc.connId, pc.peer.identityHash);
            let success = (localId !== undefined && remoteId !== undefined);
            pc.peer.identity = remoteId;
            return success;
        }
        // handling of events for peer connection negotiation:
        async onOnlineEndpointDiscovery(ep) {
            this.controlLog.debug(() => (this.localPeer.endpoint + ' has discovered that ' + ep + ' is online.'));
            let peer = await this.peerSource.getPeerForEndpoint(ep);
            if (this.shouldConnectToPeer(peer)) {
                this.controlLog.debug(() => (this.localPeer.endpoint + ' will initiate peer connection to ' + ep + '.'));
                let connId = this.getNetworkAgent().connect(this.localPeer.endpoint, peer.endpoint, this.getAgentId());
                this.addPeerConnection(connId, peer, PeerConnectionStatus.Connecting);
                this.connectionAttemptTimestamps.set(ep, Date.now());
                this.stats.connectionInit += 1;
            }
            else {
                this.controlLog.debug(() => (this.localPeer.endpoint + ' will NOT initiate peer connection to ' + ep + '.'));
            }
        }
        async onConnectionRequest(connId, local, remote) {
            if (this.localPeer.endpoint === local) {
                let peer = await this.peerSource.getPeerForEndpoint(remote);
                this.controlLog.trace(this.localPeer.endpoint + ' is receiving a conn. request from ' + remote + ', connId is ' + connId);
                if (await this.shouldAcceptPeerConnection(peer)) {
                    this.controlLog.debug('Will accept requested connection ' + connId + '!');
                    this.addPeerConnection(connId, peer, PeerConnectionStatus.ReceivingConnection);
                    this.getNetworkAgent().acceptConnection(connId, this.getAgentId());
                    this.stats.connectionAccpt += 1;
                }
            }
        }
        onConnectionEstablishment(connId, local, remote) {
            let pc = this.connections.get(connId);
            this.controlLog.trace(() => this.localPeer.endpoint + ' is receiving a connection from ' + remote + ' connId is ' + connId);
            if (pc !== undefined && this.localPeer.endpoint === local && pc.peer.endpoint === remote) {
                if (pc.status === PeerConnectionStatus.Connecting) {
                    this.sendOffer(pc);
                    pc.status = PeerConnectionStatus.OfferSent;
                }
                else if (pc.status === PeerConnectionStatus.ReceivingConnection) {
                    pc.status = PeerConnectionStatus.WaitingForOffer;
                }
            }
            else {
                this.controlLog.trace(() => 'Unknown connection ' + connId + ', ignoring. pc=' + pc + ' local=' + local + ' remote=' + remote);
            }
        }
        async onReceivingOffer(connId, source, destination, peerGroupId, remoteIdentityHash) {
            this.controlLog.trace(() => (this.localPeer.endpoint + ' is receiving peering offer from ' + source));
            // do this here so we get atomicity below.
            let peer = await this.peerSource.getPeerForEndpoint(source);
            let reply = false;
            let accept = false;
            let pc = this.connections.get(connId);
            // Maybe the PeerControlAgent, upong starting in another node, found an existint connection
            // to us, and wants to start a PeerConnection over it. So we have no previous state referring
            // to connection establishment, and we just receive the offer over an existing one.
            if (pc === undefined) {
                this.controlLog.trace('Found no previous state');
                if (await this.shouldAcceptPeerConnection(peer)) {
                    this.controlLog.debug('Will accept offer ' + connId + '!');
                    // Act as if we had just received the connection, process offer below.
                    this.addPeerConnection(connId, peer, PeerConnectionStatus.WaitingForOffer);
                    accept = true;
                    reply = true;
                }
                else {
                    this.controlLog.debug('Will NOT accept offer ' + connId + '!');
                    if (peer !== undefined &&
                        peer.identityHash === remoteIdentityHash &&
                        this.peerGroupId === peerGroupId) {
                        // OK, we don't want to accept, but this is, in principle, a valid peer.
                        // Send a rejection below.
                        accept = false;
                        reply = true;
                    }
                }
            }
            else { // pc !== undefined
                // OK, we had previous state - if everything checks up, accept.
                this.controlLog.trace('Found previous state:' + pc.status);
                if (peerGroupId === this.peerGroupId &&
                    pc.status === PeerConnectionStatus.WaitingForOffer &&
                    source === pc.peer.endpoint &&
                    destination === this.localPeer.endpoint &&
                    remoteIdentityHash === pc.peer.identityHash) {
                    this.controlLog.trace('Everything checks out!');
                    reply = true;
                    accept = true;
                }
                else {
                    this.controlLog.trace('The request is invalid.');
                }
            }
            // If the offer was correct, we send a reply.
            // Notice: accept implies reply.
            if (reply) {
                this.sendOfferReply(connId, accept);
            }
            // Act upon the offer: if it was accepted, update local state and 
            //                     initiate connection authentication. Otherwise
            //                     clear the state on this connection.
            if (accept) {
                const apc = pc;
                if (!this.checkSecuredConnection(apc)) {
                    apc.status = PeerConnectionStatus.OfferAccepted;
                    this.secureConnection(apc);
                }
                else {
                    apc.status = PeerConnectionStatus.Ready;
                    this.broadcastNewPeerEvent(apc.peer);
                }
            }
            else {
                PeerGroupAgent.controlLog.debug('Dropping connection ' + connId + ': offer was rejected');
                this.removePeerConnection(connId);
                this.getNetworkAgent().releaseConnectionIfExists(connId, this.getAgentId());
            }
        }
        onReceivingOfferReply(connId, source, destination, peerGroupId, remoteIdentityHash, accepted) {
            let pc = this.connections.get(connId);
            this.controlLog.trace(this.localPeer.endpoint + ' is receiving offer reply from ' + source);
            if (pc !== undefined &&
                peerGroupId === this.peerGroupId &&
                pc.status === PeerConnectionStatus.OfferSent &&
                source === pc.peer.endpoint &&
                destination === this.localPeer.endpoint &&
                remoteIdentityHash === pc.peer.identityHash &&
                accepted) {
                if (!this.checkSecuredConnection(pc)) {
                    pc.status = PeerConnectionStatus.OfferAccepted;
                    this.secureConnection(pc);
                }
                else {
                    pc.status = PeerConnectionStatus.Ready;
                    this.broadcastNewPeerEvent(pc.peer);
                }
            }
        }
        onConnectionAuthentication(connId, identityHash, identity, identityLocation) {
            let pc = this.connections.get(connId);
            if (pc !== undefined && pc.status === PeerConnectionStatus.OfferAccepted) {
                if (this.checkSecuredConnection(pc)) {
                    pc.status = PeerConnectionStatus.Ready;
                    this.broadcastNewPeerEvent(pc.peer);
                }
            }
        }
        onConnectionClose(connId) {
            this.removePeerConnection(connId);
        }
        // Offer / offer reply message construction, sending.
        sendOffer(pc) {
            let message = {
                type: PeerMeshAgentMessageType.PeeringOffer,
                content: {
                    peerGroupId: this.peerGroupId,
                    localIdentityHash: this.localPeer.identityHash
                }
            };
            this.controlLog.trace(() => (this.localPeer.endpoint + ' sending peering offer to ' + pc.peer.endpoint));
            this.getNetworkAgent().sendMessage(pc.connId, this.getAgentId(), message);
        }
        sendOfferReply(connId, accept) {
            let message = {
                type: PeerMeshAgentMessageType.PeeringOfferReply,
                content: {
                    peerGroupId: this.peerGroupId,
                    localIdentityHash: this.localPeer.identityHash,
                    accepted: accept
                }
            };
            this.controlLog.trace(() => { var _a; return (this.localPeer.endpoint + ' sending peering offer reply to ' + ((_a = this.connections.get(connId)) === null || _a === void 0 ? void 0 : _a.peer.endpoint)) + ': ' + (accept ? 'ACCEPT' : 'REJECT'); });
            this.getNetworkAgent().sendMessage(connId, this.getAgentId(), message);
        }
        // handle peer message reception
        onPeerMessage(connId, sender, recipient, peerGroupId, agentId, message) {
            let pc = this.connections.get(connId);
            if (peerGroupId === this.peerGroupId &&
                pc !== undefined && pc.status === PeerConnectionStatus.Ready &&
                pc.peer.identityHash === sender && this.localPeer.identityHash === recipient) {
                let agent = this.getLocalAgent(agentId);
                if (agent !== undefined && agent instanceof PeeringAgentBase) {
                    let peeringAgent = agent;
                    peeringAgent.receivePeerMessage(pc.peer.endpoint, sender, recipient, message);
                }
            }
        }
        // If two peers attempt to connect to each other nearly at the same time, they may end up with
        // two different connections between a single pair of endpoints. The following exchange allows
        // them to agree on a connection to use, and safely close the rest.
        onConnectionSelection(connId, sender, recipient, type, peerGroupId) {
            PeerGroupAgent.controlLog.trace('Connection selection for ' + connId + ' sender=' + sender + ', recipient=' + recipient + ', type=' + type);
            let pc = this.connections.get(connId);
            // If connId represents an acceptable option (a working connection in Ready state):
            if (pc !== undefined &&
                pc.status === PeerConnectionStatus.Ready &&
                this.getNetworkAgent().checkConnection(connId)) {
                let accept = false;
                let chosenConnId = this.chosenForDeduplication.get(pc.peer.endpoint);
                // if we didn't propose another connecitons, choose this one.
                if (chosenConnId === undefined || chosenConnId === connId) {
                    accept = true;
                }
                else {
                    const options = new Array();
                    options.push(connId);
                    options.push(chosenConnId);
                    options.sort();
                    const tieBreak = options[0];
                    accept = tieBreak === connId;
                }
                if (accept) {
                    this.chooseConnection(connId);
                    if (type === SecureMessageTypes.ChooseConnection) {
                        this.sendChosenConnectionConfirmation(connId);
                    }
                }
            }
        }
        /* The functions,receiveLocalEvent receives events generated by the other agents in the pod
         * and fires the appropriate event handlers defined above (onConnectionRequest, onReceivingOffer,
         * etc.)
         */
        receiveLocalEvent(ev) {
            if (ev.type === exports.NetworkEventType.RemoteAddressListening) {
                const listenEv = ev;
                this.onOnlineEndpointDiscovery(listenEv.content.remoteEndpoint);
            }
            else if (ev.type === exports.NetworkEventType.ConnectionStatusChange) {
                const connEv = ev;
                if (connEv.content.status === exports.ConnectionStatus.Closed) {
                    this.onConnectionClose(connEv.content.connId);
                }
                else if (connEv.content.status === exports.ConnectionStatus.Received) {
                    this.onConnectionRequest(connEv.content.connId, connEv.content.localEndpoint, connEv.content.remoteEndpoint);
                }
                else if (connEv.content.status === exports.ConnectionStatus.Ready) {
                    this.onConnectionEstablishment(connEv.content.connId, connEv.content.localEndpoint, connEv.content.remoteEndpoint);
                }
            }
            else if (ev.type === exports.SecureNetworkEventType.ConnectionIdentityAuth) {
                let connAuth = ev;
                if (connAuth.content.status === exports.IdentityAuthStatus.Accepted) {
                    this.onConnectionAuthentication(connAuth.content.connId, connAuth.content.identityHash, connAuth.content.identity, connAuth.content.identityLocation);
                }
            }
            else if (ev.type === exports.SecureNetworkEventType.SecureMessageReceived) {
                // The SecureConnectionAgent relies secure messages destined to this agent through local events.
                // Since this messages arrive through a secured connection, we know the sender is in possesion of
                // a given identity, and we know at which identity the message was directed (encrypted for).
                let secMsgEv = ev;
                let payload = secMsgEv.content.payload;
                if (payload.type === SecureMessageTypes.PeerMessage) {
                    this.onPeerMessage(secMsgEv.content.connId, secMsgEv.content.sender, secMsgEv.content.recipient, payload.peerGroupId, payload.agentId, payload.content);
                }
                else if (payload.type === SecureMessageTypes.ChooseConnection || payload.type === SecureMessageTypes.ConfirmChosenConnection) {
                    this.onConnectionSelection(secMsgEv.content.connId, secMsgEv.content.sender, secMsgEv.content.recipient, payload.type, payload.peerGroupId);
                }
            }
            else if (ev.type === exports.NetworkEventType.MessageReceived) {
                let msgEv = ev;
                this.receiveMessage(msgEv.content.connectionId, msgEv.content.source, msgEv.content.destination, msgEv.content.content);
            }
        }
        receiveMessage(connId, source, destination, content) {
            let message = content;
            if (message.type === PeerMeshAgentMessageType.PeeringOffer) {
                let offer = content.content;
                this.onReceivingOffer(connId, source, destination, offer.peerGroupId, offer.localIdentityHash);
            }
            else if (message.type === PeerMeshAgentMessageType.PeeringOfferReply) {
                let offerReply = content.content;
                this.onReceivingOfferReply(connId, source, destination, offerReply.peerGroupId, offerReply.localIdentityHash, offerReply.accepted);
            }
        }
        // emitted events
        broadcastNewPeerEvent(peer) {
            var _a;
            PeerGroupAgent.controlLog.debug(() => this.localPeer.endpoint + ' hasa new peer: ' + peer.endpoint);
            let ev = {
                type: exports.PeerMeshEventType.NewPeer,
                content: {
                    peerGroupId: this.peerGroupId,
                    peer: peer
                }
            };
            (_a = this.pod) === null || _a === void 0 ? void 0 : _a.broadcastEvent(ev);
        }
        broadcastLostPeerEvent(peer) {
            var _a;
            PeerGroupAgent.controlLog.debug(() => this.localPeer.endpoint + ' hasa lost a peer: ' + peer.endpoint);
            let ev = {
                type: exports.PeerMeshEventType.LostPeer,
                content: {
                    peerGroupId: this.peerGroupId,
                    peer: peer
                }
            };
            (_a = this.pod) === null || _a === void 0 ? void 0 : _a.broadcastEvent(ev);
        }
        // shorthand functions
        getNetworkAgent() {
            var _a;
            return (_a = this.pod) === null || _a === void 0 ? void 0 : _a.getAgent(NetworkAgent.AgentId);
        }
        getLocalAgent(agentId) {
            var _a;
            return (_a = this.pod) === null || _a === void 0 ? void 0 : _a.getAgent(agentId);
        }
        getSecureConnAgent() {
            return this.getLocalAgent(SecureNetworkAgent.Id);
        }
        static agentIdForPeerGroup(peerGroupId) {
            return 'peer-control-for-' + peerGroupId;
        }
    }
    PeerGroupAgent.controlLog = new Logger(PeerGroupAgent.name, LogLevel.INFO);
    PeerGroupAgent.peersLog = new Logger(PeerGroupAgent.name, LogLevel.INFO);

    /*
     * A gossip agent is created with a given gossipId (these usually match 1-to-1
     * with peerGroupIds), and then is instructed to gossip about the state reported
     * by other agents (this.trackedAgentIds keeps track of which ones).
     *
     * Each agent's state is represented by a HashedObject, and thus states can be
     * hashed and hashes sent over to quickly assess if a remote and a local instance
     * of the same agent are in the same state.
     *
     * All the tracked agents must implement the StateSyncAgent interface. They are
     * expected to spew an AgentStateUpdate event on the bus whenever they enter a
     * new state, and to receive a state that was picked up via gossip when their
     * receiveRemoteState() method is invoked.
     *
     * The gossip agents on different nodes exchange messages about two things:
     *
     *   - They can ask for (SendFullState message) or send (SendFullState message) the
     *     set of hashes of the states of all the agents being tracked.
     *
     *   - They can ask for (RequestStateObject) or send (SendStateObject) the object
     *     representing the state of a given agent.
     *
     *
     * A gossip agent follows these simple rules:
     *
     *   - On startup it will send the hashes of the states of all the tracked agents
     *     to all connected peers. Whenever a new peer is detected, it'll send it the
     *     hashes as well.
     *
     *   - Upon receiving a set of hashes of states from a peer, they'll see if they are
     *     tracking the state of any of them, and if the states differ the corresponding
     *     object states will be asked for (*).
     *
     *   - When a local agent advertises through the bus it is entering a new state by
     *     emitting the AgentStateUpdate event, any gossip agents tracking its state will
     *     gossip the new state object to all their peers.
     *
     *   - Upon receiving a new state object for an agent whose state it is tracking, a
     *     gossip agent will invoke the receiveRemoteState() method of the corresponding
     *     agent, and learn whether this state is new or known. If it is known, it'll
     *     assume the agent on the peer has an old state, and it will send the state
     *     object of the local agent in response.
     *
     *     (*) If the received state hash matches that of the state of another peer for
     *         that same agent, the asking step is skipped and that state object is used
     *         instead.
     */
    var GossipType;
    (function (GossipType) {
        GossipType["SendFullState"] = "send-full-state";
        GossipType["SendStateObject"] = "send-state-object";
        GossipType["RequestFullState"] = "request-full-state";
        GossipType["RequestStateObject"] = "request-state-object";
    })(GossipType || (GossipType = {}));
    exports.GossipEventTypes = void 0;
    (function (GossipEventTypes) {
        GossipEventTypes["AgentStateUpdate"] = "agent-state-update";
    })(exports.GossipEventTypes || (exports.GossipEventTypes = {}));
    class StateGossipAgent extends PeeringAgentBase {
        constructor(topic, peerNetwork) {
            super(peerNetwork);
            // tunable working parameters
            this.params = {
                peerGossipFraction: 0.2,
                peerGossipProb: 0.5,
                minGossipPeers: 4,
                maxCachedPrevStates: 50,
                newStateErrorRetries: 3,
                newStateErrorDelay: 1500,
                maxGossipDelay: 5000
            };
            this.peerMessageLog = StateGossipAgent.peerMessageLog;
            this.controlLog = StateGossipAgent.controlLog;
            this.gossipId = topic;
            this.trackedAgentIds = new Set();
            this.localState = new Map();
            this.remoteState = new Map();
            this.localStateObjects = new Map();
            this.remoteStateObjects = new Map();
            this.previousStatesCache = new Map();
        }
        static agentIdForGossip(gossipId) {
            return 'state-gossip-agent-for-' + gossipId;
        }
        getAgentId() {
            return StateGossipAgent.agentIdForGossip(this.gossipId);
        }
        getNetwork() {
            return this.pod;
        }
        // gossip agent control:
        ready(pod) {
            this.pod = pod;
            this.controlLog.debug('Agent ready');
        }
        trackAgentState(agentId) {
            this.trackedAgentIds.add(agentId);
        }
        untrackAgentState(agentId) {
            this.trackedAgentIds.delete(agentId);
            this.previousStatesCache.delete(agentId);
            this.localState.delete(agentId);
            this.localStateObjects.delete(agentId);
        }
        isTrackingState(agentId) {
            return this.trackedAgentIds.has(agentId);
        }
        shutdown() {
        }
        // public functions, exposing states heard through gossip
        getRemoteState(ep, agentId) {
            var _a;
            return (_a = this.remoteState.get(ep)) === null || _a === void 0 ? void 0 : _a.get(agentId);
        }
        getRemoteStateObject(ep, agentId) {
            var _a;
            return (_a = this.remoteStateObjects.get(ep)) === null || _a === void 0 ? void 0 : _a.get(agentId);
        }
        // local events listening
        receiveLocalEvent(ev) {
            if (ev.type === AgentPodEventType.AgentSetChange) {
                let changeEv = ev;
                if (changeEv.content.change === exports.AgentSetChange.Removal) {
                    this.clearAgentState(changeEv.content.agentId);
                }
            }
            else if (ev.type === exports.GossipEventTypes.AgentStateUpdate) {
                let updateEv = ev;
                this.localAgentStateUpdate(updateEv.content.agentId, updateEv.content.state);
            }
            else if (ev.type === exports.PeerMeshEventType.NewPeer) {
                let newPeerEv = ev;
                if (newPeerEv.content.peerGroupId === this.peerGroupAgent.peerGroupId) {
                    this.controlLog.trace(this.peerGroupAgent.localPeer.endpoint + ' detected new peer: ' + newPeerEv.content.peer.endpoint);
                    this.sendFullState(newPeerEv.content.peer.endpoint);
                }
            }
            else if (ev.type === exports.PeerMeshEventType.LostPeer) {
                let lostPeerEv = ev;
                if (lostPeerEv.content.peerGroupId === this.peerGroupAgent.peerGroupId) {
                    this.controlLog.trace(this.peerGroupAgent.localPeer.endpoint + ' lost a peer: ' + lostPeerEv.content.peer.endpoint);
                    this.clearPeerState(lostPeerEv.content.peer.endpoint);
                }
            }
        }
        // incoming messages
        receivePeerMessage(source, sender, recipient, content) {
            this.receiveGossip(source, content);
        }
        clearAgentState(agentId) {
            this.localState.delete(agentId);
            this.localStateObjects.delete(agentId);
            this.previousStatesCache.delete(agentId);
        }
        clearPeerState(endpoint) {
            this.remoteState.delete(endpoint);
            this.remoteStateObjects.delete(endpoint);
        }
        // Gossiping and caching of local states:
        // cached states start at the front of the array and are
        // shifted right as new states to cache arrive.
        localAgentStateUpdate(agentId, state) {
            if (this.trackedAgentIds.has(agentId)) {
                const hash = state.hash();
                const currentState = this.localState.get(agentId);
                if (currentState !== undefined && hash !== currentState) {
                    this.cachePreviousStateHash(agentId, currentState);
                }
                this.localState.set(agentId, hash);
                this.localStateObjects.set(agentId, state);
                this.controlLog.trace('Gossiping state ' + hash + ' from ' + this.peerGroupAgent.getLocalPeer().endpoint);
                this.gossipNewState(agentId);
            }
        }
        gossipNewState(agentId, sender, timestamp) {
            const peers = this.getPeerControl().getPeers();
            let count = Math.ceil(this.getPeerControl().params.maxPeers * this.params.peerGossipFraction);
            if (count < this.params.minGossipPeers) {
                count = this.params.minGossipPeers;
            }
            if (count > peers.length) {
                count = peers.length;
            }
            if (timestamp === undefined) {
                timestamp = new Date().getTime();
            }
            Shuffle.array(peers);
            this.controlLog.trace('Gossiping state to ' + count + ' peers on ' + this.peerGroupAgent.getLocalPeer().endpoint);
            for (let i = 0; i < count; i++) {
                if (sender === undefined || sender !== peers[i].endpoint) {
                    try {
                        this.sendStateObject(peers[i].endpoint, agentId);
                    }
                    catch (e) {
                        this.peerMessageLog.debug('Could not gossip message to ' + peers[i].endpoint + ', send failed with: ' + e);
                    }
                }
            }
        }
        cachePreviousStateHash(agentId, state) {
            let prevStates = this.previousStatesCache.get(agentId);
            if (prevStates === undefined) {
                prevStates = [];
                this.previousStatesCache.set(agentId, prevStates);
            }
            // remove if already cached
            let idx = prevStates.indexOf(state);
            if (idx >= 0) {
                prevStates.splice(idx, 1);
            }
            // truncate array to make room for new state
            const maxLength = this.params.maxCachedPrevStates - 1;
            if (prevStates.length > maxLength) {
                const toDelete = prevStates.length - maxLength;
                prevStates.splice(maxLength, toDelete);
            }
            // put state at the start of the cached states array
            prevStates.unshift(state);
        }
        stateHashIsInPreviousCache(agentId, state) {
            const cache = this.previousStatesCache.get(agentId);
            return (cache !== undefined) && cache.indexOf(state) >= 0;
        }
        // handling and caching of remote states
        setRemoteState(ep, agentId, state, stateObject) {
            let peerState = this.remoteState.get(ep);
            if (peerState === undefined) {
                peerState = new Map();
                this.remoteState.set(ep, peerState);
            }
            peerState.set(agentId, state);
            let peerStateObjects = this.remoteStateObjects.get(ep);
            if (peerStateObjects === undefined) {
                peerStateObjects = new Map();
                this.remoteStateObjects.set(ep, peerStateObjects);
            }
            peerStateObjects.set(agentId, stateObject);
        }
        lookupStateObject(agentId, state) {
            var _a;
            for (const [ep, peerState] of this.remoteState.entries()) {
                if (peerState.get(agentId) === state) {
                    const stateObj = (_a = this.remoteStateObjects.get(ep)) === null || _a === void 0 ? void 0 : _a.get(agentId);
                    if (stateObj !== undefined) {
                        return stateObj;
                    }
                }
            }
            return undefined;
        }
        receiveGossip(source, gossip) {
            this.peerMessageLog.debug(this.getPeerControl().getLocalPeer().endpoint + ' received ' + gossip.type + ' from ' + source);
            if (gossip.type === GossipType.SendFullState) {
                let state = new HashedMap();
                state.fromArrays(gossip.state.hashes, gossip.state.entries);
                this.receiveFullState(source, new Map(state.entries()));
            }
            if (gossip.type === GossipType.SendStateObject) {
                let state = HashedObject.fromLiteral(gossip.state);
                this.receiveStateObject(source, gossip.agentId, state, gossip.timestamp);
            }
            if (gossip.type === GossipType.RequestFullState) {
                this.sendFullState(source);
            }
            if (gossip.type === GossipType.RequestStateObject) {
                this.sendStateObject(source, gossip.agentId);
            }
        }
        getLocalStateAgent(agentId) {
            const agent = this.getNetwork().getAgent(agentId);
            if (agent !== undefined && 'receiveRemoteState' in agent) {
                return agent;
            }
            else {
                return undefined;
            }
        }
        // message handling
        receiveFullState(sender, state) {
            for (const [agentId, hash] of state.entries()) {
                if (this.trackedAgentIds.has(agentId)) {
                    const agent = this.getLocalStateAgent(agentId);
                    if (agent !== undefined) {
                        const currentState = this.localState.get(agentId);
                        if (currentState !== hash) {
                            const cacheHit = this.stateHashIsInPreviousCache(agentId, hash);
                            if (!cacheHit) {
                                try {
                                    const stateObj = this.lookupStateObject(agentId, hash);
                                    if (stateObj === undefined) {
                                        this.requestStateObject(sender, agentId);
                                    }
                                    else {
                                        this.receiveStateObject(sender, agentId, stateObj, Date.now());
                                    }
                                }
                                catch (e) {
                                    //FIXME
                                }
                                // I _think_ it's better to not gossip in this case.
                            }
                        }
                    }
                }
            }
        }
        async receiveStateObject(sender, agentId, stateObj, _timestamp) {
            if (await stateObj.validate(new Map())) {
                const state = stateObj.hash();
                this.setRemoteState(sender, agentId, state, stateObj);
                const cacheHit = this.stateHashIsInPreviousCache(agentId, state);
                let receivedOldState = cacheHit;
                if (!receivedOldState) {
                    try {
                        receivedOldState = !(await this.notifyAgentOfStateArrival(sender, agentId, state, stateObj));
                    }
                    catch (e) {
                        // maybe cache erroneous states so we don't process them over and over?
                        StateGossipAgent.controlLog.warning('Received erroneous state from ' + sender, e);
                    }
                }
                if (receivedOldState && this.localState.get(agentId) !== state) {
                    this.peerMessageLog.trace('Received old state for ' + agentId + ' from ' + sender + ', sending our own state over there.');
                    this.sendStateObject(sender, agentId);
                }
            }
            else {
                this.peerMessageLog.trace('Received invalid state for ' + agentId + ' from ' + sender + ', ignoring.');
            }
        }
        async notifyAgentOfStateArrival(sender, agentId, stateHash, state) {
            const agent = this.getLocalStateAgent(agentId);
            let isNew = false;
            let valueReady = false;
            if (agent !== undefined) {
                const stateAgent = agent;
                try {
                    isNew = await stateAgent.receiveRemoteState(sender, stateHash, state);
                    valueReady = true;
                }
                catch (e) {
                    let retries = 0;
                    while (valueReady === false && retries < this.params.newStateErrorRetries) {
                        await new Promise(r => setTimeout(r, this.params.newStateErrorDelay));
                        isNew = await stateAgent.receiveRemoteState(sender, stateHash, state);
                        valueReady = true;
                    }
                }
                if (valueReady) {
                    return isNew;
                }
                else {
                    throw new Error('Error processing remote state.');
                }
            }
            else {
                throw new Error('Cannot find receiving agent.');
            }
        }
        // message sending
        sendFullState(ep) {
            let fullStateMessage = {
                type: GossipType.SendFullState,
                state: new HashedMap(this.localState.entries()).toArrays()
            };
            this.sendMessageToPeer(ep, this.getAgentId(), fullStateMessage);
        }
        sendStateObject(peerEndpoint, agentId) {
            const state = this.localStateObjects.get(agentId);
            if (state !== undefined) {
                const timestamp = Date.now();
                let literal = state.toLiteral();
                let stateUpdateMessage = {
                    type: GossipType.SendStateObject,
                    agentId: agentId,
                    state: literal,
                    timestamp: timestamp
                };
                this.peerMessageLog.debug('Sending state for ' + agentId + ' from ' + this.peerGroupAgent.getLocalPeer().endpoint + ' to ' + peerEndpoint);
                let result = this.sendMessageToPeer(peerEndpoint, this.getAgentId(), stateUpdateMessage);
                if (!result) {
                    this.controlLog.debug('Sending state failed!');
                }
            }
            else {
                this.controlLog.warning('Attempting to send our own state to ' + peerEndpoint + ' for agent ' + agentId + ', but no state object found');
            }
        }
        requestStateObject(peerEndpoint, agentId) {
            let requestStateUpdateMessage = {
                type: GossipType.RequestStateObject,
                agentId: agentId
            };
            this.peerMessageLog.debug('Sending state update request for ' + agentId + ' from ' + this.peerGroupAgent.getLocalPeer().endpoint + ' to ' + peerEndpoint);
            let result = this.sendMessageToPeer(peerEndpoint, this.getAgentId(), requestStateUpdateMessage);
            if (!result) {
                this.controlLog.debug('Sending state request failed!');
            }
        }
    }
    StateGossipAgent.peerMessageLog = new Logger(StateGossipAgent.name, LogLevel.INFO);
    StateGossipAgent.controlLog = new Logger(StateGossipAgent.name, LogLevel.INFO);

    class TerminalOpsState extends HashedObject {
        constructor(objectHash, terminalOps) {
            super();
            this.objectHash = objectHash;
            if (terminalOps !== undefined) {
                this.terminalOps = new HashedSet(new Set(terminalOps).values());
            }
        }
        static create(objectHash, terminalOps) {
            return new TerminalOpsState(objectHash, terminalOps);
        }
        getClassName() {
            return TerminalOpsState.className;
        }
        async validate(references) {
            return this.objectHash !== undefined && this.terminalOps !== undefined;
        }
        init() {
        }
    }
    TerminalOpsState.className = 'hhs/v0/TerminalOpsState';
    TerminalOpsState.registerClass(TerminalOpsState.className, TerminalOpsState);

    /*

    *Introduction*

    A MutableObject represents the initial state of the object, which is then updated by creating
    MutationOp instances that point to it through their "target" field, and to the MutationOps that
    were created just before in the "prevOps" field.

    The TerminalOpsSyncAgent's purpose is to synchronize the state of a MutableObject by keeping track
    of its "terminal ops", i.e. the very last ops that were created, and that have no successor ops yet.

    The agent will be instantiated to sync a particular MutableObject present in the local store, and
    will perform state reconciliation with any connected peers that either advertise new states
    through gossiping or request MutationOps in response to its own state advertisements.

    The TerminalOpsSyncAgent only deals with actual state sync. The gossiping of new states is done
    by other agents (typically the StateGossipAgent, which batches together the states of all the
    objects that a peer wants to sync with a particular PeerGroup). The local TerminalOpsSyncAgent and
    StateGossipAgent communicate trough the local broadcasting mechanism of the AgentPod they share.


    *State by terminal ops*

    The TerminalOpsSyncAgent uses the "prevOps" field in the MutationOp object to discard all the ops
    that have any following ops -that is another op that points to them through its "prevOps" field-
    and use the set of remaining "terminal ops" as a way to represent the state of the MutableObject
    being synchronized. This set of terminal ops can be obtained easily and quickly from the store
    itself.

    *State broadcasting*

    After discovering that the state of the object has changed, the agent will broadcast a message to
    the local agent pod informing of the update. Any gossiping agents active in the pod will pick up
    the update and inform any connected peers. Conversely, if any gossip agent picks up any state update
    from a connected peer, it will also broadcast a message on the local agent pod. The
    TermninalOpsSyncAgent will check the received state and start synchronizing with such a peer if
    necessary.

    *State sync*

    After determining (via gossip results broadcaste on the local pod by a gossiping agent) that it
    needs to perform state sync, the TerminalOpsSyncAgent exchanges a series of messages with the
    TerminalOpsSyncAgent on the peer that has advertised a new state. Since the state is just the
    set of "terminal ops" on the other end, the agent will just ask for any of this "terminal ops"
    that are missing on the local store. Since an op can only be persisted to the store once all
    its prevOps have been already persisted, the agent may need to make several calls until it can
    reconcile the local state with the remote one, following the trail of prevOps until all the
    dependencies of the terminalOps have been fetched. There are 4 types of messages used in this
    task:

    The SendStateMessage is sent in reply to a RequestStateMessage, and it will send the set of
    terminalOps in full (gossiping usually would send just a hash of the terminalOp set).

    The SendOpsMessage is sent in reply to the RequestObjsMessage, and will send the literalized
    version of the objects and their dependencies.

    *Security measures, optimizations*

    When sending state (in the form of literalized objects) the agent may omit some dependencies
    of the objects being sent, expecting the receiving peer to already have them in its store
    (e.g., the identities and public keys that are referenced again and again by the ops being
    applied to the target object). And of course, there may be more prevOps that the other end
    discovers as a result of the received objects, and that it also needs to request.

    There are two security measures in place to prevent object exfiltration:

    Rule 1. Every requested object needs to be referenced (probably indirectly) from an op that has the
    object being synchronized as its target.
    Rule 2. Every an object A that is sent and has a reference B that is optimized away from the sent
    message must provide a proof that the sender has B locally in its store.

    The purpose of Rule 1 is preventing an adversary from requesting arbitrary objects that have no
    relation to the object being synchronized.

    The purpose of Rule 2 is a bit more subtle: an adversary may construct a legitimate MutationOp that
    he then applies to the object being syncronized in such a way that the op references some object
    that he wants to steal from another peer (perhaps an object
    unrelated to the one being synchronized). So even if the attacker knows the hash of the object that
    he wants to steal, and is able to construct a MutationOp that will be accepted by the type of the
    mutations that the mutable object accepts, he will not be able to provide the proof of ownership
    that is required for sending incomplete operations.


    */
    var TerminalOpsSyncAgentMessageType;
    (function (TerminalOpsSyncAgentMessageType) {
        TerminalOpsSyncAgentMessageType["RequestState"] = "request-state";
        TerminalOpsSyncAgentMessageType["SendState"] = "send-state";
        TerminalOpsSyncAgentMessageType["RequestObjs"] = "request-objs";
        TerminalOpsSyncAgentMessageType["SendObjs"] = "send-objs";
    })(TerminalOpsSyncAgentMessageType || (TerminalOpsSyncAgentMessageType = {}));
    class TerminalOpsSyncAgent extends PeeringAgentBase {
        constructor(peerGroupAgent, objectHash, store, acceptedMutationOpClasses, params) {
            super(peerGroupAgent);
            this.controlLog = TerminalOpsSyncAgent.controlLog;
            this.peerMessageLog = TerminalOpsSyncAgent.peerMessageLog;
            this.opTransferLog = TerminalOpsSyncAgent.opTransferLog;
            if (params === undefined) {
                params = {
                    sendTimeout: 60,
                    receiveTimeout: 90,
                    incompleteOpTimeout: 3600
                };
            }
            this.params = params;
            this.objHash = objectHash;
            this.store = store;
            this.acceptedMutationOpClasses = acceptedMutationOpClasses;
            this.opCallback = async (opHash) => {
                this.opTransferLog.trace('Op ' + opHash + ' found for object ' + this.objHash + ' in peer ' + this.peerGroupAgent.getLocalPeer().endpoint);
                let op = await this.store.load(opHash);
                if (this.shouldAcceptMutationOp(op)) {
                    await this.loadStoredState();
                }
            };
            this.outgoingObjects = new Map();
            this.incomingObjects = new Map();
            this.incompleteOps = new Map();
            this.opsForMissingObj = new MultiMap();
            this.opShippingInterval = setInterval(() => {
                let now = Date.now();
                // check sending / receiving timeouts & remove stale entries
                let allOutdatedObjectHashes = new Array();
                for (const objs of [this.outgoingObjects, this.incomingObjects]) {
                    let outdated = [];
                    for (const [hash, destinations] of objs.entries()) {
                        let outdatedEndpoints = [];
                        for (const [endpoint, params] of destinations.entries()) {
                            if (now > params.timeout) {
                                outdatedEndpoints.push(endpoint);
                            }
                        }
                        for (const ep of outdatedEndpoints) {
                            destinations.delete(ep);
                            this.controlLog.warning('fetching of object with hash ' + hash + ' from ' + ep + ' has timed out');
                        }
                        if (destinations.size === 0) {
                            outdated.push(hash);
                        }
                    }
                    for (const hash of outdated) {
                        objs.delete(hash);
                    }
                    allOutdatedObjectHashes.push(outdated);
                }
                // FIXME: schedule a retry (maybe from another peer?) when fetching fails
                for (const hash of allOutdatedObjectHashes[1]) {
                    // do something with
                    this.controlLog.warning('fetching of object with hash ' + hash + ' has timed out');
                }
                let timeoutedIncompleteOps = new Array();
                for (const [hash, incompleteOp] of this.incompleteOps.entries()) {
                    if (incompleteOp.timeout > now) {
                        for (const depHash of incompleteOp.missingObjects.keys()) {
                            this.opsForMissingObj.delete(depHash, hash);
                        }
                        timeoutedIncompleteOps.push(hash);
                    }
                }
                for (const hash of timeoutedIncompleteOps) {
                    this.incompleteOps.delete(hash);
                    console.log('timeouted incomplete op: ' + hash);
                }
                //FIXME: issue retry for tiemouted incomplete op
            }, 5000);
        }
        static syncAgentIdFor(objHash, peerGroupId) {
            return 'terminal-ops-for-' + objHash + '-in-peer-group-' + peerGroupId;
        }
        getAgentId() {
            return TerminalOpsSyncAgent.syncAgentIdFor(this.objHash, this.peerGroupAgent.peerGroupId);
        }
        ready(pod) {
            this.controlLog.debug('Starting for object ' + this.objHash +
                ' on ep ' + this.peerGroupAgent.getLocalPeer().endpoint +
                ' (topic: ' + this.peerGroupAgent.getTopic() + ')');
            this.pod = pod;
            this.loadStoredState();
            this.watchStoreForOps();
        }
        async receiveRemoteState(sender, stateHash, state) {
            var _a;
            if (state !== undefined) {
                let computedHash = state.hash();
                if (computedHash !== stateHash) {
                    // TODO: report bad peer
                    return false;
                }
                else {
                    let peerTerminalOpsState = state;
                    this.opTransferLog.debug(this.getPeerControl().getLocalPeer().endpoint + ' received terminal op list from ' + sender + ': ' + Array.from((_a = peerTerminalOpsState.terminalOps) === null || _a === void 0 ? void 0 : _a.values()));
                    let opsToFetch = [];
                    let badOps = false;
                    for (const opHash of peerTerminalOpsState.terminalOps.values()) {
                        const alreadyFetching = this.incompleteOps.has(opHash);
                        if (!alreadyFetching) {
                            const o = await this.store.load(opHash);
                            if (o === undefined) {
                                opsToFetch.push(opHash);
                            }
                            else {
                                const op = o;
                                if (!this.shouldAcceptMutationOp(op)) {
                                    badOps = true;
                                }
                            }
                        }
                    }
                    if (badOps) ;
                    else if (opsToFetch.length > 0) {
                        this.sendRequestObjsMessage(sender, opsToFetch.map((hash) => ({ hash: hash, dependencyChain: [] })));
                        //console.log('requesting ops from received sate: ' + opsToFetch);
                    }
                    return opsToFetch.length > 0 && !badOps;
                }
            }
            else {
                if (stateHash !== this.stateHash) {
                    this.sendRequestStateMessage(sender);
                }
                return false;
            }
        }
        receivePeerMessage(source, sender, recipient, content) {
            let msg = content;
            if (msg.targetObjHash !== this.objHash) {
                // TODO: report bad peer go peer group?
                this.peerMessageLog.warning('Received wrong targetObjHash, expected ' + this.objHash + ' but got ' + msg.targetObjHash + ' from ' + source);
                return;
            }
            this.peerMessageLog.debug('terminal-ops-agent: ' + this.getPeerControl().getLocalPeer().endpoint + ' received ' + msg.type + ' from ' + source);
            if (msg.targetObjHash === this.objHash) {
                if (msg.type === TerminalOpsSyncAgentMessageType.RequestState) {
                    this.sendState(source);
                }
                else if (msg.type === TerminalOpsSyncAgentMessageType.RequestObjs) {
                    this.sendOrScheduleObjects(source, msg.requestedObjects, msg.ownershipProofSecret);
                }
                else if (msg.type === TerminalOpsSyncAgentMessageType.SendState) {
                    const sendStateMsg = msg;
                    let state = HashedObject.fromLiteral(sendStateMsg.state);
                    this.receiveRemoteState(source, state.hash(), state);
                }
                else if (msg.type === TerminalOpsSyncAgentMessageType.SendObjs) {
                    // TODO: you need to check signatures here also, so FIXME
                    //       (signatures will be checked when importing object, but it would be wise
                    //       to check if each dependency has valid signatures even before the object
                    //       is complete)
                    const sendOpsMsg = msg;
                    this.receiveObjects(source, sendOpsMsg.sentObjects, sendOpsMsg.omittedDeps, sendOpsMsg.ownershipProofSecret);
                }
            }
        }
        watchStoreForOps() {
            this.store.watchReferences('targetObject', this.objHash, this.opCallback);
        }
        unwatchStoreForOps() {
            this.store.removeReferencesWatch('targetObject', this.objHash, this.opCallback);
        }
        getObjectHash() {
            return this.objHash;
        }
        shutdown() {
            this.unwatchStoreForOps();
            if (this.opShippingInterval !== undefined) {
                clearInterval(this.opShippingInterval);
            }
        }
        async loadStoredState() {
            var _a;
            const state = await this.getStoredState();
            const stateHash = state.hash();
            if (this.stateHash === undefined || this.stateHash !== stateHash) {
                this.controlLog.debug('Found new state ' + stateHash + ' for ' + this.objHash + ' in ' + this.peerGroupAgent.getLocalPeer().endpoint);
                this.state = state;
                this.stateHash = stateHash;
                let stateUpdate = {
                    type: exports.GossipEventTypes.AgentStateUpdate,
                    content: { agentId: this.getAgentId(), state }
                };
                (_a = this.pod) === null || _a === void 0 ? void 0 : _a.broadcastEvent(stateUpdate);
            }
        }
        async getStoredState() {
            let terminalOpsInfo = await this.store.loadTerminalOpsForMutable(this.objHash);
            if (terminalOpsInfo === undefined) {
                terminalOpsInfo = { terminalOps: [] };
            }
            return TerminalOpsState.create(this.objHash, terminalOpsInfo.terminalOps);
        }
        sendRequestStateMessage(destination) {
            let msg = {
                type: TerminalOpsSyncAgentMessageType.RequestState,
                targetObjHash: this.objHash
            };
            this.sendSyncMessageToPeer(destination, msg);
        }
        sendRequestObjsMessage(destination, reqs) {
            var _a, _b, _c;
            let secret = new BrowserRNG().randomHexString(128);
            let newReqs = [];
            for (const req of reqs) {
                this.controlLog.trace('Pending reqs for ' + req.hash + ': ' + ((_a = this.incomingObjects.get(req.hash)) === null || _a === void 0 ? void 0 : _a.size));
                // if we have already requested this object from this very same peer, do not ask for it again
                const alreadyRequested = ((_b = this.incomingObjects.get(req.hash)) === null || _b === void 0 ? void 0 : _b.get(destination)) !== undefined;
                // if we already have two pending requests, do not ask for it again
                const pendingReqs = ((_c = this.incomingObjects.get(req.hash)) === null || _c === void 0 ? void 0 : _c.size) || 0;
                if (!alreadyRequested && pendingReqs < 2) {
                    if (this.expectIncomingObject(destination, req.hash, req.dependencyChain, secret)) {
                        newReqs.push(req);
                        this.controlLog.trace('This req was not being expected, WILL request');
                    }
                    else {
                        this.controlLog.trace('This req was already being expected, WILL NOT request');
                    }
                }
            }
            if (newReqs.length > 0) {
                let msg = {
                    type: TerminalOpsSyncAgentMessageType.RequestObjs,
                    targetObjHash: this.objHash,
                    requestedObjects: newReqs,
                    ownershipProofSecret: secret
                };
                this.sendSyncMessageToPeer(destination, msg);
                //console.log('sending objs req for: ' + newReqs.map((req: ObjectRequest) => req.hash) + ' to ' + destination);
            }
        }
        sendState(ep) {
            var _a;
            if (this.state !== undefined) {
                let msg = {
                    type: TerminalOpsSyncAgentMessageType.SendState,
                    targetObjHash: this.objHash,
                    state: (_a = this.state) === null || _a === void 0 ? void 0 : _a.toLiteral()
                };
                this.sendSyncMessageToPeer(ep, msg);
            }
        }
        async sendOrScheduleObjects(destination, requestedObjects, secret) {
            let missing = await this.tryToSendObjects(destination, requestedObjects, secret);
            for (const req of missing) {
                this.scheduleOutgoingObject(destination, req.hash, req.dependencyChain, secret);
                // note: if the object was already scheduled the above function will return false and
                //       do nothing, but that is OK.
            }
        }
        // try to send the requested objects, return the ones that were not found.
        async tryToSendObjects(destination, requestedObjects, secret) {
            let provenReferences = new Set();
            let ownershipProofs = new Array();
            let sendLater = new Array();
            let context = new Context();
            for (const req of requestedObjects) {
                let opHash = req.hash;
                let valid = true;
                let missing = false;
                // follow depedency path, until we reach the op
                for (const depHash of req.dependencyChain) {
                    let depLiteral = await this.store.loadLiteral(depHash);
                    if (depLiteral === undefined) {
                        missing = true;
                        break;
                    }
                    else {
                        const matches = depLiteral.dependencies.filter((dep) => (dep.hash === opHash));
                        if (matches.length > 0) {
                            opHash = depHash;
                        }
                        else {
                            valid = false;
                            break;
                        }
                    }
                }
                // if we found all intermediate objects, check if the op is valid
                if (!missing && valid) {
                    let op = await this.store.load(opHash);
                    if (op === undefined) {
                        missing = true;
                    }
                    else if (!this.shouldAcceptMutationOp(op)) {
                        valid = false;
                    }
                }
                // if we found the op and it is valid, fetch the requested object
                if (valid && !missing) {
                    let obj = await this.store.load(req.hash);
                    if (obj === undefined) {
                        missing = true;
                    }
                    else {
                        obj.toContext(context);
                        const hash = context.rootHashes[context.rootHashes.length - 1];
                        for (const dep of context.literals.get(hash).dependencies) {
                            if (dep.type === 'reference') {
                                if (!provenReferences.has(dep.hash)) {
                                    let ref = await this.store.load(dep.hash);
                                    ownershipProofs.push({ hash: dep.hash, ownershipProofHash: ref.hash(secret) });
                                    provenReferences.add(dep.hash);
                                }
                            }
                        }
                    }
                }
                // if everything is consistent but we don't have it, mark to schedule
                if (valid && missing) {
                    sendLater.push(req);
                }
            }
            if (context.rootHashes.length > 0) {
                let msg = {
                    type: TerminalOpsSyncAgentMessageType.SendObjs,
                    targetObjHash: this.objHash,
                    sentObjects: context.toLiteralContext(),
                    omittedDeps: ownershipProofs,
                    ownershipProofSecret: secret
                };
                this.sendSyncMessageToPeer(destination, msg);
            }
            return sendLater;
        }
        async processReceivedObject(hash, context) {
            var _a;
            let obj = await HashedObject.fromContextWithValidation(context, hash);
            if (this.shouldAcceptMutationOp(obj)) {
                this.controlLog.trace(() => 'saving object with hash ' + hash + ' in ' + this.peerGroupAgent.localPeer.endpoint);
                this.opTransferLog.debug('Op is complete, saving ' + hash + ' of type ' + obj.getClassName());
                await this.store.save(obj);
            }
            else {
                this.controlLog.warning(() => 'NOT saving object with hash ' + hash + ' in ' + this.peerGroupAgent.localPeer.endpoint + ', it has the wrong type for a mutation op.');
            }
            let destinations = this.outgoingObjects.get(hash);
            if (destinations !== undefined) {
                for (const [endpoint, params] of destinations.entries()) {
                    this.tryToSendObjects(endpoint, [{ hash: hash, dependencyChain: params.dependencyChain }], params.secret);
                }
            }
            this.controlLog.trace('ops depending on completed object: ' + ((_a = this.opsForMissingObj.get(hash)) === null || _a === void 0 ? void 0 : _a.size));
            for (const opHash of this.opsForMissingObj.get(hash)) {
                const incompleteOp = this.incompleteOps.get(opHash);
                incompleteOp.context.objects.set(hash, obj);
                incompleteOp.missingObjects.delete(hash);
                if (incompleteOp.missingObjects.size === 0) {
                    try {
                        this.processReceivedObject(opHash, incompleteOp.context);
                        // TODO: catch error, log, report bad peer?
                    }
                    catch (e) {
                        this.controlLog.warning('could not process received object with hash ' + hash + ', error is: ' + e);
                    }
                    finally {
                        this.incompleteOps.delete(opHash);
                        this.opsForMissingObj.delete(hash, opHash);
                    }
                }
            }
            // just in case this op was received partailly before:
            // FIXME: don't do if there was an error above!
            const incompleteOp = this.incompleteOps.get(hash);
            if (incompleteOp !== undefined) {
                for (const reqHash of incompleteOp.missingObjects.keys()) {
                    this.opsForMissingObj.delete(reqHash, hash);
                }
                this.incompleteOps.delete(hash);
            }
        }
        async receiveObjects(source, literalContext, omittedDeps, secret) {
            var _a;
            let context = new Context();
            context.fromLiteralContext(literalContext);
            let ownershipProofForHash = new Map();
            for (const omittedDep of omittedDeps) {
                ownershipProofForHash.set(omittedDep.hash, omittedDep.ownershipProofHash);
            }
            if (context.checkRootHashes() && context.checkLiteralHashes()) {
                for (const hash of context.rootHashes) {
                    this.controlLog.trace(() => 'processing incoming object with hash ' + hash);
                    const incoming = (_a = this.incomingObjects.get(hash)) === null || _a === void 0 ? void 0 : _a.get(source);
                    if (incoming !== undefined && incoming.secret === secret) {
                        try {
                            let toRequest = Array();
                            // add omitted dependencies, if their ownership proofs are correct
                            for (let [depHash, depChain] of context.findMissingDeps(hash).entries()) {
                                let dep = await this.store.load(depHash);
                                if (dep === undefined || dep.hash(secret) !== ownershipProofForHash.get(depHash)) {
                                    if (dep !== undefined) {
                                        this.controlLog.warning('missing valid ownership proof for ' + hash);
                                        // TODO: log / report invalid ownership proof
                                    }
                                    toRequest.push({ hash: depHash, dependencyChain: depChain });
                                }
                                else {
                                    context.objects.set(depHash, dep);
                                }
                            }
                            if (toRequest.length === 0) {
                                this.controlLog.trace('received object with hash ' + hash + ' is complete, about to process');
                                this.processReceivedObject(hash, context);
                            }
                            else {
                                // If this claims to be an op that should be procesed later, record an incomplete op
                                if (this.shouldAcceptMutationOpLiteral(context.literals.get(hash))) {
                                    this.controlLog.trace('received object with hash ' + hash + ' is incomplete, about to process');
                                    this.processIncompleteOp(source, hash, context, toRequest);
                                }
                                else {
                                    this.controlLog.warning('received object with hash ' + hash + ' has the wrong type for a mutation op, ignoring');
                                }
                                this.sendRequestObjsMessage(source, toRequest);
                                //console.log('requesting objects from missing deps: ' + toRequest.map((req: ObjectRequest) => req.hash));
                            }
                        }
                        catch (e) {
                            TerminalOpsSyncAgent.controlLog.warning(e);
                        }
                        this.incomingObjects.delete(hash);
                    }
                    else {
                        // TODO: report missing or incorrect incoming object entry
                        if (incoming === undefined) {
                            if (await this.store.load(hash) === undefined) {
                                this.controlLog.warning('missing incoming object entry for hash ' + hash + ' in object sent by ' + source);
                            }
                        }
                        else {
                            this.controlLog.warning('incoming object secret mismatch, expected: ' + secret + ', received: ' + incoming.secret);
                        }
                    }
                }
            }
            else {
                // TODO: report invalid context somewhere
                this.controlLog.warning('received invalid context from ' + source + ' with rootHashes ' + (context === null || context === void 0 ? void 0 : context.rootHashes));
            }
        }
        async processIncompleteOp(source, hash, context, toRequest) {
            let incompleteOp = this.incompleteOps.get(hash);
            let missingObjects = new Map(toRequest.map((req) => [req.hash, req]));
            if (incompleteOp === undefined) {
                this.opTransferLog.debug('Received new incomplete op ' + hash + ', missing objects: ' + toRequest.map((req) => req.hash));
                incompleteOp = {
                    source: source,
                    context: context,
                    missingObjects: missingObjects,
                    timeout: Date.now() + this.params.incompleteOpTimeout * 1000
                };
                this.incompleteOps.set(hash, incompleteOp);
                for (const objReq of toRequest) {
                    this.opsForMissingObj.add(objReq.hash, hash);
                }
            }
            else {
                const initialMissingCount = incompleteOp.missingObjects.size;
                incompleteOp.context.merge(context);
                let found = new Array();
                for (const missingHash of incompleteOp.missingObjects.keys()) {
                    if (incompleteOp.context.has(missingHash)) {
                        found.push(missingHash);
                    }
                }
                for (const foundHash of found) {
                    incompleteOp.missingObjects.delete(foundHash);
                    this.opsForMissingObj.delete(foundHash, hash);
                }
                if (incompleteOp.missingObjects.size === 0) {
                    try {
                        this.processReceivedObject(hash, context);
                    }
                    finally {
                        // FIXME: if someone sends a broken dependency object, this would remove the
                        //        op from the incompleteOp map!
                        this.incompleteOps.delete(hash);
                    }
                }
                else if (incompleteOp.missingObjects.size < initialMissingCount) {
                    this.opTransferLog.debug('Received duplicated incomplete op ' + hash + ', completed ' + (initialMissingCount - incompleteOp.missingObjects.size) + 'deps, ' + incompleteOp.missingObjects.size + ' remain to be fetched');
                    incompleteOp.timeout = Date.now() + this.params.incompleteOpTimeout * 1000;
                }
                else {
                    this.opTransferLog.debug('Received duplicated incomplete op ' + hash + ', no missing dependencies were present');
                }
            }
        }
        sendSyncMessageToPeer(destination, msg) {
            this.sendMessageToPeer(destination, this.getAgentId(), msg);
        }
        shouldAcceptMutationOp(op) {
            var _a;
            return this.objHash === ((_a = op.targetObject) === null || _a === void 0 ? void 0 : _a.hash()) &&
                this.acceptedMutationOpClasses.indexOf(op.getClassName()) >= 0;
        }
        shouldAcceptMutationOpLiteral(op) {
            return this.objHash === LiteralUtils.getFields(op)['targetObject']._hash &&
                this.acceptedMutationOpClasses.indexOf(op.value._class) >= 0;
        }
        expectIncomingObject(source, objHash, dependencyChain, secret) {
            return this.insertObjectMovement(this.incomingObjects, source, objHash, dependencyChain, secret, this.params.receiveTimeout);
        }
        scheduleOutgoingObject(destination, objHash, dependencyChain, secret) {
            return this.insertObjectMovement(this.outgoingObjects, destination, objHash, dependencyChain, secret, this.params.sendTimeout);
        }
        insertObjectMovement(allMovements, endpoint, objHash, dependencyChain, secret, timeout) {
            let movement = allMovements.get(objHash);
            if (movement === undefined) {
                movement = new Map();
                allMovements.set(objHash, movement);
            }
            if (movement.has(endpoint)) {
                return false;
            }
            else {
                movement.set(endpoint, { dependencyChain: dependencyChain, secret: secret, timeout: Date.now() + timeout * 1000 });
                return true;
            }
        }
    }
    TerminalOpsSyncAgent.controlLog = new Logger(TerminalOpsSyncAgent.name, LogLevel.INFO);
    TerminalOpsSyncAgent.peerMessageLog = new Logger(TerminalOpsSyncAgent.name, LogLevel.INFO);
    TerminalOpsSyncAgent.opTransferLog = new Logger(TerminalOpsSyncAgent.name, LogLevel.INFO);

    class HeaderBasedState extends HashedObject {
        constructor(mutableObj, terminalOpHistories) {
            super();
            this.mutableObj = mutableObj;
            if (terminalOpHistories !== undefined) {
                this.terminalOpHeaderHashes = new HashedSet(new Set(terminalOpHistories.map((h) => h.headerHash)).values());
                this.terminalOpHeaders = new HashedSet(new Set(terminalOpHistories.map((h) => h.literalize())).values());
            }
            else {
                this.terminalOpHeaderHashes = new HashedSet();
                this.terminalOpHeaders = new HashedSet();
            }
        }
        static async createFromTerminalOps(mutableObj, terminalOps, store) {
            const terminalOpHeaders = [];
            for (const opHash of terminalOps) {
                const history = await store.loadOpHeader(opHash);
                terminalOpHeaders.push(history);
            }
            return HeaderBasedState.create(mutableObj, terminalOpHeaders);
        }
        static create(target, terminalOpHistories) {
            return new HeaderBasedState(target, terminalOpHistories);
        }
        getClassName() {
            return HeaderBasedState.className;
        }
        async validate(_references) {
            var _a;
            if (this.mutableObj === undefined) {
                return false;
            }
            if (this.terminalOpHeaderHashes === undefined || !(this.terminalOpHeaderHashes instanceof HashedSet)) {
                return false;
            }
            if (this.terminalOpHeaders == undefined || !(this.terminalOpHeaders instanceof HashedSet)) {
                return false;
            }
            for (const hash of this.terminalOpHeaderHashes.values()) {
                if (typeof (hash) !== 'string') {
                    return false;
                }
            }
            const checkHashes = new HashedSet();
            for (const hashedLit of (_a = this.terminalOpHeaders) === null || _a === void 0 ? void 0 : _a.values()) {
                if (hashedLit === undefined) {
                    return false;
                }
                try {
                    const h = new OpHeader(hashedLit);
                    /*
                    // the following makes no sense, it is comparing an op hash with the mutable obj hash
                    // I'm commenting it out, can't see what the intent was

                    if (h.opHash !== this.mutableObj) {
                        return false;
                    }
                    */
                    checkHashes.add(h.headerHash);
                }
                catch (e) {
                    return false;
                }
            }
            if (!this.terminalOpHeaderHashes.equals(checkHashes)) {
                return false;
            }
            return true;
        }
        init() {
        }
    }
    HeaderBasedState.className = 'hhs/v0/HeaderBasedState';
    HashedObject.registerClass(HeaderBasedState.className, HeaderBasedState);

    class HistoryWalk {
        constructor(direction, initial, fragment, filter) {
            this.direction = direction;
            this.fragment = fragment;
            this.visited = new Set();
            this.queue = [];
            this.queueContents = new Set();
            this.filter = filter;
            for (const hash of initial.values()) {
                if (this.fragment.contents.has(hash) && (filter === undefined || filter(hash))) {
                    this.enqueueIfNew(hash);
                }
            }
        }
        [Symbol.iterator]() {
            return this;
        }
        enqueueIfNew(what) {
            if (!this.visited.has(what) && !this.queueContents.has(what)) {
                this.enqueue(what);
            }
        }
        enqueue(what) {
            this.queue.push(what);
            this.queueContents.add(what);
        }
        dequeue() {
            const result = this.queue.shift();
            this.queueContents.delete(result);
            return result;
        }
        goFrom(opHeaderHash) {
            let unfiltered;
            if (this.direction === 'forward') {
                unfiltered = this.goForwardFrom(opHeaderHash);
            }
            else {
                unfiltered = this.goBackwardFrom(opHeaderHash);
            }
            if (this.filter === undefined) {
                return unfiltered;
            }
            else {
                const filtered = new Set();
                for (const hash of unfiltered.values()) {
                    if (this.filter(hash)) {
                        filtered.add(hash);
                    }
                }
                return filtered;
            }
        }
        goForwardFrom(opHeaderHash) {
            return this.fragment.nextOpHeaders.get(opHeaderHash);
        }
        goBackwardFrom(opHeaderHash) {
            const history = this.fragment.contents.get(opHeaderHash);
            if (history !== undefined) {
                return history.prevOpHeaders;
            }
            else {
                return new Set();
            }
        }
    }

    class BFSHistoryWalk extends HistoryWalk {
        next() {
            if (this.queue.length > 0) {
                const hash = this.dequeue();
                for (const succ of this.goFrom(hash)) {
                    // if succ is in fragment.missing do not go there
                    if (this.fragment.contents.has(succ)) {
                        this.enqueueIfNew(succ);
                    }
                }
                const nextOp = this.fragment.contents.get(hash);
                if (nextOp === undefined) {
                    throw new Error('Missing op history found while walking history fragment, probably includeInitial=true and direction=forward where chosen that are an incompatible pair');
                }
                return { value: nextOp, done: false };
            }
            else {
                return { done: true, value: undefined };
            }
        }
    }

    class FullHistoryWalk extends HistoryWalk {
        next() {
            if (this.queue.length > 0) {
                const hash = this.dequeue();
                for (const succ of this.goFrom(hash)) {
                    // if succ is in fragment.missing do not go there
                    if (this.fragment.contents.has(succ)) {
                        this.enqueue(succ);
                    }
                }
                const nextOp = this.fragment.contents.get(hash);
                if (nextOp === undefined) {
                    throw new Error('Missing op history found while walking history fragment, probably includeInitial=true and direction=forward where chosen that are an incompatible pair');
                }
                return { value: nextOp, done: false };
            }
            else {
                return { done: true, value: undefined };
            }
        }
    }

    // A CasualHistoryFragment is built from a (sub)set of operations
    // for a given MutableObject target, that are stored in the "contents"
    // (Hash -> OpCausalHistory) map.
    // Since during sync the ops themselves are not available, a supplemental
    // OpCausalHistory object is used. It only contains the hash of the op,
    // the hash of the OpCausalHistory objects of its predecessors, and some
    // extra information.
    // All history manipulation is done over OpCausalHistory objects, the actual
    // op hashes can be obtained once the causality has been sorted out.
    // The fragment keeps track of the set of terminal ops (ops without any
    // following ops, in the sense that they are the last ops to have been
    // applied according to te causal ordering defined by the "prevOps" field).
    // It also keeps track of the ops that are referenced by the ops in the 
    // fragment but are not in it (in the "missingPrevOpHistories" field).
    // Therefore the fragment may be seen as a set of ops that takes the target
    // MutableObject from a state that contains all the ops in "missingPrevOpHistories" to a
    // state that contains all the ops in "terminalOpHistories".
    // lemma: if an op is new to the fragment, then it either
    //
    //        a) is in the missingOps set.
    //
    //                     or
    //
    //        b) is not a direct dependency of any ops in the fragment
    //           and therefore it should go into terminalOps.
    // proof: assume neither a) or b) hold, then you have a
    //        new op that is not in missingOps, but is a
    //        direct dependency of an op present in the fragment.
    //        But then, since it is a direct dependency and it is not in
    //        missingOps, it must be present in the fragment, contrary
    //        to our assumption.
    class HistoryFragment {
        constructor(target) {
            this.mutableObj = target;
            this.terminalOpHeaders = new Set();
            this.missingPrevOpHeaders = new Set();
            this.contents = new Map();
            this.roots = new Set();
            this.opHeadersForOp = new MultiMap();
            this.nextOpHeaders = new MultiMap();
        }
        add(opHeader) {
            if (this.isNew(opHeader.headerHash)) {
                this.contents.set(opHeader.headerHash, opHeader);
                this.opHeadersForOp.add(opHeader.opHash, opHeader.headerHash);
                if (opHeader.prevOpHeaders.size === 0) {
                    this.roots.add(opHeader.headerHash);
                }
                // Adjust missingOps and terminalOps (see lemma above)
                if (this.missingPrevOpHeaders.has(opHeader.headerHash)) {
                    this.missingPrevOpHeaders.delete(opHeader.headerHash);
                }
                else {
                    this.terminalOpHeaders.add(opHeader.headerHash);
                }
                for (const prevOpHeader of opHeader.prevOpHeaders) {
                    // Adjust missingOps and terminalOps with info about this new prev op
                    if (this.isNew(prevOpHeader)) {
                        // It may or may not be in missingOps but, since prevOp 
                        // is new, in any case add:
                        this.missingPrevOpHeaders.add(prevOpHeader);
                    }
                    else {
                        // It may or may not be in terminalOps but, since prevOp 
                        // is not new, in any case remove:
                        this.terminalOpHeaders.delete(prevOpHeader);
                    }
                    // Add reverse mapping to nextOps
                    this.nextOpHeaders.add(prevOpHeader, opHeader.headerHash);
                }
            }
        }
        remove(opHeaderHash) {
            const opHeader = this.contents.get(opHeaderHash);
            if (opHeader !== undefined) {
                this.contents.delete(opHeader.headerHash);
                this.opHeadersForOp.delete(opHeader.opHash, opHeader.headerHash);
                this.terminalOpHeaders.delete(opHeader.headerHash);
                if (opHeader.prevOpHeaders.size === 0) {
                    this.roots.delete(opHeader.headerHash);
                }
                if (this.nextOpHeaders.get(opHeaderHash).size > 0) {
                    this.missingPrevOpHeaders.add(opHeaderHash);
                }
                for (const prevOpHistoryHash of opHeader.prevOpHeaders) {
                    this.nextOpHeaders.delete(prevOpHistoryHash, opHeader.headerHash);
                    if (this.nextOpHeaders.get(prevOpHistoryHash).size === 0) {
                        if (this.contents.has(prevOpHistoryHash)) {
                            this.terminalOpHeaders.add(prevOpHistoryHash);
                        }
                        else {
                            this.missingPrevOpHeaders.delete(prevOpHistoryHash);
                        }
                    }
                }
            }
        }
        verifyUniqueOps() {
            for (const opHashes of this.opHeadersForOp.values()) {
                if (opHashes.size > 1) {
                    return false;
                }
            }
            return true;
        }
        clone() {
            const clone = new HistoryFragment(this.mutableObj);
            for (const opHistory of this.contents.values()) {
                clone.add(opHistory);
            }
            return clone;
        }
        filterByTerminalOpHeaders(terminalOpHeaders) {
            const filteredOpHeaders = this.closureFrom(terminalOpHeaders, 'backward');
            const filtered = new HistoryFragment(this.mutableObj);
            for (const hash of filteredOpHeaders.values()) {
                filtered.add(this.contents.get(hash));
            }
            return filtered;
        }
        removeNonTerminalOps() {
            const terminal = new Set(this.terminalOpHeaders);
            for (const hash of Array.from(this.contents.keys())) {
                if (!terminal.has(hash)) {
                    this.remove(hash);
                }
            }
        }
        addAllPredecessors(origin, fragment) {
            for (const opHeader of fragment.iterateFrom(origin, 'backward', 'bfs')) {
                this.add(opHeader);
            }
        }
        getStartingOpHeaders() {
            const startingOpHeaders = new Set();
            for (const root of this.roots) {
                startingOpHeaders.add(root);
            }
            for (const missing of this.missingPrevOpHeaders) {
                for (const starting of this.nextOpHeaders.get(missing)) {
                    startingOpHeaders.add(starting);
                }
            }
            return startingOpHeaders;
        }
        getTerminalOps() {
            return this.getOpsForHeaders(this.terminalOpHeaders);
        }
        getStartingOps() {
            return this.getOpsForHeaders(this.getStartingOpHeaders());
        }
        getOpHeaderForOp(opHash) {
            let opHistories = this.opHeadersForOp.get(opHash);
            if (opHistories === undefined) {
                return undefined;
            }
            else {
                if (opHistories.size > 1) {
                    throw new Error('Op histories matching op ' + opHash + ' were requested from fragment, but there is more than one (' + opHistories.size + ')');
                }
                else {
                    return this.contents.get(opHistories.values().next().value);
                }
            }
        }
        getAllOpHeadersForOp(opHash) {
            const opHistories = (Array.from(this.opHeadersForOp.get(opHash))
                .map((hash) => this.contents.get(hash)));
            return opHistories;
        }
        // The following 3 functions operate on the known part of the fragment (what's
        // in this.contents, not the hashes in missingOpHistories).
        // Returns an iterator that visits all opHistories reachable from the initial set.
        // - If method is 'bfs', each op history is visited once, in BFS order.
        // - If method is 'causal', each op history is visited as many tomes as there is
        //   a causality relation leading to it (in the provided direction).
        iterateFrom(initial, direction = 'forward', method = 'bfs', filter) {
            if (!(initial instanceof Set)) {
                initial = new Set([initial]);
            }
            if (method === 'bfs') {
                return new BFSHistoryWalk(direction, initial, this, filter);
            }
            else {
                return new FullHistoryWalk(direction, initial, this, filter);
            }
        }
        // Returns the set of terminal opHistories reachable from initial.
        terminalOpsFor(originOpHeaders, direction = 'forward') {
            if (!(originOpHeaders instanceof Set)) {
                originOpHeaders = new Set([originOpHeaders]);
            }
            const terminal = new Set();
            for (const opHeader of this.iterateFrom(originOpHeaders, direction, 'bfs')) {
                let isTerminal;
                if (direction === 'forward') {
                    isTerminal = this.nextOpHeaders.get(opHeader.headerHash).size === 0;
                }
                else if (direction === 'backward') {
                    isTerminal = true;
                    for (const prevOpHistory of opHeader.prevOpHeaders) {
                        if (!this.missingPrevOpHeaders.has(prevOpHistory)) {
                            isTerminal = false;
                            break;
                        }
                    }
                }
                else {
                    throw new Error("Direction should be 'forward' or 'backward'.");
                }
                if (isTerminal) {
                    terminal.add(opHeader);
                }
            }
            return terminal;
        }
        // Returns true if ALL the hashes in destination are reachable from origin.
        isReachable(originOpHeaders, destinationOpHeaders, direction) {
            const targets = new Set(destinationOpHeaders.values());
            for (const opHistory of this.iterateFrom(originOpHeaders, direction, 'bfs')) {
                targets.delete(opHistory.headerHash);
                if (targets.size === 0) {
                    break;
                }
            }
            return targets.size === 0;
        }
        closureFrom(originOpHeaders, direction, filter) {
            const result = new Set();
            for (const opHeader of this.iterateFrom(originOpHeaders, direction, 'bfs', filter)) {
                result.add(opHeader.headerHash);
            }
            return result;
        }
        causalClosureFrom(startingOpHeaders, providedOpHeaders, maxOps, ignoreOpHeader, filterOpHeader) {
            // We iterate over all the depenency "arcs", each time recording that one dependency has been
            // fullfilled by removing it from a set in missingOpHistories. If the set ever empties, this
            // op can be iterated over (all its prevOps have already been visited). 
            var _a, _b;
            const closure = new Set();
            const missingPrevOpHeaders = new Map();
            const result = new Array();
            // Create the initial entries in missingPrevOpHistories, not considering anyPrevOps in 
            // providedOpHistories.
            /*
            for (const startingHash of startingOpHistories) {
                if (filterOpHistory === undefined || filterOpHistory(startingHash)) {
                    const startingOpHistory = this.contents.get(startingHash) as OpCausalHistory;
                    CausalHistoryFragment.loadMissingPrevOpHistories(missingPrevOpHistories, startingOpHistory, providedOpHistories);
                }
            }
            */
            for (const opHeader of this.iterateFrom(startingOpHeaders, 'forward', 'full')) {
                if (maxOps !== undefined && maxOps === result.length) {
                    break;
                }
                const hash = opHeader.headerHash;
                if ((filterOpHeader === undefined || filterOpHeader(hash))) {
                    HistoryFragment.loadMissingPrevOpHeaders(missingPrevOpHeaders, opHeader, providedOpHeaders);
                    if (((_a = missingPrevOpHeaders.get(hash)) === null || _a === void 0 ? void 0 : _a.size) === 0) {
                        for (const nextHash of this.nextOpHeaders.get(hash)) {
                            const nextOpHeader = this.contents.get(nextHash);
                            if (filterOpHeader === undefined || filterOpHeader(nextHash)) {
                                HistoryFragment.loadMissingPrevOpHeaders(missingPrevOpHeaders, nextOpHeader, providedOpHeaders);
                                (_b = missingPrevOpHeaders.get(nextHash)) === null || _b === void 0 ? void 0 : _b.delete(hash);
                            }
                        }
                        if (!closure.has(hash)) {
                            closure.add(hash);
                            if (ignoreOpHeader === undefined || !ignoreOpHeader(hash)) {
                                result.push(hash);
                            }
                        }
                    }
                }
            }
            return result;
        }
        causalClosure(providedOpHeaders, maxOps, ignoreOpHeader, filterOpHeader) {
            return this.causalClosureFrom(this.getStartingOpHeaders(), providedOpHeaders, maxOps, ignoreOpHeader, filterOpHeader);
        }
        async loadFromTerminalOpHeaders(store, terminalOpHeaders, maxOpHeaders, forbiddenOpHeaders) {
            let next = new Array();
            for (const opHeaderHash of terminalOpHeaders) {
                if (forbiddenOpHeaders === undefined || !forbiddenOpHeaders.has(opHeaderHash)) {
                    next.push(opHeaderHash);
                }
            }
            do {
                for (const opHeaderHash of next) {
                    const opHistory = await store.loadOpHeaderByHeaderHash(opHeaderHash);
                    this.add(opHistory);
                    if (maxOpHeaders === this.contents.size) {
                        break;
                    }
                }
                next = [];
                for (const opHeaderHash of this.missingPrevOpHeaders) {
                    if (forbiddenOpHeaders === undefined || !forbiddenOpHeaders.has(opHeaderHash)) {
                        next.push(opHeaderHash);
                    }
                }
            } while (next.length > 0 && !(this.contents.size === maxOpHeaders));
        }
        static loadMissingPrevOpHeaders(missingPrevOpHeaders, opHeader, providedOpHeaders) {
            let missing = missingPrevOpHeaders.get(opHeader.headerHash);
            if (missing === undefined) {
                missing = new Set();
                for (const prevOp of opHeader.prevOpHeaders) {
                    if (!providedOpHeaders.has(prevOp)) {
                        missing.add(prevOp);
                    }
                }
                missingPrevOpHeaders.set(opHeader.headerHash, missing);
            }
        }
        isNew(headerHash) {
            return !this.contents.has(headerHash);
        }
        getOpsForHeaders(headers) {
            return new Set(Array.from(headers).map((history) => { var _a; return (_a = this.contents.get(history)) === null || _a === void 0 ? void 0 : _a.opHash; }));
        }
    }

    class Lock {
        constructor() {
            this.inUse = false;
        }
        acquire() {
            const success = !this.inUse;
            this.inUse = true;
            return success;
        }
        release() {
            const success = this.inUse;
            this.inUse = false;
            return success;
        }
    }

    class HistoryDelta {
        constructor(mutableObj, store) {
            this.mutableObj = mutableObj;
            this.store = store;
            this.fragment = new HistoryFragment(mutableObj);
            this.start = new HistoryFragment(mutableObj);
            this.gap = new Set();
        }
        async compute(targetOpHeaders, startingOpHeaders, maxDeltaSize, maxBacktrackSize) {
            var _a, _b, _c;
            for (const hash of startingOpHeaders) {
                const opHeader = await this.store.loadOpHeaderByHeaderHash(hash);
                if (opHeader !== undefined) {
                    this.start.add(opHeader);
                    this.fragment.remove(opHeader.headerHash);
                }
            }
            for (const hash of targetOpHeaders) {
                if (!this.start.contents.has(hash)) {
                    const opHeader = await this.store.loadOpHeaderByHeaderHash(hash);
                    if (opHeader !== undefined) {
                        this.fragment.add(opHeader);
                    }
                }
            }
            this.updateGap();
            while (this.gap.size > 0 && this.fragment.contents.size < maxDeltaSize) {
                let h = undefined;
                for (const hash of this.fragment.getStartingOpHeaders()) {
                    const op = this.fragment.contents.get(hash);
                    if (h === undefined || ((_a = op.computedProps) === null || _a === void 0 ? void 0 : _a.height) < h) {
                        h = (_b = op.computedProps) === null || _b === void 0 ? void 0 : _b.height;
                    }
                }
                for (const hash of Array.from(this.start.missingPrevOpHeaders)) {
                    if (this.start.contents.size >= maxBacktrackSize) {
                        break;
                    }
                    const op = await this.store.loadOpHeaderByHeaderHash(hash);
                    if (op !== undefined && ((_c = op.computedProps) === null || _c === void 0 ? void 0 : _c.height) > h) {
                        this.start.add(op);
                        this.fragment.remove(hash);
                    }
                }
                for (const hash of Array.from(this.fragment.missingPrevOpHeaders)) {
                    if (this.fragment.contents.size >= maxDeltaSize) {
                        break;
                    }
                    if (!this.start.contents.has(hash)) {
                        const op = await this.store.loadOpHeaderByHeaderHash(hash);
                        if (op !== undefined) {
                            this.fragment.add(op);
                        }
                    }
                }
                this.updateGap();
            }
        }
        opHeadersFollowingFromStart(maxOps) {
            const start = new Set(this.start.contents.keys());
            return this.fragment.causalClosure(start, maxOps);
        }
        updateGap() {
            const gap = new Set();
            for (const hash of this.fragment.missingPrevOpHeaders) {
                if (!this.start.contents.has(hash)) {
                    gap.add(hash);
                }
            }
            this.gap = gap;
        }
    }

    class ObjectPacker {
        constructor(store, maxLiterals) {
            this.store = store;
            this.content = [];
            this.contentHashes = new Set();
            this.omissions = new Map();
            this.allowedOmissions = new Map();
            this.maxLiterals = maxLiterals;
            this.filterPrevOpsFromDeps = (lit) => {
                const prevOpHashes = HashedSet.elementsFromLiteral(LiteralUtils.getFields(lit)['prevOps']).map(HashReference.hashFromLiteral);
                return lit.dependencies.filter((dep) => prevOpHashes.indexOf(dep.hash) < 0);
            };
        }
        allowOmission(hash, referenceChain) {
            if (!this.allowedOmissions.has(hash)) {
                this.allowedOmissions.set(hash, referenceChain);
            }
        }
        async allowOmissionsRecursively(initialHashesToOmit, maxAllowedOmissions, isAdditionalReferenceRoot) {
            const omittableRefsQueue = Array.from(initialHashesToOmit);
            const omittableRefs = new Set();
            const refChains = new Map();
            for (const hash of omittableRefsQueue) {
                omittableRefs.add(hash);
                refChains.set(hash, [hash]);
            }
            while (omittableRefsQueue.length > 0 && (maxAllowedOmissions === undefined || this.allowedOmissions.size < maxAllowedOmissions)) {
                const nextHash = omittableRefsQueue.shift();
                const literal = await this.store.loadLiteral(nextHash);
                if (literal !== undefined) {
                    let refChain = refChains.get(nextHash);
                    if (isAdditionalReferenceRoot !== undefined && isAdditionalReferenceRoot(literal)) {
                        refChain = [nextHash];
                    }
                    this.allowOmission(nextHash, refChain);
                    for (const dep of literal.dependencies) {
                        if (!this.allowedOmissions.has(dep.hash) && !omittableRefs.has(dep.hash)) {
                            omittableRefs.add(dep.hash);
                            omittableRefsQueue.push(dep.hash);
                            const depRefChain = refChain.slice();
                            depRefChain.push(dep.hash);
                            refChains.set(dep.hash, depRefChain);
                        }
                    }
                }
            }
        }
        async addObject(hash) {
            if (this.contentHashes.has(hash)) {
                return true;
            }
            else {
                const result = await this.attemptToAdd(hash, this.maxLiterals - this.content.length);
                if (result !== undefined) {
                    // Since literals is in inverse causal order, its elements should be reversed 
                    // when added to the pack.
                    while (result.literals.length > 0) {
                        const literal = result.literals.pop();
                        this.content.push(literal);
                        this.contentHashes.add(literal.hash);
                    }
                    for (const hash of result.omitted.keys()) {
                        // We're currently computing two different reference chains: attemptToAdd will return
                        // how the added object references the omitted one, while this.allowedOmissions has
                        // the ref chain saved back from when the omission was allowed.
                        // We're currently using the second one, so the verifier can verify just as he receives
                        // his response, and withouth risking leaking any information unrelated to the mutable
                        // being synchronized.
                        this.omissions.set(hash, this.allowedOmissions.get(hash));
                    }
                    return true;
                }
                else {
                    return false;
                }
            }
        }
        // Attempt to add all causal history ops and their needed dependencies
        // starting from the given set until the very last ones.
        // If successful, return true. If there are more ops to send, return
        // false.
        async addForwardOps(initHistoryHashes, causalHistory) {
            for (const opHistory of causalHistory.iterateFrom(initHistoryHashes, 'forward')) {
                if (!await this.addObject(opHistory.opHash)) {
                    return false;
                }
            }
            return true;
        }
        // attemptToadd impotant note: the literal array is in inverse causal order.
        //                             (i.e. the last element should be applied first)
        async attemptToAdd(hash, maxAllowedLiterals) {
            const queued = new Array();
            const packed = new Array();
            const packedHashes = new Set();
            const omitted = new Map();
            const currentReferenceChain = new Array();
            if (!this.contentHashes.has(hash) && !this.allowedOmissions.has(hash)) {
                queued.push([hash]);
            }
            while (queued.length > 0 && packed.length < maxAllowedLiterals) {
                const nextHashes = queued.pop();
                if (nextHashes.length === 0) {
                    currentReferenceChain.pop();
                }
                else {
                    const nextHash = nextHashes.shift();
                    queued.push(nextHashes);
                    if (!this.contentHashes.has(nextHash) && !packedHashes.has(nextHash) && !omitted.has(nextHash)) {
                        if (this.allowedOmissions.has(nextHash)) {
                            omitted.set(nextHash, currentReferenceChain.slice());
                        }
                        else {
                            const literal = await this.store.loadLiteral(nextHash);
                            packed.push(literal);
                            packedHashes.add(literal.hash);
                            const deps = literal.dependencies.map((d) => d.hash);
                            queued.push(deps);
                            currentReferenceChain.push(nextHash);
                        }
                    }
                }
            }
            if (queued.length === 0) {
                return { literals: packed, omitted: omitted };
            }
            else {
                return undefined;
            }
        }
    }

    exports.MessageType = void 0;
    (function (MessageType) {
        MessageType["Request"] = "request";
        MessageType["Response"] = "response";
        MessageType["RejectRequest"] = "reject-request";
        MessageType["SendLiteral"] = "send-literal";
        MessageType["CancelRequest"] = "cancel-request";
    })(exports.MessageType || (exports.MessageType = {}));
    const ProviderLimits = {
        MaxOpsToRequest: 512,
        MaxLiteralsPerResponse: 1024,
        MaxHistoryPerResponse: 1024
    };
    const LiteralBatchSize = 256;
    class HistoryProvider {
        constructor(syncAgent) {
            this.syncAgent = syncAgent;
            this.responses = new Map();
            this.currentResponses = new Map();
            this.queuedResponses = new Map();
            this.streamingResponses = 0;
            this.checkIfLiteralIsValidOp = (literal) => this.syncAgent.literalIsValidOp(literal);
            this.continueStreamingResponses = this.continueStreamingResponses.bind(this);
            this.controlLog = HistoryProvider.controlLog;
            this.storeLog = HistoryProvider.storeLog;
            this.opXferLog = HistoryProvider.opXferLog;
        }
        continueStreamingResponses() {
            for (const requestId of this.currentResponses.values()) {
                const respInfo = this.responses.get(requestId);
                if (respInfo !== undefined) {
                    this.sendLiterals(respInfo.request.requestId, LiteralBatchSize);
                }
            }
        }
        // TODO: check if we answer right away, or if we're already streaming literals
        //       from a previous request and this needs to be queued
        async onReceivingRequest(remote, msg) {
            if (this.responses.get(msg.requestId) === undefined) {
                const respInfo = {
                    request: msg,
                    remote: remote,
                    status: 'created',
                    requestArrivalTimestamp: Date.now()
                };
                if (msg.mutableObj !== this.syncAgent.mutableObjHash) {
                    const detail = 'Rejecting request ' + respInfo.request.requestId + ', mutableObj is ' + respInfo.request.mutableObj + ' but it should be ' + this.syncAgent.mutableObjHash;
                    this.rejectRequest(respInfo, 'invalid-request', detail);
                    return;
                }
                else {
                    this.responses.set(msg.requestId, respInfo);
                    if (this.currentResponses.get(remote) === undefined) {
                        this.sendResponse(respInfo);
                    }
                    else {
                        this.enqueueResponse(respInfo);
                    }
                }
            }
        }
        onReceivingRequestCancellation(remote, msg) {
            const cancelledResp = this.responses.get(msg.requestId);
            if (cancelledResp !== undefined && cancelledResp.remote === remote) {
                this.removeResponse(cancelledResp);
                HistoryProvider.controlLog.debug('Received request cancellation for ' + msg.requestId);
            }
        }
        async createResponse(respInfo) {
            await this.logStoreContents(respInfo.request.requestId);
            const req = respInfo.request;
            const resp = {
                type: exports.MessageType.Response,
                requestId: respInfo.request.requestId,
                literalCount: 0
            };
            // Validate history request, if present
            if (respInfo.request.requestedTerminalOpHistory !== undefined || respInfo.request.requestedStartingOpHistory !== undefined) {
                const toCheck = new Set();
                if (respInfo.request.requestedTerminalOpHistory !== undefined) {
                    for (const hash of respInfo.request.requestedTerminalOpHistory) {
                        toCheck.add(hash);
                    }
                }
                if (respInfo.request.requestedStartingOpHistory !== undefined) {
                    for (const hash of respInfo.request.requestedStartingOpHistory) {
                        toCheck.add(hash);
                    }
                }
                for (const opHistoryHash of toCheck) {
                    const opHistory = await this.syncAgent.store.loadOpHeaderByHeaderHash(opHistoryHash);
                    if (opHistory !== undefined) {
                        const literal = await this.syncAgent.store.loadLiteral(opHistory.opHash);
                        if (!this.syncAgent.literalIsValidOp(literal)) {
                            const detail = 'Invalid requestedTerminalOpHistory/requestedStartingOpHistory for request ' + respInfo.request.requestId + ', rejecting';
                            this.rejectRequest(respInfo, 'invalid-request', detail);
                            return false;
                        }
                    }
                }
            }
            // Validate requested ops, if present
            if (respInfo.request.requestedOps !== undefined) {
                for (const opHash of respInfo.request.requestedOps) {
                    const literal = await this.syncAgent.store.loadLiteral(opHash);
                    if (!this.syncAgent.literalIsValidOp(literal)) {
                        const detail = 'Invalid requestedOps for request ' + respInfo.request.requestId + ', rejecting';
                        this.rejectRequest(respInfo, 'invalid-request', detail);
                        return false;
                    }
                }
            }
            // Validate sent state, if present
            const remoteStateOps = new Set();
            if (respInfo.request.currentState !== undefined) {
                for (const opHistoryHash of respInfo.request.currentState) {
                    const opHistory = await this.syncAgent.store.loadOpHeaderByHeaderHash(opHistoryHash);
                    if (opHistory !== undefined) {
                        const literal = await this.syncAgent.store.loadLiteral(opHistory.opHash);
                        if (!this.syncAgent.literalIsValidOp(literal)) {
                            const detail = 'Invalid currentState for request ' + respInfo.request.requestId + ', rejecting';
                            this.rejectRequest(respInfo, 'invalid-request', detail);
                            return false;
                        }
                        remoteStateOps.add(opHistory.opHash);
                    }
                }
            }
            // OK - Request is valid.
            // Generate history fragment to include in the response
            const respDelta = new HistoryDelta(this.syncAgent.mutableObjHash, this.syncAgent.store);
            let maxHistory = req.maxHistory;
            let maxOps = req.maxLiterals;
            if (maxHistory === undefined || maxHistory > ProviderLimits.MaxHistoryPerResponse) {
                maxHistory = ProviderLimits.MaxHistoryPerResponse;
            }
            if (maxOps === undefined || maxOps > ProviderLimits.MaxOpsToRequest) {
                maxOps = ProviderLimits.MaxOpsToRequest;
            }
            let respHistoryFragment = undefined;
            if (req.requestedTerminalOpHistory !== undefined && req.requestedTerminalOpHistory.length > 0) {
                const start = req.requestedStartingOpHistory === undefined ? [] : req.requestedStartingOpHistory;
                await respDelta.compute(req.requestedTerminalOpHistory, start, maxHistory, 512);
                respHistoryFragment = respDelta.fragment.filterByTerminalOpHeaders(new Set(req.requestedTerminalOpHistory));
                if (respHistoryFragment.contents.size > 0) {
                    resp.history = Array.from(respHistoryFragment.contents.values()).map((h) => h.literalize());
                }
            }
            let maxLiterals = respInfo.request.maxLiterals;
            if (maxLiterals === undefined || maxLiterals > ProviderLimits.MaxLiteralsPerResponse) {
                maxLiterals = ProviderLimits.MaxLiteralsPerResponse;
            }
            // TODO: only load packer if we're going to send ops
            const packer = new ObjectPacker(this.syncAgent.store, maxLiterals);
            await packer.allowOmissionsRecursively(remoteStateOps.values(), 2048, this.checkIfLiteralIsValidOp);
            let full = false;
            const sendingOps = new Array();
            if (respInfo.request.requestedOps !== undefined) {
                for (const hash of respInfo.request.requestedOps) {
                    if (sendingOps.length === maxOps) {
                        break;
                    }
                    if (!packer.allowedOmissions.has(hash)) {
                        full = !await packer.addObject(hash);
                        if (full) {
                            this.opXferLog.trace('Cannot pack ' + hash + ', no room.');
                            break;
                        }
                        else {
                            this.opXferLog.trace('Packed ' + hash + '. ' + packer.content.length + ' literals packed so far.');
                            sendingOps.push(hash);
                        }
                    }
                    else {
                        this.opXferLog.debug('Cannot pack ' + hash + ': it is an allowed omision.\nreference chain is: ' + packer.allowedOmissions.get(hash));
                    }
                }
            }
            if (!full &&
                respInfo.request.mode === 'infer-req-ops' &&
                respInfo.request.requestedTerminalOpHistory !== undefined &&
                respHistoryFragment !== undefined &&
                sendingOps.length < maxOps) {
                const start = new Set(respInfo.request.currentState);
                const sending = new Set();
                for (const opHash of sendingOps) {
                    const opHistory = respHistoryFragment.getOpHeaderForOp(opHash);
                    if (opHistory !== undefined) {
                        sending.add(opHistory.headerHash);
                    }
                }
                const ignore = (opHistoryHash) => sending.has(opHistoryHash);
                const extraOpsToSend = respHistoryFragment.causalClosure(start, maxOps - sendingOps.length, ignore);
                for (const opHistoryHash of extraOpsToSend) {
                    const opHistory = respHistoryFragment.contents.get(opHistoryHash);
                    if (!packer.allowedOmissions.has(opHistory.opHash)) {
                        full = !await packer.addObject(opHistory.opHash);
                        if (full) {
                            break;
                        }
                        else {
                            sendingOps.push(opHistory.opHash);
                        }
                    }
                    else {
                        this.opXferLog.debug('Omitting one inferred op due tu allowed omission: ' + opHistory.opHash);
                    }
                }
            }
            // All set: send response
            if (packer.content.length > 0) {
                resp.sendingOps = sendingOps;
                resp.literalCount = packer.content.length;
                respInfo.literalsToSend = packer.content;
                respInfo.nextLiteralIdx = 0;
                if (packer.omissions.size > 0) {
                    //console.log('omitting ' + packer.omissions.size + ' references');
                    resp.omittedObjs = [];
                    resp.omittedObjsReferenceChains = [];
                    resp.omittedObjsOwnershipProofs = [];
                    for (const [hash, refChain] of packer.omissions.entries()) {
                        resp.omittedObjs.push(hash);
                        resp.omittedObjsReferenceChains.push(refChain);
                        const dep = await this.syncAgent.store.load(hash);
                        resp.omittedObjsOwnershipProofs.push(dep.hash(req.omissionProofsSecret));
                    }
                }
            }
            respInfo.response = resp;
            return true;
        }
        sendLiterals(requestId, maxLiterals) {
            const respInfo = this.responses.get(requestId);
            let sent = 0;
            if (respInfo !== undefined) {
                if (respInfo.literalsToSend !== undefined) {
                    for (let i = 0; i < maxLiterals; i++) {
                        if (this.responses.get(requestId) === undefined) {
                            // this response is done
                            // (there could be overlap in the firing of 'sendStreamingResponses')
                            break;
                        }
                        const nextIdx = respInfo.nextLiteralIdx;
                        if (nextIdx < respInfo.literalsToSend.length) {
                            try {
                                if (!this.sendLiteral(respInfo, nextIdx, respInfo.literalsToSend[nextIdx])) {
                                    break;
                                }
                            }
                            catch (e) {
                                break;
                            }
                            respInfo.nextLiteralIdx = nextIdx + 1;
                            sent = sent + 1;
                        }
                        else {
                            break;
                        }
                    }
                    if (this.isResponseComplete(respInfo)) {
                        this.removeResponse(respInfo);
                    }
                }
            }
            //TODO: check if timer for sending should be enabled?
            return sent;
        }
        sendLiteral(respInfo, sequence, literal) {
            const msg = {
                requestId: respInfo.request.requestId,
                type: exports.MessageType.SendLiteral,
                sequence: sequence,
                literal: literal
            };
            return this.syncAgent.sendMessageToPeer(respInfo.remote, this.syncAgent.getAgentId(), msg);
        }
        rejectRequest(respInfo, reason, detail) {
            HeaderBasedSyncAgent.controlLog.warning(detail);
            this.removeResponse(respInfo);
            const msg = {
                type: exports.MessageType.RejectRequest,
                requestId: respInfo.request.requestId,
                reason: reason,
                detail: detail
            };
            this.syncAgent.sendMessageToPeer(respInfo.remote, this.syncAgent.getAgentId(), msg);
        }
        async sendResponse(respInfo) {
            var _a;
            const reqId = respInfo.request.requestId;
            this.controlLog.debug('\nSending response for ' + reqId);
            this.currentResponses.set(respInfo.remote, reqId);
            this.dequeueResponse(respInfo);
            if (await this.createResponse(respInfo)) {
                this.syncAgent.sendMessageToPeer(respInfo.remote, this.syncAgent.getAgentId(), respInfo.response);
                if (((_a = respInfo.response) === null || _a === void 0 ? void 0 : _a.literalCount) > 0) {
                    this.startStreamingResponse(respInfo);
                }
                if (this.isResponseComplete(respInfo)) {
                    this.removeResponse(respInfo);
                }
            }
            else {
                this.removeResponse(respInfo);
            }
        }
        attemptQueuedResponse(remote) {
            const queued = this.queuedResponses.get(remote);
            if (queued !== undefined && queued.length > 0) {
                const reqId = queued.shift();
                this.controlLog.debug('\nFound queued request ' + reqId);
                const respInfo = this.responses.get(reqId);
                this.sendResponse(respInfo);
                return true;
            }
            else {
                return false;
            }
        }
        enqueueResponse(respInfo) {
            const reqId = respInfo.request.requestId;
            this.controlLog.debug('\nEnqueuing response for ' + reqId + ' currently processing ' + this.currentResponses.get(respInfo.remote));
            let queued = this.queuedResponses.get(respInfo.remote);
            if (queued === undefined) {
                queued = [];
                this.queuedResponses.set(respInfo.remote, queued);
            }
            queued.push(reqId);
        }
        dequeueResponse(respInfo) {
            const reqId = respInfo.request.requestId;
            const queued = this.queuedResponses.get(respInfo.remote);
            const idx = queued === null || queued === void 0 ? void 0 : queued.indexOf(reqId);
            if (idx !== undefined && idx >= 0) {
                queued === null || queued === void 0 ? void 0 : queued.splice(idx);
            }
        }
        removeResponse(respInfo) {
            const requestId = respInfo.request.requestId;
            if (this.responses.get(requestId) !== undefined) {
                this.controlLog.debug('Removing sent request ' + requestId);
                this.controlLog.debug('Queue after for ' + respInfo.remote + ': ' + this.queuedResponses.get(respInfo.remote));
                // remove from current & queue
                if (this.currentResponses.get(respInfo.remote) === requestId) {
                    this.currentResponses.delete(respInfo.remote);
                }
                this.dequeueResponse(respInfo);
                // remove request info
                this.responses.delete(respInfo.request.requestId);
                if (this.isStreamingResponse(respInfo)) {
                    this.streamingResponses = this.streamingResponses - 1;
                    if (this.streamingResponses === 0 && this.streamingResponsesInterval !== undefined) {
                        clearInterval(this.streamingResponsesInterval);
                        this.streamingResponsesInterval = undefined;
                    }
                }
                const queued = this.attemptQueuedResponse(respInfo.remote);
                this.controlLog.debug('Found following request after ' + requestId + ': ' + queued);
            }
        }
        isResponseComplete(respInfo) {
            const done = (respInfo === null || respInfo === void 0 ? void 0 : respInfo.response) !== undefined &&
                (!this.isStreamingResponse(respInfo) ||
                    this.isStreamingCompleted(respInfo));
            return done;
        }
        isStreamingResponse(respInfo) {
            return respInfo.literalsToSend !== undefined;
        }
        isStreamingCompleted(respInfo) {
            return respInfo.literalsToSend !== undefined &&
                respInfo.nextLiteralIdx === respInfo.literalsToSend.length;
        }
        startStreamingResponse(respInfo) {
            this.streamingResponses = this.streamingResponses + 1;
            if (this.streamingResponsesInterval === undefined) {
                this.streamingResponsesInterval = setInterval(this.continueStreamingResponses, 100);
            }
            this.sendLiterals(respInfo.request.requestId, LiteralBatchSize);
        }
        async logStoreContents(requestId) {
            if (this.storeLog.level <= LogLevel.DEBUG) {
                this.storeLog.debug('\nStored state before response to request ' + requestId + '\n' + await this.syncAgent.lastStoredOpsDescription());
            }
        }
    }
    HistoryProvider.controlLog = new Logger(HistoryProvider.name, LogLevel.INFO);
    HistoryProvider.storeLog = new Logger(HistoryProvider.name, LogLevel.INFO);
    HistoryProvider.opXferLog = new Logger(HistoryProvider.name, LogLevel.INFO);

    const MaxRequestsPerRemote = 2;
    const MaxPendingOps = 1024;
    const MinRequestedOps = 128;
    const RequestTimeout = 32;
    const LiteralArrivalTimeout = 16;
    const MaxSavedCancelledRequests = 64;
    const MaxLiteralsPerRequest = 512;
    const MaxHistoryPerRequest = 1024;
    class HistorySynchronizer {
        constructor(syncAgent) {
            var _a;
            this.terminated = false;
            this.syncAgent = syncAgent;
            this.localStateFragment = new HistoryFragment(this.syncAgent.mutableObjHash);
            this.remoteStateFragments = new Map();
            this.discoveredHistory = new HistoryFragment(this.syncAgent.mutableObjHash);
            this.requestedOps = new HistoryFragment(this.syncAgent.mutableObjHash);
            this.requests = new Map();
            this.requestsForOpHistory = new MultiMap();
            this.requestsForOp = new MultiMap();
            this.activeRequests = new MultiMap();
            this.requestsBlockedByOpHeader = new MultiMap();
            this.newRequestsLock = new Lock();
            this.needToRetryNewRequests = false;
            this.checkRequestTimeouts = this.checkRequestTimeouts.bind(this);
            this.lastCancelledRequests = [];
            this.logPrefix = 'On peer ' + ((_a = this.syncAgent.peerGroupAgent.localPeer.identity) === null || _a === void 0 ? void 0 : _a.hash()) + ':';
            this.controlLog = HistorySynchronizer.controlLog;
            this.sourcesLog = HistorySynchronizer.sourcesLog;
            this.stateLog = HistorySynchronizer.stateLog;
            this.opXferLog = HistorySynchronizer.opXferLog;
            this.storeLog = HistorySynchronizer.storeLog;
            this.requestLog = HistorySynchronizer.requestLog;
            this.responseLog = HistorySynchronizer.responseLog;
        }
        async onNewHistory(remote, receivedOpHistories) {
            this.controlLog.debug('\n' + this.logPrefix + '\nReceived new state from ' + remote);
            for (const opHistory of receivedOpHistories) {
                if (await this.opHistoryIsMissingFromStore(opHistory.headerHash)) {
                    if (!this.discoveredHistory.contents.has(opHistory.headerHash)) {
                        this.discoveredHistory.add(opHistory);
                    }
                    this.addOpToRemoteState(remote, opHistory);
                }
            }
            this.attemptNewRequests();
        }
        checkRequestTimeouts() {
            let cancelledSome = false;
            for (const reqInfo of this.requests.values()) {
                const cancelled = this.checkRequestRemoval(reqInfo);
                if (cancelled) {
                    HistorySynchronizer.controlLog.debug('Cancelled request ' + reqInfo.request.requestId + ' in timeout loop');
                }
                cancelledSome = cancelledSome || cancelled;
            }
            if (cancelledSome) {
                this.attemptNewRequests();
            }
        }
        async attemptNewRequests() {
            if (this.newRequestsLock.acquire()) {
                this.needToRetryNewRequests = true;
                while (this.needToRetryNewRequests) {
                    try {
                        this.needToRetryNewRequests = false;
                        await this.attemptNewRequestsSerially();
                    }
                    catch (e) {
                        this.controlLog.error('\n' + this.logPrefix + '\nError while attempting new requests: ', e);
                    }
                }
                this.newRequestsLock.release();
            }
            else {
                this.controlLog.trace('\n' + this.logPrefix + '\nNot attempting new request: could not acquire lock');
                this.needToRetryNewRequests = true;
            }
        }
        async attemptNewRequestsSerially() {
            this.controlLog.debug('\n' + this.logPrefix + '\nAttempting new request...');
            if (this.discoveredHistory.contents.size === 0) {
                this.controlLog.debug('\n' + this.logPrefix + '\nThere is nothing to request.');
                return;
            }
            if (this.requestedOps.contents.size > MinRequestedOps) {
                this.controlLog.debug('\n' + this.logPrefix + '\nDelaying request, too many pending ops.');
                return;
            }
            if (this.stateLog.level <= LogLevel.DEBUG) {
                let debugInfo = '\n' + this.logPrefix + '\nState info before attempt:\n';
                const discHist = Array.from(this.discoveredHistory.contents.keys());
                const pendingHist = Array.from(this.requestsForOpHistory.keys());
                const pendingOps = Array.from(this.requestsForOp.keys());
                debugInfo = debugInfo + '\nDiscovered op histories:   [' + discHist.slice(0, 8) + (discHist.length > 8 ? ' ...' : '') + '] (count: ' + discHist.length + ')';
                debugInfo = debugInfo + '\nMissing prev op histories: [' + Array.from(this.discoveredHistory.missingPrevOpHeaders) + ']';
                debugInfo = debugInfo + '\nPending op histories:      [' + pendingHist.slice(0, 8) + (pendingHist.length > 8 ? ' ...' : '') + '] (count: ' + pendingHist.length + ')';
                debugInfo = debugInfo + '\nPending ops:               [' + pendingOps.slice(0, 8) + (pendingOps.length > 8 ? ' ...' : '') + '] (count: ' + pendingOps.length + ')';
                debugInfo = debugInfo + '\nLocal state:               [' + Array.from(this.localStateFragment.contents.keys()) + ']';
                debugInfo = debugInfo + '\nRequests:                  [' + Array.from(this.requests.keys()).map((k) => { var _a; return k + '(' + ((_a = this.requests.get(k)) === null || _a === void 0 ? void 0 : _a.status) + ')'; }) + ']';
                if (this.stateLog.level <= LogLevel.TRACE) {
                    debugInfo = debugInfo + '\n\nDiscovered states by remote:';
                    for (const [remote, history] of this.remoteStateFragments.entries()) {
                        debugInfo = debugInfo + '\n' + remote + ': [' + Array.from(history.contents.keys()) + ']';
                    }
                }
                this.stateLog.debug(debugInfo);
            }
            // Compute remote histories
            const remoteHistories = this.computeRemoteHistories();
            // Collect all op histories that need to be fetched, and which remotes have them
            const missingOpHistorySources = new MultiMap();
            const missingOpHistories = new Set();
            // By capturing unknown op headers at the edge of the discovered history fragment
            const opHistoryFromPrevOps = Array.from(this.discoveredHistory.missingPrevOpHeaders);
            for (const hash of opHistoryFromPrevOps) {
                const isUnrequested = this.opHistoryIsUnrequested(hash);
                const isMissingFromStore = isUnrequested && await this.opHistoryIsMissingFromStore(hash);
                // (*) the above is short circuited like that only for performance: if it is not unrequested
                // it doesn't matter wheter it is in the store or not, we will not ask for it again.
                if (isUnrequested && isMissingFromStore) {
                    const sources = new Array();
                    for (const ep of this.syncAgent.remoteStates.keys()) {
                        const history = remoteHistories.get(ep);
                        if (history !== undefined) {
                            if (history.missingPrevOpHeaders.has(hash)) {
                                if (this.canSendNewRequestTo(ep)) {
                                    missingOpHistories.add(hash); // this way we only add it if there is at least one source
                                    missingOpHistorySources.add(ep, hash);
                                    sources.push(ep);
                                }
                                else {
                                    this.controlLog.trace('\n' + this.logPrefix + '\nDiscarding endpoint ' + ep + ' as source of op history ' + hash + ': no slot available for sending request.');
                                }
                            }
                        }
                    }
                    this.sourcesLog.trace('\n' + this.logPrefix + '\nSources for missing prev op history ' + hash + ': ', sources);
                }
                else {
                    if (!isUnrequested) {
                        this.controlLog.trace('\n' + this.logPrefix + '\nIgnoring missing prev op history ' + hash + ': it has already been requested.');
                    }
                    else {
                        this.controlLog.trace('\n' + this.logPrefix + '\nIgnoring missing prev op history ' + hash + ': it is present in the store.');
                    }
                }
            }
            const sortedOpHistorySources = Array.from(missingOpHistorySources.entries());
            sortedOpHistorySources.sort((s1, s2) => s2[1].size - s1[1].size);
            const opHistoriesToRequest = new Array();
            this.controlLog.trace('\n' + this.logPrefix + '\nWill check ' + sortedOpHistorySources.length + ' remote sources');
            const considered = new Set();
            for (const [ep, opHistories] of sortedOpHistorySources) {
                this.controlLog.trace('\n' + this.logPrefix + '\nConsidering remote ' + ep + ' with ' + opHistories.size + ' possible op histories...');
                const toRequest = new Set();
                for (const opHistory of opHistories) {
                    if (missingOpHistories.has(opHistory)) {
                        toRequest.add(opHistory);
                        missingOpHistories.delete(opHistory);
                    }
                }
                if (toRequest.size > 0) {
                    opHistoriesToRequest.push([ep, toRequest]);
                    considered.add(ep);
                }
                if (missingOpHistories.size === 0) {
                    break;
                }
            }
            for (const remote of remoteHistories.keys()) {
                if (!considered.has(remote)) {
                    opHistoriesToRequest.push([remote, new Set()]);
                }
            }
            const startingOpHistories = this.computeStartingOpHistories();
            let didSend = false;
            for (const [remote, opHistories] of opHistoriesToRequest) {
                const remoteHistory = remoteHistories.get(remote);
                const startingOps = await this.computeStartingOps(remoteHistory);
                const ops = await this.findOpsToRequest(remoteHistory);
                const aim = {
                    opHistories: opHistories,
                    ops: ops
                };
                const current = {
                    startingOpHistories: startingOpHistories,
                    startingOps: startingOps
                };
                if (opHistories.size === 0 && ops.length === 0) {
                    this.controlLog.debug('\n' + this.logPrefix + '\nFound no history or ops to request for remote ' + remote);
                    continue;
                }
                if (this.controlLog.level <= LogLevel.DEBUG) {
                    let debugInfo = '';
                    if (opHistories.size > 0) {
                        debugInfo = debugInfo + '\nNew request for ' + remote + '\n';
                        debugInfo = debugInfo + 'Requesting op histories: [' + Array.from(opHistories) + ']\n';
                        debugInfo = debugInfo + '          starting from: [' + Array.from(current.startingOpHistories) + ']\n';
                    }
                    if (ops.length > 0) {
                        debugInfo = debugInfo + '\n';
                        debugInfo = debugInfo + 'Requesting ops:          [' + ops + ']\n';
                    }
                    if (opHistories.size > 0 || ops.length > 0) {
                        debugInfo = debugInfo + 'Starting point for ops:  [' + Array.from(current.startingOps) + ']\n';
                    }
                    this.controlLog.debug('\n' + this.logPrefix + debugInfo);
                }
                if (this.storeLog.level <= LogLevel.DEBUG) {
                    await this.logStoreContents();
                }
                const sent = this.request(remote, aim, current);
                if (sent /* && ops.length > 0*/ && this.requestedOps.contents.size < MaxPendingOps) {
                    didSend = true;
                    // try to saturate the link: if there is room, make another request
                    if (this.canSendNewRequestTo(remote)) {
                        const startingOps = await this.computeStartingOps(remoteHistory);
                        const ops = await this.findOpsToRequest(remoteHistory);
                        if (ops.length > 0) {
                            this.controlLog.debug('\n' + this.logPrefix + '\nRequesting an additional ' + ops.length + ' ops from remote ' + remote);
                            const aim = { ops: ops };
                            const current = { startingOps: startingOps };
                            this.request(remote, aim, current);
                        }
                    }
                }
            }
            if (!didSend) {
                for (const req of this.requests.values()) {
                    if (req.status === 'accepted-response-blocked') {
                        break;
                    }
                }
            }
        }
        request(remote, aim, current, mode = 'infer-req-ops') {
            var _a, _b;
            if (mode === undefined) {
                mode = this.requestedOps.contents.size < MaxPendingOps ? 'infer-req-ops' : 'as-requested';
            }
            const msg = {
                type: exports.MessageType.Request,
                requestId: new BrowserRNG().randomHexString(128),
                mutableObj: this.syncAgent.mutableObjHash,
                mode: mode,
                maxLiterals: MaxLiteralsPerRequest,
                maxHistory: MaxHistoryPerRequest
            };
            this.controlLog.debug('\n' + this.logPrefix + '\nRequesting ' + ((_a = aim.opHistories) === null || _a === void 0 ? void 0 : _a.size) + ' op histories and ' + ((_b = aim.ops) === null || _b === void 0 ? void 0 : _b.length) + ' ops from remote ' + remote + ' with requestId ' + msg.requestId);
            if (aim.opHistories !== undefined) {
                msg.requestedTerminalOpHistory = Array.from(aim.opHistories.values());
                let startingOpHistorySet;
                if ((current === null || current === void 0 ? void 0 : current.startingOpHistories) !== undefined) {
                    startingOpHistorySet = current === null || current === void 0 ? void 0 : current.startingOpHistories;
                }
                else {
                    startingOpHistorySet = this.computeStartingOpHistories();
                }
                msg.requestedStartingOpHistory = Array.from(startingOpHistorySet);
            }
            if (aim.ops !== undefined) {
                msg.requestedOps = Array.from(aim.ops);
                if ((current === null || current === void 0 ? void 0 : current.startingOps) !== undefined) {
                    msg.currentState = Array.from(current === null || current === void 0 ? void 0 : current.startingOps);
                }
                else {
                    msg.currentState = Array.from(this.localStateFragment.contents.keys()); //this.computeStartingOps(remote);
                }
            }
            const reqInfo = {
                request: msg,
                remote: remote,
                status: 'created',
                nextOpSequence: 0,
                nextLiteralSequence: 0,
                receivedLiteralsCount: 0,
                outOfOrderLiterals: new Map(),
                requestSendingTimestamp: Date.now()
            };
            let sent = this.sendRequest(reqInfo);
            if (sent) {
                this.checkRequestTimeoutsTimer();
            }
            else {
                this.cleanupRequest(reqInfo);
            }
            return sent;
        }
        checkRequestTimeoutsTimer() {
            if (this.requests.size > 0) {
                if (this.checkRequestTimeoutsInterval === undefined) {
                    this.checkRequestTimeoutsInterval = setInterval(this.checkRequestTimeouts, 5000);
                }
            }
            else {
                if (this.checkRequestTimeoutsInterval !== undefined) {
                    clearInterval(this.checkRequestTimeoutsInterval);
                    this.checkRequestTimeoutsInterval = undefined;
                }
            }
        }
        // Do some intelligence over which ops can be requested from an endpoint
        async findOpsToRequest(remoteHistory) {
            let max = MaxPendingOps - this.requestedOps.contents.size;
            if (max > ProviderLimits.MaxOpsToRequest) {
                max = ProviderLimits.MaxOpsToRequest;
            }
            this.controlLog.debug('pending ops: ' + this.requestedOps.contents.size + ' can request ' + max + ' more');
            if (max > 0 && remoteHistory !== undefined) {
                const startingOps = new Set();
                for (const missingStartingOp of remoteHistory.missingPrevOpHeaders) {
                    if (this.requestsForOp.hasKey(missingStartingOp) ||
                        !(await this.opHistoryIsMissingFromStore(missingStartingOp))) {
                        startingOps.add(missingStartingOp);
                    }
                }
                const opHeaders = remoteHistory.causalClosure(startingOps, max, undefined, (h) => !this.requestsForOp.hasKey(remoteHistory.contents.get(h).opHash));
                const ops = opHeaders.map((opHeaderHash) => remoteHistory.contents.get(opHeaderHash).opHash);
                const allRemoteOps = Array.from(remoteHistory.contents.keys());
                this.controlLog.debug('starting ops: ' + Array.from(startingOps));
                this.controlLog.debug('all remote ops: ' + allRemoteOps.slice(0, 8) + (allRemoteOps.length > 8 ? ' ...' : '') + ' (count: ' + allRemoteOps.length + ')');
                this.controlLog.debug('to request: ' + opHeaders.slice(0, 8) + (opHeaders.length > 8 ? ' ...' : '') + ' (count: ' + opHeaders.length + ')');
                return ops;
            }
            else {
                return [];
            }
        }
        /*
        private findOpsToRequest(remote: Endpoint, startingOps: Set<Hash>) {

            const remoteHistory = this.remoteHistories.get(remote);

            let max = MaxPendingOps - this.requestedOps.contents.size;
            if (max > ProviderLimits.MaxOpsToRequest) {
                max = ProviderLimits.MaxOpsToRequest;
            }
            if (max > 0 && remoteHistory !== undefined) {

                console.log('starting ops for findOpsToRequest from ' + remote + ' with max=' + max);
                console.log(Array.from(startingOps))

                const ops = remoteHistory.causalClosure(startingOps, max, undefined, (h: Hash) => !this.requestsForOp.hasKey((remoteHistory.contents.get(h) as OpCausalHistory).opHash))
                                    .map( (opHistoryHash: Hash) =>
                        (remoteHistory.contents.get(opHistoryHash) as OpCausalHistory).opHash );

                console.log('found ops to request from ' + remote);
                console.log(ops);

                return ops;
            } else {
                return [];
            }
        }
        */
        // Handle local state changes: remove arriving ops from discoveredHistory, remoteHistories,
        // requestedOps, requestsForOp, requestsForOpHistory, and endpointsForUnknownHistory.
        // Also check if there are any erroneos histories lingering for this op, remove them
        // and mark the peers as not trustworthy (TODO). 
        async onNewLocalOp(op) {
            const prevOpCausalHistories = new Map();
            for (const prevOpRef of op.getPrevOps()) {
                const prevOpHistory = await this.syncAgent.store.loadOpHeader(prevOpRef.hash);
                prevOpCausalHistories.set(prevOpRef.hash, prevOpHistory);
            }
            const opHistories = this.discoveredHistory.getAllOpHeadersForOp(op.getLastHash());
            for (const opHistory of opHistories) {
                if (!opHistory.verifyOpMatch(op, prevOpCausalHistories)) {
                    this.processBadOpHistory(opHistory);
                }
                else {
                    this.markOpAsFetched(opHistory);
                }
            }
            const opHistory = op.getHeader(prevOpCausalHistories);
            this.addOpToCurrentState(opHistory);
            if (this.stateLog.level <= LogLevel.TRACE) {
                let debugInfo = this.logPrefix;
                debugInfo = debugInfo + '\nNew local op ' + op.hash() + ' causal: ' + opHistory.headerHash + ' -> [' + Array.from(opHistory.prevOpHeaders) + ']';
                debugInfo = debugInfo + '\nCurrent state now is: [' + Array.from(this.localStateFragment.contents.keys()) + ']';
                this.stateLog.trace(debugInfo);
            }
        }
        addOpToCurrentState(opHistory) {
            this.localStateFragment.add(opHistory);
            this.localStateFragment.removeNonTerminalOps();
        }
        addOpToRemoteState(remote, opHistory) {
            let remoteState = this.remoteStateFragments.get(remote);
            if (remoteState === undefined) {
                remoteState = new HistoryFragment(this.syncAgent.mutableObjHash);
                this.remoteStateFragments.set(remote, remoteState);
            }
            remoteState.add(opHistory);
            remoteState.removeNonTerminalOps();
        }
        computeRemoteHistories() {
            const remoteHistories = new Map();
            for (const [remote, state] of this.remoteStateFragments.entries()) {
                const history = this.discoveredHistory.filterByTerminalOpHeaders(new Set(state.contents.keys()));
                remoteHistories.set(remote, history);
            }
            return remoteHistories;
        }
        async onReceivingResponse(remote, msg) {
            var _a, _b, _c;
            const req = this.requests.get(msg.requestId);
            if (req === undefined) {
                //TODO make this a debug message instead of a warning
                if (this.lastCancelledRequests.indexOf(msg.requestId) < 0) {
                    this.controlLog.warning('\n' + this.logPrefix + '\nIgnoring response for unknown request ' + msg.requestId);
                }
                return;
            }
            if ((req === null || req === void 0 ? void 0 : req.status) !== 'sent') {
                this.controlLog.warning('\n' + this.logPrefix + '\nIgnoring response for request ' + msg.requestId + ": status is not 'sent', but " + ((_a = this.requests.get(msg.requestId)) === null || _a === void 0 ? void 0 : _a.status));
                return;
            }
            if (this.controlLog.level <= LogLevel.DEBUG) {
                let debugInfo = '';
                debugInfo = debugInfo + 'Received response for request ' + msg.requestId + ' from ' + remote + ' with ' + ((_b = msg.history) === null || _b === void 0 ? void 0 : _b.length) + ' op histories, ' + ((_c = msg.sendingOps) === null || _c === void 0 ? void 0 : _c.length) + ' ops and expecting ' + msg.literalCount + ' literals.\n';
                if (msg.history !== undefined) {
                    const histories = msg.history.map((opHistory) => opHistory.headerHash);
                    debugInfo = debugInfo + 'Histories: [' + histories.slice(0, 8) + (histories.length > 8 ? ' ...' : '') + '] (count: ' + histories.length + ')\n';
                }
                if (msg.sendingOps !== undefined) {
                    debugInfo = debugInfo + '      Ops: [' + msg.sendingOps.slice(0, 8) + (msg.sendingOps.length > 8 ? ' ...' : '') + '] (count: ' + msg.sendingOps.length + ')\n';
                }
                this.responseLog.debug('\n' + this.logPrefix + '\n' + debugInfo);
            }
            if (await this.validateResponse(remote, msg)) {
                const reqInfo = this.requests.get(msg.requestId);
                if (reqInfo !== undefined) {
                    const req = reqInfo.request;
                    reqInfo.status = 'accepted-response-blocked';
                    reqInfo.missingCurrentState = new Set(req.currentState);
                    if (req.currentState !== undefined) {
                        for (const opHistory of req.currentState.values()) {
                            if (await this.opHistoryIsMissingFromStore(opHistory)) {
                                this.requestsBlockedByOpHeader.add(opHistory, req.requestId);
                                this.controlLog.debug('\n' + this.logPrefix + '\nRequest ' + req.requestId + ' is blocked by missing op w/history ' + opHistory);
                            }
                            else {
                                reqInfo.missingCurrentState.delete(opHistory);
                            }
                        }
                    }
                    await this.attemptToProcessResponse(reqInfo);
                    this.requestLog.debug('Received resp for ' + req.requestId);
                }
                else {
                    this.requestLog.debug('Ignoring resp for ' + msg.requestId + ': it is valid, but it vanished during validation.');
                }
            }
            else {
                this.requestLog.debug('Received INVALID resp for ' + msg.requestId);
            }
        }
        async onReceivingLiteral(remote, msg) {
            const reqInfo = this.requests.get(msg.requestId);
            if (reqInfo === undefined || reqInfo.remote !== remote) {
                if (reqInfo === undefined) {
                    if (this.lastCancelledRequests.indexOf(msg.requestId) < 0) {
                        this.opXferLog.warning('\n' + this.logPrefix + '\nReceived literal for unknown request ' + msg.requestId);
                    }
                    else {
                        this.opXferLog.debug('\n' + this.logPrefix + '\nReceived literal for cancelled request ' + msg.requestId);
                    }
                }
                else if (reqInfo.remote !== remote) {
                    this.opXferLog.warning('\n' + this.logPrefix + '\nReceived literal claiming to come from ' + reqInfo.remote + ', but it actually came from ' + msg.requestId);
                }
                return;
            }
            let enqueue = false;
            let process = false;
            if (reqInfo.request.maxLiterals === undefined || reqInfo.receivedLiteralsCount < reqInfo.request.maxLiterals) {
                if (reqInfo.status !== 'accepted-response') {
                    // if we are expecting ops
                    if ((reqInfo.request.requestedOps !== undefined &&
                        reqInfo.request.requestedOps.length > 0) ||
                        (reqInfo.request.mode === 'infer-req-ops' &&
                            reqInfo.request.requestedTerminalOpHistory !== undefined &&
                            reqInfo.request.requestedTerminalOpHistory.length > 0)) {
                        this.opXferLog.trace('\n' + this.logPrefix + '\nWill enqueue literal number ' + msg.sequence + ' for request ' + reqInfo.request.requestId + ' (status is ' + reqInfo.status + ')');
                        enqueue = true;
                    }
                }
                else { // reqInfo.status === 'accepted-response'
                    this.opXferLog.trace('\n' + this.logPrefix + '\nWill process literal number ' + msg.sequence + ' for request ' + reqInfo.request.requestId);
                    enqueue = true;
                    process = true;
                }
                if (enqueue) {
                    reqInfo.lastLiteralTimestamp = Date.now();
                    reqInfo.receivedLiteralsCount = reqInfo.receivedLiteralsCount + 1;
                    if (reqInfo.request.maxLiterals === undefined || reqInfo.outOfOrderLiterals.size < reqInfo.request.maxLiterals) {
                        reqInfo.outOfOrderLiterals.set(msg.sequence, msg.literal);
                    }
                }
                if (process) {
                    await this.attemptToProcessLiterals(reqInfo);
                }
                if (!enqueue && !process) {
                    this.opXferLog.warning('\n' + this.logPrefix + '\nWill ignore literal number ' + msg.sequence + ' for request ' + reqInfo.request.requestId);
                }
            }
            else {
                this.opXferLog.warning('\n' + this.logPrefix + '\nIgnored received literal for request ' + reqInfo.request.requestId + ', all literals were already received.');
            }
        }
        // We're not rejecting anything for now, will implement when the retry logic is done.
        onReceivingRequestRejection(remote, msg) {
        }
        async attemptToProcessResponse(reqInfo) {
            var _a, _b, _c;
            if (this.requests.get(reqInfo.request.requestId) === undefined) {
                this.controlLog.debug('\n' + this.logPrefix + '\nIgnoring response to ' + reqInfo.request.requestId + ', the request is no longer there.');
                return; // already processed
            }
            if (reqInfo.status !== 'accepted-response-blocked' ||
                reqInfo.missingCurrentState.size > 0) {
                this.controlLog.debug('\n' + this.logPrefix + '\nIgnoring response to ' + reqInfo.request.requestId + ', the request is blocked by missing prevOps.');
                return;
            }
            reqInfo.status = 'accepted-response-processing';
            if (await this.validateOmissionProofs(reqInfo)) {
                const req = reqInfo.request;
                const resp = reqInfo.response;
                reqInfo.responseArrivalTimestamp = Date.now();
                // Update the expected op history arrivals
                if (req.requestedTerminalOpHistory !== undefined) {
                    for (const opHistoryHash of req.requestedTerminalOpHistory) {
                        this.requestsForOpHistory.delete(opHistoryHash, req.requestId);
                    }
                }
                // Only add history for ops we have not yet received.
                // Do it backwards, so if new ops are added while this loop is running, we will never
                // add an op but omit one of its predecessors because it was stored in-between.
                if (reqInfo.receivedHistory !== undefined && reqInfo.receivedHistory.contents.size > 0) {
                    let addedOpHeaders = 0;
                    let duplicatedOpHeaders = 0;
                    const rcvdHistory = reqInfo.receivedHistory;
                    for (const opHistory of rcvdHistory.iterateFrom(rcvdHistory.terminalOpHeaders, 'backward', 'bfs')) {
                        this.requestsForOpHistory.delete(opHistory.headerHash, req.requestId);
                        if (await this.opHistoryIsMissingFromStore(opHistory.headerHash) && this.opHistoryIsUndiscovered(opHistory.headerHash)) {
                            addedOpHeaders = addedOpHeaders + 1;
                            this.discoveredHistory.add(opHistory);
                        }
                        else {
                            duplicatedOpHeaders = duplicatedOpHeaders + 1;
                        }
                    }
                    this.responseLog.debug('Imported ' + addedOpHeaders + ' new and ignored ' + duplicatedOpHeaders + ' duplicated op headers for request ' + req.requestId);
                }
                // Update expected op arrivals: delete what we asked and use what the server actually is sending instead
                if (req.requestedOps !== undefined) {
                    for (const opHash of req.requestedOps) {
                        this.requestsForOp.delete(opHash, req.requestId);
                        if (this.requestsForOp.get(opHash).size === 0) {
                            for (const opHistory of this.discoveredHistory.getAllOpHeadersForOp(opHash)) {
                                this.requestedOps.remove(opHistory.headerHash);
                            }
                        }
                    }
                }
                if (resp.sendingOps !== undefined) {
                    for (const opHash of resp.sendingOps) {
                        this.requestsForOp.add(opHash, req.requestId);
                        for (const opHistory of this.discoveredHistory.getAllOpHeadersForOp(opHash)) {
                            this.requestedOps.add(opHistory);
                        }
                    }
                }
                // Finally, if we are expecting ops after this response, validate and pre-load any omitted
                // dependencies.
                if (resp.sendingOps !== undefined && resp.sendingOps.length > 0) {
                    reqInfo.receivedObjects = new Context();
                    reqInfo.receivedObjects.resources = this.syncAgent.resources;
                    if (this.syncAgent.mutableObj !== undefined) {
                        reqInfo.receivedObjects.objects.set(this.syncAgent.mutableObjHash, this.syncAgent.mutableObj);
                    }
                }
                if (resp.omittedObjsOwnershipProofs !== undefined &&
                    resp.omittedObjs !== undefined &&
                    resp.omittedObjs.length === resp.omittedObjsOwnershipProofs.length &&
                    reqInfo.receivedObjects !== undefined) {
                    this.opXferLog.trace('\n' + this.logPrefix + '\nHave to load ' + resp.omittedObjs.length + ' omitted deps for ' + req.requestId);
                    for (const idx of resp.omittedObjs.keys()) {
                        const hash = resp.omittedObjs[idx];
                        const omissionProof = resp.omittedObjsOwnershipProofs[idx];
                        const dep = await this.syncAgent.store.load(hash);
                        if (dep !== undefined && dep.hash(reqInfo.request.omissionProofsSecret) === omissionProof) {
                            if (((_b = (_a = reqInfo.receivedObjects) === null || _a === void 0 ? void 0 : _a.objects) === null || _b === void 0 ? void 0 : _b.get(dep.hash())) === undefined) {
                                (_c = reqInfo.receivedObjects) === null || _c === void 0 ? void 0 : _c.objects.set(dep.hash(), dep);
                            }
                        }
                    }
                    this.opXferLog.trace('\n' + this.logPrefix + '\nDone loading ' + resp.omittedObjs.length + ' omitted deps for ' + req.requestId);
                }
                reqInfo.status = 'accepted-response';
                await this.attemptToProcessLiterals(reqInfo);
                const removed = this.checkRequestRemoval(reqInfo);
                if (removed) {
                    this.attemptNewRequests();
                }
            }
        }
        async attemptToProcessLiterals(reqInfo) {
            if (reqInfo.nextLiteralPromise !== undefined) {
                this.opXferLog.trace('\n' + this.logPrefix + '\nSkipping attemptToProcessLiterals call for ' + reqInfo.request.requestId + ', there is a literal being processed already.');
                return;
            }
            this.opXferLog.trace('\n' + this.logPrefix + '\nCalled attemptToProcessLiterals for ' + reqInfo.request.requestId + ': ' + reqInfo.outOfOrderLiterals.size + ' literals to process');
            while (reqInfo.outOfOrderLiterals.size > 0 && reqInfo.receivedObjects !== undefined) {
                // Check if the request has not been cancelled
                if (this.requests.get(reqInfo.request.requestId) === undefined) {
                    break;
                }
                const literal = reqInfo.outOfOrderLiterals.get(reqInfo.nextLiteralSequence);
                if (literal === undefined) {
                    break;
                }
                else {
                    reqInfo.outOfOrderLiterals.delete(reqInfo.nextLiteralSequence);
                    reqInfo.nextLiteralPromise = this.processLiteral(reqInfo, literal);
                    const done = !await reqInfo.nextLiteralPromise;
                    if (done) {
                        break;
                    }
                }
            }
            reqInfo.nextLiteralPromise = undefined;
        }
        async processLiteral(reqInfo, literal) {
            var _a, _b;
            // FIXME: but what about custom hashes?
            if (!LiteralUtils.validateHash(literal)) {
                const detail = 'Wrong hash found when receiving literal ' + literal.hash + ' in response to request ' + reqInfo.request.requestId;
                this.cancelRequest(reqInfo, 'invalid-literal', detail);
                return false;
            }
            (_a = reqInfo.receivedObjects) === null || _a === void 0 ? void 0 : _a.literals.set(literal.hash, literal);
            reqInfo.nextLiteralSequence = reqInfo.nextLiteralSequence + 1;
            if (((_b = reqInfo.response) === null || _b === void 0 ? void 0 : _b.sendingOps)[reqInfo.nextOpSequence] === literal.hash) {
                if (this.syncAgent.literalIsValidOp(literal)) {
                    try {
                        // throws if validation fails
                        await HashedObject.fromContextWithValidation(reqInfo.receivedObjects, literal.hash);
                        reqInfo.nextOpSequence = reqInfo.nextOpSequence + 1;
                        await this.syncAgent.store.saveWithContext(literal.hash, reqInfo.receivedObjects);
                        // FIXME: there's no validation of the op matching the actual causal history op
                        // TODO:  validate, remove op and all history following if op does not match
                        this.opXferLog.debug('\n' + this.logPrefix + '\nReceived op ' + literal.hash + ' from request ' + reqInfo.request.requestId + '(was requested: ' + (reqInfo.request.requestedOps !== undefined && reqInfo.request.requestedOps.indexOf(literal.hash) >= 0) + ') ');
                        const removed = this.checkRequestRemoval(reqInfo);
                        if (removed) {
                            this.attemptNewRequests();
                        }
                    }
                    catch (e) {
                        const detail = 'Error while deliteralizing op ' + literal.hash + ' in response to request ' + reqInfo.request.requestId + '(op sequence: ' + reqInfo.nextOpSequence + ')';
                        this.cancelRequest(reqInfo, 'invalid-literal', '\n' + this.logPrefix + '\n' + detail);
                        this.opXferLog.warning(e);
                        this.opXferLog.warning(e.stack);
                        this.opXferLog.warning('\n' + this.logPrefix + '\nnextLiteralSequence=' + reqInfo.nextLiteralSequence);
                        this.opXferLog.warning('\n' + this.logPrefix + '\nreceivedLiteralsCount=' + reqInfo.receivedLiteralsCount);
                        return false;
                    }
                }
                else {
                    const detail = '\n' + this.logPrefix + '\nReceived op ' + literal.hash + ' is not valid for mutableObj ' + this.syncAgent.mutableObjHash + ', in response to request ' + reqInfo.request.requestId + '(op sequence: ' + reqInfo.nextOpSequence + ')';
                    this.cancelRequest(reqInfo, 'invalid-literal', detail);
                    return false;
                }
            }
            return true;
        }
        markOpAsFetched(opHeader) {
            var _a;
            this.opXferLog.debug('\n' + this.logPrefix + '\nMarking op ' + opHeader.opHash + ' as fetched (op history is ' + opHeader.headerHash + ').');
            const opHeaderHash = opHeader.headerHash;
            const opHash = opHeader.opHash;
            for (const state of this.remoteStateFragments.values()) {
                state.remove(opHeaderHash);
            }
            this.requestedOps.remove(opHeaderHash);
            this.requestsForOp.deleteKey(opHash);
            for (const opHistory of this.discoveredHistory.getAllOpHeadersForOp(opHash)) {
                this.requestedOps.remove(opHistory.headerHash);
            }
            this.discoveredHistory.remove(opHeaderHash);
            // in case we were trying to fetch history for this op
            this.markOpHeaderAsFetched(opHeaderHash);
            for (const requestId of this.requestsBlockedByOpHeader.get(opHeaderHash)) {
                const reqInfo = this.requests.get(requestId);
                if (reqInfo !== undefined) {
                    this.opXferLog.debug('\n' + this.logPrefix + '\nAttempting to process blocked request ' + requestId);
                    (_a = reqInfo.missingCurrentState) === null || _a === void 0 ? void 0 : _a.delete(opHeaderHash);
                    this.attemptToProcessResponse(reqInfo); // not awaiting this
                }
                else {
                    this.opXferLog.debug('\n' + this.logPrefix + '\nNot attempting to process blocked request ' + requestId + ': it is no longer there.');
                }
            }
            this.requestsBlockedByOpHeader.deleteKey(opHeaderHash);
        }
        markOpHeaderAsFetched(opHistoryHash) {
            this.requestsForOpHistory.deleteKey(opHistoryHash);
        }
        // TODO: identify peer as bad !
        processBadOpHistory(opCausalHistory) {
            this.markOpAsFetched(opCausalHistory);
        }
        computeStartingOpHistories() {
            return new Set(this.localStateFragment.contents.keys()); //this.terminalOpHistoriesPlusCurrentState(this.discoveredHistory);
        }
        async computeStartingOps(remoteHistory) {
            // find the missingPrevOpHeaders of the unrequested fragment of remoteHistory
            // TODO: take into account which ops we want to actually request, and add the
            //       ops in missingPrevOpHeaders necessary just for those
            var _a, _b;
            const unrequestedFragmentForRemote = remoteHistory.clone();
            for (const opHeader of this.requestedOps.contents.values()) {
                unrequestedFragmentForRemote.remove(opHeader.headerHash);
            }
            // TODO: make this method return an array, so we can give more priority to the
            //       ops in missingPrevOpHeaders than to the ones added next
            const start = new Set();
            for (const opHeaderHash of unrequestedFragmentForRemote.missingPrevOpHeaders) {
                if (this.requestedOps.contents.has(opHeaderHash) ||
                    (await this.syncAgent.store.loadOpHeaderByHeaderHash(opHeaderHash)) !== undefined) {
                    start.add(opHeaderHash);
                }
            }
            // To enable speculative addition of ops to the reply, we add our current state too.
            if (((_a = this.syncAgent.state) === null || _a === void 0 ? void 0 : _a.terminalOpHeaderHashes) !== undefined) {
                for (const opHeaderHash of (_b = this.syncAgent.state) === null || _b === void 0 ? void 0 : _b.terminalOpHeaderHashes.values()) {
                    start.add(opHeaderHash);
                }
            }
            //for (const opHeader of this.localStateFragment.contents.values()) {
            //    start.add(opHeader.headerHash);
            //}
            return start;
            /*
            const requestedFragmentForRemote = new HistoryFragment(remoteHistory.mutableObj);

            for (const opHeader of this.localState.contents.values()) {
                requestedFragmentForRemote.add(opHeader);
            }

            for (const opHeader of this.requestedOps.contents.values()) {
                if (remoteHistory.contents.has(opHeader.headerHash)) {
                    requestedFragmentForRemote.add(opHeader);
                }
            }

            return new Set<Hash>(requestedFragmentForRemote.terminalOpHeaders);
            */
        }
        opHistoryIsUndiscovered(opHistory) {
            return !this.discoveredHistory.contents.has(opHistory);
        }
        opHistoryIsUnrequested(opHistory) {
            return this.requestsForOpHistory.get(opHistory).size === 0;
        }
        async opHistoryIsMissingFromStore(opHistory) {
            return await this.syncAgent.store.loadOpHeaderByHeaderHash(opHistory) === undefined;
        }
        async validateResponse(remote, msg) {
            const reqInfo = this.requests.get(msg.requestId);
            // if request is known and was sent to 'remote' and unreplied as of now:
            if (reqInfo !== undefined && reqInfo.remote === remote && reqInfo.response === undefined) {
                reqInfo.status = 'validating';
                reqInfo.response = msg;
                const req = reqInfo.request;
                const resp = reqInfo.response;
                let receivedHistory = undefined;
                // Make sets out of these arrays for easy membership check:
                const requestedOpHistories = new Set(req.requestedTerminalOpHistory);
                //const informedAsFetchedOpHistories = new Set<Hash>(req.terminalFetchedOpHistories);
                const requestedOps = new Set(req.requestedOps);
                // Validate received history
                if (resp.history !== undefined) {
                    receivedHistory = new HistoryFragment(this.syncAgent.mutableObjHash);
                    // Verify all received op history literals and create a fragment from 'em:
                    for (const opHistoryLiteral of resp.history) {
                        try {
                            receivedHistory.add(new OpHeader(opHistoryLiteral));
                        }
                        catch (e) {
                            const detail = 'Error parsing op history literal ' + opHistoryLiteral.headerHash + ' received from ' + reqInfo.remote + ', cancelling request ' + reqInfo.request.requestId;
                            this.cancelRequest(reqInfo, 'invalid-response', detail);
                            return false;
                        }
                    }
                    // Check the reconstructed fragment does not provide more than one history for each mentioned op,
                    // which would indicate an invalid history:
                    if (!receivedHistory.verifyUniqueOps()) {
                        const detail = 'History received as reply to request ' + req.requestId + ' from ' + reqInfo.remote + ' contains duplicated histories for the same op, cancelling.';
                        this.cancelRequest(reqInfo, 'invalid-response', detail);
                        return false;
                    }
                    // Check that the terminal op histories of the received fragment are amongst the requested histories
                    for (const opHistoryHash of receivedHistory.terminalOpHeaders) {
                        if (!requestedOpHistories.has(opHistoryHash)) {
                            const detail = 'Received op history ' + opHistoryHash + ' is terminal in the reconstructed fragment, but was not requested.';
                            this.cancelRequest(reqInfo, 'invalid-response', detail);
                            return false;
                        }
                    }
                    // Check that the histories we sent as already known were not included
                    if (req.requestedStartingOpHistory !== undefined) {
                        for (const opHistoryHash of req.requestedStartingOpHistory) {
                            if (receivedHistory.contents.has(opHistoryHash)) {
                                const detail = 'Received history contains op history ' + opHistoryHash + ' which was informed as already present in request ' + req.requestId + ', cancelling it.';
                                this.cancelRequest(reqInfo, 'invalid-response', detail);
                                return false;
                            }
                        }
                    }
                    // Check that any received histories whose ops are already in the store are legit
                    for (const opHistory of receivedHistory.contents.values()) {
                        const storedOpHistory = await this.syncAgent.store.loadOpHeader(opHistory.opHash);
                        if (storedOpHistory !== undefined) {
                            if (storedOpHistory.headerHash !== opHistory.headerHash) {
                                const detail = 'Received history for op ' + opHistory.opHash + ' has causal hash of ' + opHistory.headerHash + ', but it does not match the already stored causal hash of ' + storedOpHistory.headerHash + ', discarding response for ' + req.requestId;
                                this.cancelRequest(reqInfo, 'invalid-response', detail);
                                return false;
                            }
                        }
                    }
                }
                // Validate response's sendingOps
                // The reply MAY contain ops we didn't request, if they directly follow our stated current state.
                // Make a history fragment using this additional ops to check that is indeed the case.
                const additionalOpsHistory = new HistoryFragment(this.syncAgent.mutableObjHash);
                if (resp.sendingOps !== undefined) {
                    for (const hash of resp.sendingOps) {
                        if (!requestedOps.has(hash)) {
                            const opHistory = receivedHistory === null || receivedHistory === void 0 ? void 0 : receivedHistory.getOpHeaderForOp(hash);
                            if (opHistory === undefined) {
                                const detail = 'Received op hash ' + hash + ' cannot be justified, it is neither in requestedOps nor in the received history';
                                this.cancelRequest(reqInfo, 'invalid-response', detail);
                                return false;
                            }
                            else {
                                additionalOpsHistory.add(opHistory);
                            }
                        }
                    }
                    // Check if the additional ops follow from provided history
                    if (additionalOpsHistory.contents.size > 0) {
                        if (reqInfo.request.mode !== 'infer-req-ops') {
                            const detail = 'Response to request ' + req.requestId + ' includes additional ops, but mode is not infer-req-ops';
                            this.cancelRequest(reqInfo, 'invalid-response', detail);
                            return false;
                        }
                        else {
                            for (const opHistoryHash of additionalOpsHistory.missingPrevOpHeaders) {
                                if (await this.syncAgent.store.loadOpHeaderByHeaderHash(opHistoryHash) === undefined) {
                                    const detail = 'Request informs it will send an op depending upon another with history hash ' + opHistoryHash + ', but it was neither requested or follows directly from informed fetched op histories.';
                                    this.cancelRequest(reqInfo, 'invalid-response', detail);
                                    return false;
                                }
                            }
                        }
                    }
                }
                reqInfo.receivedHistory = receivedHistory;
                return true;
            }
            else {
                return false;
            }
        }
        // If the response has any omission proofs, validate them
        async validateOmissionProofs(reqInfo) {
            var _a, _b;
            const req = reqInfo.request;
            const resp = reqInfo.response;
            if ((resp === null || resp === void 0 ? void 0 : resp.omittedObjs) !== undefined && resp.omittedObjs.length > 0) {
                if ((resp === null || resp === void 0 ? void 0 : resp.sendingOps) === undefined || resp.sendingOps.length === 0) {
                    const detail = 'Response includes ' + resp.omittedObjs.length + ' omitted objects, but it is not sending any ops - this makes no sense.';
                    this.cancelRequest(reqInfo, 'invalid-response', detail);
                    return false;
                }
                if ((resp === null || resp === void 0 ? void 0 : resp.omittedObjsReferenceChains) === undefined || resp.omittedObjsReferenceChains.length !== resp.omittedObjs.length) {
                    const detail = 'Response includes ' + resp.omittedObjs.length + ' omitted objects but ' + ((_a = resp.omittedObjsReferenceChains) === null || _a === void 0 ? void 0 : _a.length) + ' reference chains - they should be the same.';
                    this.cancelRequest(reqInfo, 'invalid-response', detail);
                    return false;
                }
                if ((resp === null || resp === void 0 ? void 0 : resp.omittedObjsOwnershipProofs) === undefined || resp.omittedObjsOwnershipProofs.length !== resp.omittedObjs.length) {
                    const detail = 'Response includes ' + resp.omittedObjs.length + ' omitted objects but ' + ((_b = resp.omittedObjsOwnershipProofs) === null || _b === void 0 ? void 0 : _b.length) + ' ownership proofs - they should be the same.';
                    this.cancelRequest(reqInfo, 'invalid-response', detail);
                    return false;
                }
                let omittedObjsOk = true;
                for (const idx of resp.omittedObjs.keys()) {
                    const hash = resp.omittedObjs[idx];
                    const referenceChain = Array.from(resp.omittedObjsReferenceChains[idx]);
                    const refOpHash = referenceChain.shift();
                    if (refOpHash === undefined) {
                        omittedObjsOk = false;
                        this.controlLog.warning('\n' + this.logPrefix + '\nReference chain for object ' + hash + ' is empty, cancelling request ' + req.requestId);
                        break;
                    }
                    const refOpLit = await this.syncAgent.store.loadLiteral(refOpHash);
                    if (refOpLit === undefined) {
                        omittedObjsOk = false;
                        this.controlLog.warning('\n' + this.logPrefix + '\nReferenced op in reference chain ' + refOpHash + ' not found locally, cancelling request ' + req.requestId);
                        break;
                    }
                    if (!this.syncAgent.literalIsValidOp(refOpLit)) {
                        omittedObjsOk = false;
                        this.controlLog.warning('\n' + this.logPrefix + '\nReferenced op ' + refOpHash + 'in reference chain for omitted obj ' + hash + ' is not a valid op, cancelling request ' + req.requestId);
                        break;
                    }
                    let currLit = refOpLit;
                    while (referenceChain.length > 0) {
                        let foundDep = false;
                        const nextHash = referenceChain[0];
                        for (const dep of currLit.dependencies) {
                            if (dep.hash === nextHash) {
                                foundDep = true;
                                break;
                            }
                        }
                        if (foundDep) {
                            const nextLit = await this.syncAgent.store.loadLiteral(nextHash);
                            if (nextLit !== undefined) {
                                currLit = nextLit;
                                referenceChain.shift();
                            }
                            else {
                                this.controlLog.warning('\n' + this.logPrefix + '\nReferenced obj in reference chain ' + nextHash + ' not found locally, cancelling request ' + req.requestId);
                                break;
                            }
                        }
                        else {
                            this.controlLog.warning('\n' + this.logPrefix + '\nDep ' + nextHash + 'in reference chain for omitted obj ' + hash + ' not found amongst dependencies of ' + currLit.hash + ', cancelling request ' + req.requestId);
                            break;
                        }
                    }
                    if (referenceChain.length > 0) {
                        omittedObjsOk = false;
                        break;
                    }
                    if (currLit.hash !== hash) {
                        omittedObjsOk = false;
                        this.controlLog.warning('\n' + this.logPrefix + '\nReference chain for omitted obj ' + hash + ' ends in another object: ' + currLit.hash + ', cancelling request ' + req.requestId);
                        break;
                    }
                    const ownershipProof = resp.omittedObjsOwnershipProofs[idx];
                    const dep = await this.syncAgent.store.load(hash);
                    if (dep === undefined || dep.hash(reqInfo.request.omissionProofsSecret) !== ownershipProof) {
                        omittedObjsOk = false;
                        this.controlLog.warning('\n' + this.logPrefix + '\nOmission proof for obj ' + hash + ' is wrong, cancelling request ' + req.requestId);
                        break;
                    }
                }
                if (!omittedObjsOk) {
                    const detail = 'Detail not available.';
                    this.cancelRequest(reqInfo, 'invalid-omitted-objs', detail);
                    return false;
                }
            }
            return true;
        }
        // request messaging (send, cancel)
        // request lifecycle
        canSendNewRequestTo(remote) {
            const active = this.activeRequests.get(remote);
            return active.size < MaxRequestsPerRemote;
        }
        sendRequest(reqInfo) {
            var _a, _b, _c, _d;
            reqInfo.status = 'sent';
            reqInfo.requestSendingTimestamp = Date.now();
            const reqId = reqInfo.request.requestId;
            this.requests.set(reqId, reqInfo);
            this.activeRequests.add(reqInfo.remote, reqId);
            if (((_a = reqInfo.request) === null || _a === void 0 ? void 0 : _a.requestedOps) !== undefined) {
                for (const hash of (_b = reqInfo.request) === null || _b === void 0 ? void 0 : _b.requestedOps) {
                    this.requestsForOp.add(hash, reqId);
                    for (const opHistory of this.discoveredHistory.getAllOpHeadersForOp(hash)) {
                        this.requestedOps.add(opHistory);
                    }
                }
            }
            if (reqInfo.request.requestedTerminalOpHistory !== undefined) {
                for (const opHistoryHash of reqInfo.request.requestedTerminalOpHistory) {
                    this.requestsForOpHistory.add(opHistoryHash, reqId);
                }
            }
            let sent = this.syncAgent.sendMessageToPeer(reqInfo.remote, this.syncAgent.getAgentId(), reqInfo.request);
            if (sent) {
                this.requestLog.debug('Sent req ' + reqInfo.request.requestId + ' (' + ((_c = reqInfo.request.requestedOps) === null || _c === void 0 ? void 0 : _c.length) + ' ops) to ' + reqInfo.remote);
            }
            else {
                this.requestLog.debug('Sent FAILURE for req ' + reqInfo.request.requestId + ' (' + ((_d = reqInfo.request.requestedOps) === null || _d === void 0 ? void 0 : _d.length) + ' ops)');
            }
            return sent;
        }
        cancelRequest(reqInfo, reason, detail) {
            if (this.lastCancelledRequests.indexOf(reqInfo.request.requestId) < 0) {
                if (this.lastCancelledRequests.length >= MaxSavedCancelledRequests) {
                    this.lastCancelledRequests.shift();
                }
                this.lastCancelledRequests.push(reqInfo.request.requestId);
            }
            HeaderBasedSyncAgent.controlLog.debug('\n' + this.logPrefix + '\n' + detail);
            this.cleanupRequest(reqInfo);
            const msg = {
                type: exports.MessageType.CancelRequest,
                requestId: reqInfo.request.requestId,
                reason: reason,
                detail: detail
            };
            this.requestLog.debug('Cancelling request ' + reqInfo.request.requestId);
            this.syncAgent.sendMessageToPeer(reqInfo.remote, this.syncAgent.getAgentId(), msg);
        }
        checkRequestRemoval(reqInfo) {
            if (reqInfo.response === undefined && reqInfo.requestSendingTimestamp !== undefined &&
                Date.now() > reqInfo.requestSendingTimestamp + RequestTimeout * 1000) {
                // Remove due to timeout waiting for response.
                this.cancelRequest(reqInfo, 'slow-connection', 'Timeout waiting for response');
                return true;
            }
            else if (reqInfo.response !== undefined && reqInfo.status !== 'validating') { // ??? requests are vanishing during validation
                if (reqInfo.response.sendingOps === undefined || reqInfo.response.sendingOps.length === 0) {
                    // This request is not sending any ops, so it can be removed as soon as there is a response
                    this.cleanupRequest(reqInfo);
                    return true;
                }
                else if (reqInfo.nextOpSequence === reqInfo.response.sendingOps.length) {
                    // All the ops in the request have been received, it can be removed
                    this.cleanupRequest(reqInfo);
                    return true;
                }
                else {
                    // Check if the receiving of the ops has not timed out
                    let lastLiteralRequestTimestamp;
                    if (reqInfo.lastLiteralTimestamp === undefined) {
                        if (reqInfo.responseArrivalTimestamp !== undefined) {
                            lastLiteralRequestTimestamp = reqInfo.responseArrivalTimestamp;
                        }
                        else {
                            lastLiteralRequestTimestamp = reqInfo.requestSendingTimestamp;
                        }
                    }
                    else {
                        lastLiteralRequestTimestamp = reqInfo.lastLiteralTimestamp;
                    }
                    if (reqInfo.receivedLiteralsCount < reqInfo.response.literalCount && lastLiteralRequestTimestamp !== undefined && Date.now() > lastLiteralRequestTimestamp + LiteralArrivalTimeout * 1000) {
                        this.cancelRequest(reqInfo, 'slow-connection', 'Timeout waiting for a literal to arrive');
                        return true;
                    }
                }
            }
            return false;
        }
        cleanupRequest(reqInfo) {
            var _a, _b, _c;
            if (this.requests.get(reqInfo.request.requestId) === undefined) {
                return;
            }
            const requestId = reqInfo.request.requestId;
            if (reqInfo.request.currentState !== undefined) {
                for (const hash of reqInfo.request.currentState.values()) {
                    this.requestsBlockedByOpHeader.delete(hash, requestId);
                }
            }
            if (reqInfo.request.requestedOps !== undefined) {
                // Remove the op requests
                for (const opHash of (_a = reqInfo.request) === null || _a === void 0 ? void 0 : _a.requestedOps) {
                    this.requestsForOp.delete(opHash, requestId);
                    if (this.requestsForOp.get(opHash).size === 0) {
                        for (const opHistory of this.discoveredHistory.getAllOpHeadersForOp(opHash)) {
                            this.requestedOps.remove(opHistory.headerHash);
                        }
                    }
                }
            }
            if (((_b = reqInfo.response) === null || _b === void 0 ? void 0 : _b.sendingOps) !== undefined) {
                // If the request has a response, then requestsForOp may have been
                // updated to expect what the response.sendingOps sepecifies, so remove
                // thes op requests
                for (const opHash of (_c = reqInfo.response) === null || _c === void 0 ? void 0 : _c.sendingOps) {
                    this.requestsForOp.delete(opHash, requestId);
                    if (this.requestsForOp.get(opHash).size === 0) {
                        for (const opHistory of this.discoveredHistory.getAllOpHeadersForOp(opHash)) {
                            this.requestedOps.remove(opHistory.headerHash);
                        }
                    }
                }
            }
            // remove pending opHistories
            if (reqInfo.request.requestedTerminalOpHistory !== undefined) {
                for (const opHistoryHash of reqInfo.request.requestedTerminalOpHistory) {
                    this.requestsForOpHistory.delete(opHistoryHash, requestId);
                }
            }
            // remove from active
            this.activeRequests.delete(reqInfo.remote, requestId);
            // remove request info
            this.requests.delete(reqInfo.request.requestId);
            // see if we can shut down the timer checking for timeouts
            this.checkRequestTimeoutsTimer();
            this.requestLog.debug('Cleaned up request ' + reqInfo.request.requestId);
        }
        async logStoreContents() {
            this.storeLog.debug('\n' + this.logPrefix + '\nStored state before request\n' + await this.syncAgent.lastStoredOpsDescription());
        }
        selfDiagnostic() {
            var _a, _b, _c;
            let diag = '\ncurrent requests:\n';
            for (const [reqId, reqInfo] of this.requests.entries()) {
                diag = diag + '\n[' + reqId + '] to peer ' + reqInfo.remote + '\n';
                diag = diag + '\n    status:  ' + reqInfo.status;
                if (reqInfo.requestSendingTimestamp !== undefined) {
                    diag = diag + '\n    sent:    ' + ((Date.now() - reqInfo.requestSendingTimestamp) / 1000) + ' seconds ago';
                }
                if (reqInfo.responseArrivalTimestamp !== undefined) {
                    diag = diag + '\n    replied: ' + ((Date.now() - reqInfo.responseArrivalTimestamp) / 1000) + ' seconds ago';
                }
                diag = diag + '\n    req op history terminals: ' + reqInfo.request.requestedTerminalOpHistory;
                diag = diag + '\n    requested ops: ' + reqInfo.request.requestedOps;
                diag = diag + '\n    response ops manifest: ' + ((_a = reqInfo.response) === null || _a === void 0 ? void 0 : _a.sendingOps);
                diag = diag + '\n    expected literals:' + ((_b = reqInfo.response) === null || _b === void 0 ? void 0 : _b.literalCount);
                diag = diag + '\n    received literal count: ' + reqInfo.receivedLiteralsCount;
                const blockedBy = new Array();
                for (const [opHeaderHash, reqIds] of this.requestsBlockedByOpHeader.entries()) {
                    if (reqIds.has(reqId)) {
                        blockedBy.push(((_c = this.discoveredHistory.contents.get(opHeaderHash)) === null || _c === void 0 ? void 0 : _c.opHash) || 'missing from disc');
                    }
                }
                if (blockedBy.length > 0) {
                    diag = diag + '\n    blocked by ops: ' + blockedBy;
                }
                diag = diag + '\n';
            }
            return diag;
        }
        shutdown() {
            this.terminated = true;
            if (this.checkRequestTimeoutsInterval !== undefined) {
                clearInterval(this.checkRequestTimeoutsInterval);
                this.checkRequestTimeoutsInterval = undefined;
            }
        }
    }
    HistorySynchronizer.controlLog = new Logger(HistorySynchronizer.name, LogLevel.INFO);
    HistorySynchronizer.sourcesLog = new Logger(HistorySynchronizer.name, LogLevel.INFO);
    HistorySynchronizer.stateLog = new Logger(HistorySynchronizer.name, LogLevel.INFO);
    HistorySynchronizer.opXferLog = new Logger(HistorySynchronizer.name, LogLevel.INFO);
    HistorySynchronizer.storeLog = new Logger(HistorySynchronizer.name, LogLevel.INFO);
    HistorySynchronizer.requestLog = new Logger(HistorySynchronizer.name, LogLevel.INFO);
    HistorySynchronizer.responseLog = new Logger(HistorySynchronizer.name, LogLevel.INFO);

    class HeaderBasedSyncAgent extends PeeringAgentBase {
        constructor(peerGroupAgent, mutableObjOrHash, resources, acceptedMutationOpClasses, stateOpFilter) {
            super(peerGroupAgent);
            this.terminated = false;
            if (mutableObjOrHash instanceof MutableObject) {
                this.mutableObj = mutableObjOrHash;
                this.mutableObjHash = mutableObjOrHash.hash();
            }
            else {
                this.mutableObjHash = mutableObjOrHash;
            }
            this.acceptedMutationOpClasses = acceptedMutationOpClasses;
            this.stateOpFilter = stateOpFilter;
            this.resources = resources;
            this.store = resources.store;
            this.remoteStates = new Map();
            this.synchronizer = new HistorySynchronizer(this);
            this.provider = new HistoryProvider(this);
            this.opCallback = this.opCallback.bind(this);
            this.controlLog = HeaderBasedSyncAgent.controlLog;
            this.messageLog = HeaderBasedSyncAgent.messageLog;
        }
        static syncAgentIdFor(objHash, peerGroupId) {
            return 'causal-sync-for-' + objHash + '-in-peer-group-' + peerGroupId;
        }
        getAgentId() {
            return HeaderBasedSyncAgent.syncAgentIdFor(this.mutableObjHash, this.peerGroupAgent.peerGroupId);
        }
        ready(pod) {
            this.pod = pod;
            this.updateStateFromStore().then(async () => {
                if (this.stateOpHeadersByOpHash !== undefined) {
                    for (const opHistory of this.stateOpHeadersByOpHash.values()) {
                        const op = await this.store.load(opHistory === null || opHistory === void 0 ? void 0 : opHistory.opHash);
                        await this.synchronizer.onNewLocalOp(op);
                    }
                }
            });
            this.watchStoreForOps();
            this.controlLog.debug('Started agent for ' + this.mutableObjHash);
        }
        shutdown() {
            this.terminated = true;
            this.synchronizer.shutdown();
        }
        // Reactive logic:
        //                   - Gossip agent informing us of the reception of remote state updates
        //                   - Messages from peers with requests, replies, literals, etc.
        async receiveRemoteState(sender, stateHash, state) {
            var _a;
            if (this.terminated)
                return false;
            let isNew = false;
            if (state instanceof HeaderBasedState && state.mutableObj === this.mutableObjHash) {
                this.remoteStates.set(sender, new HashedSet((_a = state.terminalOpHeaderHashes) === null || _a === void 0 ? void 0 : _a.values()));
                if (this.stateHash !== stateHash) {
                    const filteredState = this.stateOpFilter === undefined ? state : await this.stateOpFilter(state, this.store, false, this.state);
                    const unknown = new Set();
                    for (const opHistoryLiteral of filteredState.terminalOpHeaders.values()) {
                        if ((await this.store.loadOpHeaderByHeaderHash(opHistoryLiteral.headerHash)) === undefined) {
                            unknown.add(new OpHeader(opHistoryLiteral));
                        }
                    }
                    isNew = unknown.size > 0;
                    if (isNew) {
                        this.synchronizer.onNewHistory(sender, unknown);
                    }
                }
            }
            return isNew;
        }
        receivePeerMessage(source, sender, recipient, content) {
            if (this.terminated)
                return;
            const msg = content;
            if (this.messageLog.level <= LogLevel.DEBUG) {
                this.messageLog.debug('Msg received from: ' + source + ' to: ' + this.peerGroupAgent.getLocalPeer().endpoint, msg);
            }
            if (msg.type === exports.MessageType.Request) {
                this.provider.onReceivingRequest(source, msg);
            }
            else if (msg.type === exports.MessageType.Response) {
                this.synchronizer.onReceivingResponse(source, msg);
            }
            else if (msg.type === exports.MessageType.SendLiteral) {
                this.synchronizer.onReceivingLiteral(source, msg);
            }
            else if (msg.type === exports.MessageType.RejectRequest) {
                this.synchronizer.onReceivingRequestRejection(source, msg);
            }
            else if (msg.type === exports.MessageType.CancelRequest) {
                this.provider.onReceivingRequestCancellation(source, msg);
            }
        }
        // Monitoring local state for changes: 
        watchStoreForOps() {
            this.store.watchReferences('targetObject', this.mutableObjHash, this.opCallback);
        }
        unwatchStoreForOps() {
            this.store.removeReferencesWatch('targetObject', this.mutableObjHash, this.opCallback);
        }
        async opCallback(opHash) {
            if (this.terminated)
                return;
            this.controlLog.trace('Op ' + opHash + ' found for object ' + this.mutableObjHash + ' in peer ' + this.peerGroupAgent.getLocalPeer().endpoint);
            let op = await this.store.load(opHash);
            if (this.shouldAcceptMutationOp(op)) {
                await this.synchronizer.onNewLocalOp(op);
                await this.updateStateFromStore();
            }
        }
        ;
        literalIsValidOp(literal) {
            let valid = false;
            if (this.acceptedMutationOpClasses !== undefined && literal !== undefined) {
                const fields = LiteralUtils.getFields(literal);
                const className = LiteralUtils.getClassName(literal);
                if (fields['targetObject'] !== undefined && fields['targetObject']._hash === this.mutableObjHash &&
                    this.acceptedMutationOpClasses.indexOf(className) >= 0) {
                    valid = true;
                }
            }
            return valid;
        }
        // Loading local state:
        async updateStateFromStore() {
            const state = await this.loadStateFromStore();
            this.updateState(state);
        }
        /*private async loadSynchronizerState(): Promise<HeaderBasedState> {

            this.synchronizer.localState.getTerminalOps();

        }*/
        async loadStateFromStore() {
            var _a;
            let terminalOpsInfo = await this.store.loadTerminalOpsForMutable(this.mutableObjHash);
            if (terminalOpsInfo === undefined) {
                terminalOpsInfo = { terminalOps: [] };
            }
            const terminalOpHeaders = [];
            for (const terminalOpHash of terminalOpsInfo.terminalOps) {
                let terminalOpHeader = (_a = this.stateOpHeadersByOpHash) === null || _a === void 0 ? void 0 : _a.get(terminalOpHash);
                if (terminalOpHeader === undefined) {
                    terminalOpHeader = await this.store.loadOpHeader(terminalOpHash);
                }
                terminalOpHeaders.push(terminalOpHeader);
            }
            const state = HeaderBasedState.create(this.mutableObjHash, terminalOpHeaders);
            if (this.stateOpFilter === undefined) {
                return state;
            }
            else {
                return this.stateOpFilter(state, this.store, true);
            }
        }
        updateState(state) {
            var _a, _b, _c, _d;
            const stateHash = state.hash();
            if (this.stateHash === undefined || this.stateHash !== stateHash) {
                HeaderBasedSyncAgent.controlLog.trace('Found new state ' + stateHash + ' for ' + this.mutableObjHash + ' in ' + this.peerGroupAgent.getLocalPeer().endpoint);
                this.state = state;
                this.stateHash = stateHash;
                this.stateOpHeadersByOpHash = new Map();
                if (((_a = this.state) === null || _a === void 0 ? void 0 : _a.terminalOpHeaders) !== undefined) {
                    for (const opHeader of (_c = (_b = this.state) === null || _b === void 0 ? void 0 : _b.terminalOpHeaders) === null || _c === void 0 ? void 0 : _c.values()) {
                        this.stateOpHeadersByOpHash.set(opHeader.opHash, new OpHeader(opHeader));
                    }
                }
                let stateUpdate = {
                    type: exports.GossipEventTypes.AgentStateUpdate,
                    content: { agentId: this.getAgentId(), state }
                };
                (_d = this.pod) === null || _d === void 0 ? void 0 : _d.broadcastEvent(stateUpdate);
            }
        }
        shouldAcceptMutationOp(op) {
            var _a;
            return this.mutableObjHash === ((_a = op.targetObject) === null || _a === void 0 ? void 0 : _a.hash()) &&
                this.acceptedMutationOpClasses.indexOf(op.getClassName()) >= 0;
        }
        async lastStoredOpsDescription(limit = 25) {
            const load = await this.store.loadByReference('targetObject', this.mutableObjHash, { order: 'desc', limit: limit });
            const last = load.objects.length === limit ? 'last ' : '';
            let contents = 'Showing ' + last + load.objects.length + ' ops in store for ' + this.mutableObjHash + '\n';
            let idx = 0;
            for (const op of load.objects) {
                const opHistory = await this.store.loadOpHeader(op.getLastHash());
                contents = contents + idx + ': ' + opHistory.opHash + ' causal: ' + opHistory.headerHash + ' -> [' + Array.from(opHistory.prevOpHeaders) + ']\n';
                idx = idx + 1;
            }
            return contents;
        }
    }
    HeaderBasedSyncAgent.controlLog = new Logger(HeaderBasedSyncAgent.name, LogLevel.INFO);
    HeaderBasedSyncAgent.messageLog = new Logger(HeaderBasedSyncAgent.name, LogLevel.INFO);
    HeaderBasedSyncAgent.MaxRequestsPerRemote = 2;

    class InvalidateAfterOp extends MutationOp {
        // Meaning: invalidate targetOp after terminalOps, i.e. undo any ops that
        // have targetOp in causalOps but are not contained in the set of ops that
        // come up to {terminalOps}.
        constructor(targetOp, terminalOps) {
            super(targetOp === null || targetOp === void 0 ? void 0 : targetOp.targetObject);
            if (targetOp !== undefined) {
                this.targetOp = targetOp;
                if (terminalOps === undefined) {
                    throw new Error('InvalidateAfterOp cannot be created: terminalOps parameter is missing.');
                }
                else {
                    this.terminalOps = new HashedSet(Array.from(terminalOps).map((op) => op.createReference()).values());
                }
                if (targetOp instanceof CascadedInvalidateOp) {
                    throw new Error('An InvalidateAfterOp cannot target an undo / redo op directly.');
                }
                if (targetOp instanceof InvalidateAfterOp) {
                    throw new Error('An InvalidateAfterOp cannot target another InvalidateAfterOp directly.');
                }
            }
        }
        init() {
        }
        async validate(references) {
            if (!(await super.validate(references))) {
                return false;
            }
            // check that the terminalOps and the InvAfterOp itself all point to the same MutableObject.
            for (const terminalOpRef of this.terminalOps.values()) {
                const terminalOp = references.get(terminalOpRef.hash);
                if (terminalOp === undefined) {
                    return false;
                }
                if (!terminalOp.getTargetObject().equals(this.targetObject)) {
                    return false;
                }
            }
            if (this.targetOp instanceof CascadedInvalidateOp) {
                return false;
            }
            if (this.targetOp instanceof InvalidateAfterOp) {
                return false;
            }
            if (!this.getTargetOp().getTargetObject().equals(this.getTargetObject())) {
                return false;
            }
            return true;
        }
        getTargetOp() {
            if (this.targetOp === undefined) {
                throw new Error('Trying to get targetOp for InvalidateAfterOp ' + this.hash() + ', but it is not present.');
            }
            return this.targetOp;
        }
        getTerminalOps() {
            if (this.terminalOps === undefined) {
                throw new Error('Trying to get terminalOps for InvalidateAfterOp ' + this.hash() + ', but it is not present.');
            }
            return this.terminalOps;
        }
    }

    /*
     *        Op0 <-
     *         ^     \
     *  target |    c.\
     *         |       \            causal
     *     InvAfterOp    Op1 <------------------ Op2
     *         ^    \     ^                       ^
     *  target |   c.\    | target                | target
     *         |      \   |        causal         |
     *       UndoOp    UndoOp(1) <-------------- UndoOp(2)
     *         ^    \     ^                       ^
     *  target |   c.\    | target                | target
     *         |      \   |        causal         |
     *       RedoOp     RedoOp <---------------- RedoOp
     *         ^    \     ^                       ^
     *  target |   c.\    | target                | target
     *         |      \   |        causal         |
     *       UndoOp    UndoOp(3) <-------------- UndoOp(4)
     *
     */
    /*
     *
     *                  causal                      causal
     *        Op0  <--------------------- Op1 <------------------ Op2
     *         ^       _________________/  ^                       ^
     *  target |      / Op1 is too late    | target                | target
     *         |     /                     |        causal         |
     *     InvAfterOp <---------------  UndoOp(1) <-------------- UndoOp(2)
     *         ^        causal             ^                       ^
     *  target |                           | target                | target
     *         |        causal             |        causal         |
     *       UndoOp <-----------------  RedoOp <---------------- RedoOp
     *         ^                           ^                       ^
     *  target |                           | target                | target
     *         |        causal             |        causal         |
     *       RedoOp <-----------------  UndoOp(3) <-------------- UndoOp(4)
     *         ^                           ^                       ^
     *         |...                        |...                    |...
     *
     */
    /*
     *
     * Always: this.causal.target \in this.target.causal
     *
     * if causal is InvAfterOp => target is NOT CascadeOp, this.undo = true
     * if causal is CascadeOp  => target is CascadeOp, this.undo = !this.target.undo
     *
     *
     */
    /* The diagram above shows the situations where an UndoOp may be necessary. Here
     * InvAfterOp on the top left is invalidating Op1, and transitively Op2 that is
     * causally dependant on Op1. However, InvAfterOp is itself being undone, then
     * redone, then undone again, and those actions are also cascaded to Op1 and Op2.
     *
     * There are 4 possible cases, marked above:
     *
     *  (1) is the direct case, where Op1 is being undone because it is outside of the
     *  terminalOps defined in InvAfterOp.
     *
     *  (2) is a cascade of (1) to Op2, that is dependent on Op1.
     *
     *  (3) is a cascade of a RedoOp on the original InvAfterOp, that triggers a new
     *  undo for Op1. Notice in this case that the RedoOp is cascaded as an undo.
     *
     *  (4) is similar to (2), but is undoing a RedoOp for Op2 instead of Op2 itself.
     *
     * It is important to notice that in all cases but (1),
     *
     *          undo.causal.target \in undo.target.causalOps
     *
     */
    class CascadedInvalidateOp extends MutationOp {
        constructor(undo, targetOp, causalOp) {
            super(targetOp === null || targetOp === void 0 ? void 0 : targetOp.targetObject);
            if (undo !== undefined) {
                this.undo = undo;
                const opType = undo ? 'UndoOp' : 'RedoOp';
                if (targetOp === undefined) {
                    throw new Error('Cannot create ' + opType + ', targetOp not provided.');
                }
                this.targetOp = targetOp;
                if (causalOp === undefined) {
                    throw new Error('Cannot create ' + opType + ', causalOp not provided.');
                }
                this.setCausalOps([causalOp].values());
                // this.causalOps is initialized by call to super() above
                // sanity checks:
                // The cascade has merit: causalOp.targetOp \in targetOp.causalOps
                if (!targetOp.getCausalOps().has(causalOp.getTargetOp())) {
                    throw new Error('Creating undo because of an InvalidateAfterOp, but the op being undone does not depend on the invalidated one.');
                }
                // First CascadedInvOp in a chain is always an UndoOp, after that undos and redos alternate.
                if (targetOp instanceof CascadedInvalidateOp) {
                    if (this.undo === targetOp.undo) {
                        throw new Error('Creating ' + opType + ' that has another ' + opType + ' as target, only alternating undo <- redo <- undo ... chains are admissible.');
                    }
                }
                else {
                    if (!this.undo) {
                        throw new Error('A RedoOp can only have an UndoOp as target (found a ' + targetOp.getClassName() + ')');
                    }
                }
                if (causalOp instanceof InvalidateAfterOp) {
                    const invAfterOp = causalOp;
                    // invAfterOps can only be used as cause for UndoOps
                    if (!undo) {
                        throw new Error('Creating a RedoOp using an InvalidateAfterOp as causalOp (this should be an UndoOp then).');
                    }
                    // here we could also check that targetOp is really outside of invalidateAfterOp.terminalOps,
                    // but that's costly, and constructor checks aim only to aid debugging, so we'll not.
                    // invAfterOps can only be used as cause for ops within the same MutableObject
                    if (!this.getTargetObject().equals(invAfterOp.getTargetObject())) {
                        throw new Error('Trying to undo an op in a different mutable object than the invalidation op.');
                    }
                    // undo / redo ops cannot be invalidated by a InvAfterOp
                    if (targetOp instanceof CascadedInvalidateOp) {
                        throw new Error('Creating an ' + opType + ' with an UndoOp or RedoOp as target, an an InvalidateAfterOp as cause. InvalidateAfterOps only affect regular ops, not undos/redos.');
                    }
                }
                else if (causalOp instanceof CascadedInvalidateOp) ;
                else {
                    throw new Error('The cause of an undo/redo can only be another UndoOp/RedoOp, or an InvalidateAfterOp.');
                }
                this.prevOps = new HashedSet([causalOp.createReference(), targetOp.createReference()].values());
            }
        }
        // Obs: The validate() method in an UndoOp can only check if the UndoOp itself is well built. However,
        //      it is important to verify that the undo is consistent with the history already in the store.
        //      There is a special validateUndosInContext method for that (haven't decided where yet). 
        async validate(references) {
            var _a;
            if (!(await super.validate(references))) {
                return false;
            }
            if (this.getAuthor() !== undefined) {
                return false;
            }
            if (this.undo === undefined) {
                return false;
            }
            if (typeof (this.undo) !== 'boolean') {
                return false;
            }
            if (this.targetOp === undefined) {
                return false;
            }
            if (!(this.targetOp instanceof MutationOp)) {
                return false;
            }
            if (this.causalOps === undefined) {
                return false;
            }
            if (!(this.causalOps instanceof HashedSet)) {
                return false;
            }
            if (((_a = this.causalOps) === null || _a === void 0 ? void 0 : _a.size()) !== 1) {
                return false;
            }
            const causalOpRef = this.causalOps.values().next().value;
            if (!(causalOpRef instanceof HashReference)) {
                return false;
            }
            const causalOp = references.get(causalOpRef.hash);
            if (causalOp instanceof InvalidateAfterOp) {
                const invAfterOp = causalOp;
                // invAfterOps can only be used as cause for UndoOps
                if (!this.undo) {
                    return false;
                }
                // here we could also check that targetOp is really outside of invalidateAfterOp.terminalOps,
                // but that's costly, and constructor checks aim only to aid debugging, so we'll not.
                // invAfterOps can only be used as cause for ops within the same MutableObject
                if (!this.getTargetObject().equals(invAfterOp.getTargetObject())) {
                    return false;
                }
                // undo / redo ops cannot be invalidated by a InvAfterOp
                if (this.targetOp instanceof CascadedInvalidateOp) {
                    return false;
                }
            }
            else if (causalOp instanceof CascadedInvalidateOp) ;
            else {
                return false;
            }
            // The cascade has merit: causalOp.targetOp \in targetOp.causalOps
            if (!this.targetOp.getCausalOps().has(causalOp.getTargetOp())) {
                return false;
            }
            // First CascadedInvOp in a chain is always an UndoOp, after that undos and redos alternate.
            if (this.targetOp instanceof CascadedInvalidateOp) {
                if (this.undo === this.targetOp.undo) {
                    return false;
                }
            }
            else {
                if (!this.undo) {
                    return false;
                }
            }
            const prevOps = new HashedSet([causalOp.createReference(), this.targetOp.createReference()].values());
            // see that prevOps are correctly generated
            if (this.prevOps === undefined || !this.prevOps.equals(prevOps)) {
                return false;
            }
            return true;
        }
        getTargetOp() {
            if (this.targetOp === undefined) {
                throw new Error('Trying to get targetOp for InvalidateAfterOp ' + this.hash() + ', but it is not present.');
            }
            return this.targetOp;
        }
        getFinalTargetOp() {
            let finalTargetOp = this.getTargetOp();
            while (finalTargetOp instanceof CascadedInvalidateOp) {
                finalTargetOp = finalTargetOp.getTargetOp();
            }
            return finalTargetOp;
        }
        /*literalizeInContext(context: Context, path: string, flags?: Array<string>) : Hash {

            if (flags === undefined) {
                flags = [];
            }

            if (this.undo) {
                flags.push('undo');
            } else {
                flags.push('redo');
            }
            

            return super.literalizeInContext(context, path, flags);

        }*/
        getClassName() {
            return CascadedInvalidateOp.className;
        }
        init() {
        }
        static create(targetOp, causalOp) {
            const undo = (targetOp instanceof CascadedInvalidateOp) ? !targetOp.undo : true;
            if (undo) {
                return new CascadedInvalidateOp(true, targetOp, causalOp);
            }
            else {
                return new CascadedInvalidateOp(false, targetOp, causalOp);
            }
        }
    }
    CascadedInvalidateOp.className = 'hhs/v0/CascadedInvalidateOp';
    HashedObject.registerClass(CascadedInvalidateOp.className, CascadedInvalidateOp);

    //import { ObjectStateAgent } from 'sync/agents/state/ObjectStateAgent';
    //import { TerminalOpsStateAgent } from 'sync/agents/state/TerminalOpsStateAgent';
    class MutableObject extends HashedObject {
        constructor(acceptedOpClasses, supportsUndo = false) {
            super();
            if (supportsUndo) {
                if (acceptedOpClasses.indexOf(CascadedInvalidateOp.className) < 0) {
                    acceptedOpClasses.push(CascadedInvalidateOp.className);
                }
            }
            this._acceptedMutationOpClasses = acceptedOpClasses;
            this._boundToStore = false;
            this._allAppliedOps = new Set();
            this._terminalOps = new Map();
            this._activeUndoOpsPerOp = new MultiMap();
            this._unsavedOps = [];
            this._unappliedOps = new Map();
            this._applyOpsLock = new Lock();
            this._opCallback = async (hash) => {
                await this.applyOpFromStore(hash);
            };
            this._externalMutationCallbacks = new Set();
        }
        supportsUndo() {
            return this._acceptedMutationOpClasses.indexOf(CascadedInvalidateOp.className) >= 0;
        }
        /*
        // override if appropiate
        async undo(op: MutationOp): Promise<boolean> {
            op; return true;
        }

        // override if appropiate
        async redo(op: MutationOp): Promise<boolean> {
            op; return true;
        }*/
        isValidOp(opHash) {
            return this._activeUndoOpsPerOp.get(opHash).size === 0;
        }
        addMutationCallback(cb) {
            this._externalMutationCallbacks.add(cb);
        }
        deleteMutationCallback(cb) {
            this._externalMutationCallbacks.delete(cb);
        }
        watchForChanges(auto) {
            if (auto) {
                this.bindToStore();
            }
            else {
                this.unbindFromStore();
            }
            return this._boundToStore;
        }
        // getOpHeader will correclty ge the headers for ops that are still unsaved too
        async getOpHeader(opHash) {
            const stack = new Array();
            const cache = new Map();
            const unsaved = new Map();
            for (const op of this._unsavedOps) {
                unsaved.set(op.hash(), op);
            }
            stack.push(opHash);
            while (stack.length > 0) {
                const nextHash = stack[stack.length - 1];
                if (cache.has(nextHash)) {
                    // do nothing
                    stack.pop();
                }
                else if (unsaved.has(nextHash)) {
                    const op = unsaved.get(nextHash);
                    const prevOps = op.getPrevOpsIfPresent();
                    let missing = false;
                    if (prevOps !== undefined) {
                        for (const prevOpHash of prevOps) {
                            if (!cache.has(prevOpHash.hash)) {
                                stack.push(prevOpHash.hash);
                                missing = true;
                            }
                        }
                    }
                    if (!missing) {
                        const opHeader = op.getHeader(cache);
                        cache.set(stack.pop(), opHeader);
                    }
                }
                else {
                    const op = await this.getStore().loadOpHeader(stack.pop());
                    if (op === undefined) {
                        throw new Error('Trying to get op header for op ' + opHash + ', but it depends on op ' + nextHash + ' that is neither in the store or an unapplied op in ' + this.hash() + ' (a ' + this.getClassName() + ')');
                    }
                    cache.set(nextHash, op);
                }
            }
            return cache.get(opHash);
        }
        bindToStore() {
            // NOTE: watchReferences is idempotent
            this.getStore().watchReferences('targetObject', this.getLastHash(), this._opCallback);
            this._boundToStore = true;
        }
        unbindFromStore() {
            this.getStore().removeReferencesWatch('targetObject', this.getLastHash(), this._opCallback);
            this._boundToStore = false;
        }
        // TODO: if this object is bound to the store while the load takes place, we could take measures
        //       to try to avoid loading objects twice if they arrive while the load takes place.
        //       As it is now, the implementation should prepare for the event of an op being loaded twice.
        /*
        async loadOperations(limit?: number, start?: string) : Promise<void> {
            if (this._loadStrategy === 'none') {
                throw new Error("Trying to load operations from store, but load strategy was set to 'none'");
            } else if (this._loadStrategy === 'full') {

                if (limit !== undefined) {
                    throw new Error("Trying to load " + limit + " operations from store, but load strategy was set to 'full' - you should use 'lazy' instead");
                }

                if (start !== undefined) {
                    throw new Error("Trying to load operations from store starting at " + start + " but load strategy was set to 'full' - you should use 'lazy' instead");
                }

                await this.loadAllChanges();
            } else if (this._loadStrategy === 'lazy') {
                await this.loadLastOpsFromStore(limit, start);
            }

        }
        */
        async loadAllChanges(batchSize = 128) {
            let results = await this.getStore()
                .loadByReference('targetObject', this.getLastHash(), {
                order: 'asc',
                limit: batchSize
            });
            while (results.objects.length > 0) {
                for (const obj of results.objects) {
                    if (obj instanceof MutationOp && this.isAcceptedMutationOpClass(obj)) {
                        await this.apply(obj, false);
                    }
                }
                results = await this.getStore()
                    .loadByReference('targetObject', this.getLastHash(), {
                    order: 'asc',
                    limit: batchSize,
                    start: results.end
                });
            }
        }
        async loadAndWatchForChanges(loadBatchSize = 128) {
            this.watchForChanges(true);
            await this.loadAllChanges(loadBatchSize);
        }
        async loadLastOpsFromStore(limit, start) {
            let count = 0;
            let params = { order: 'desc', limit: limit };
            if (start !== undefined) {
                params.start = start;
            }
            let results = await this.getStore()
                .loadByReference('targetObject', this.getLastHash(), params);
            for (const obj of results.objects) {
                let op = obj;
                if (this.isAcceptedMutationOpClass(op)) {
                    this.apply(op, false);
                    count = count + 1;
                }
            }
            return { results: count, last: results.end };
        }
        async applyOpFromStore(hash) {
            let op;
            if (!this._allAppliedOps.has(hash) && !this._unappliedOps.has(hash)) {
                op = await this.getStore().load(hash);
                this._unappliedOps.set(hash, op);
                this.applyPendingOpsFromStore();
            }
        }
        async applyPendingOpsFromStore() {
            let go = true;
            while (go) {
                if (this._applyOpsLock.acquire()) {
                    try {
                        const pending = Array.from(this._unappliedOps.entries());
                        go = false;
                        const toRemove = new Array();
                        for (const [hash, op] of pending) {
                            if (this.canApplyOp(op)) {
                                await this.apply(op, false);
                                toRemove.push(hash);
                                go = true;
                            }
                        }
                        go = go || this._unappliedOps.size > pending.length;
                        for (const hash of toRemove) {
                            this._unappliedOps.delete(hash);
                        }
                    }
                    finally {
                        this._applyOpsLock.release();
                    }
                }
                else {
                    // If we fail to acquire the lock, then the loop above is already executing.
                    // Since the loop will not exit until there are no more ops to process, we
                    // can safely do nothing.
                    go = false;
                }
            }
        }
        applyNewOp(op) {
            if (!this.isAcceptedMutationOpClass(op)) {
                throw new Error('Invalid op ' + op.hash() + ' attempted for ' + this.hash());
            }
            else {
                op.setTargetObject(this);
                let prevOps = op.getPrevOpsIfPresent();
                if (prevOps === undefined) {
                    op.prevOps = new HashedSet();
                    for (const termOp of this._terminalOps.values()) {
                        op.prevOps.add(termOp.createReference());
                    }
                }
                else {
                    for (const prevOpRef of op.getPrevOps()) {
                        if (!this._allAppliedOps.has(prevOpRef.hash)) {
                            throw new Error('Cannot apply new op ' + op.hash() + ': it has prevOp ' + prevOpRef.hash + ' that has not been applied yet.');
                        }
                    }
                }
                const done = this.apply(op, true);
                return done;
            }
        }
        apply(op, isNew) {
            const opHash = op.hash();
            if (this._allAppliedOps.has(opHash)) {
                return Promise.resolve();
            }
            for (const prevOpRef of op.getPrevOps()) {
                this._terminalOps.delete(prevOpRef.hash);
            }
            this._terminalOps.set(opHash, op);
            this._allAppliedOps.add(opHash);
            if (isNew) {
                this.enqueueOpToSave(op);
            }
            let result = Promise.resolve(false);
            if (op instanceof CascadedInvalidateOp) {
                const finalTargetOp = op.getFinalTargetOp();
                const finalTargetOpHash = finalTargetOp.hash();
                const wasUndone = this._activeUndoOpsPerOp.get(finalTargetOpHash).size > 0;
                if (op.undo) {
                    this._activeUndoOpsPerOp.add(finalTargetOpHash, opHash);
                }
                else { // redo
                    this._activeUndoOpsPerOp.delete(finalTargetOpHash, op.getTargetOp().hash());
                }
                if (wasUndone !== op.undo) {
                    if (op.undo) {
                        //result = this.undo(op.getFinalTargetOp());
                        result = this.mutate(op.getFinalTargetOp(), false, true);
                    }
                    else { // redo
                        //result = this.redo(op.getFinalTargetOp());
                        result = this.mutate(op.getFinalTargetOp(), true, true);
                    }
                }
            }
            else {
                result = this.mutate(op, true, false);
            }
            const done = result.then((mutated) => {
                if (mutated) {
                    for (const cb of this._externalMutationCallbacks) {
                        cb(op);
                    }
                }
            });
            return done;
        }
        canApplyOp(op) {
            let ok = true;
            for (const prevOp of op.getPrevOps()) {
                if (!this._allAppliedOps.has(prevOp.hash)) {
                    ok = false;
                    break;
                }
            }
            return ok;
        }
        async saveQueuedOps(store) {
            if (store === undefined) {
                store = this.getStore();
            }
            else {
                this.setStore(store);
            }
            if (this._unsavedOps.length === 0) {
                return false;
            }
            else {
                while (this._unsavedOps.length > 0) {
                    let op = this._unsavedOps[0];
                    try {
                        await store.save(op, false);
                    }
                    catch (e) {
                        MutableObject.controlLog.debug(() => 'Error trying to save op for ' + this.hash() + ' (class: ' + this.getClassName() + ').');
                        throw e;
                    }
                    // This same op may have been saved and unshifted concurrently, check before unshifting
                    // to avoid removing an unsaved op.
                    if (op === this._unsavedOps[0]) {
                        this._unsavedOps.shift();
                    }
                }
                return true;
            }
        }
        async loadOp(opHash) {
            for (const op of this._unsavedOps) {
                if (op.hash() === opHash) {
                    return op;
                }
            }
            return this.getStore().load(opHash);
        }
        enqueueOpToSave(op) {
            this._unsavedOps.push(op);
        }
        literalizeInContext(context, path, flags) {
            if (flags === undefined) {
                flags = [];
            }
            flags.push('mutable');
            if (this.supportsUndo()) {
                flags.push('supports_undo');
            }
            return super.literalizeInContext(context, path, flags);
        }
        isAcceptedMutationOpClass(op) {
            return this._acceptedMutationOpClasses.indexOf(op.getClassName()) >= 0 && op.getTargetObject().equals(this);
        }
        // Override if necessary
        shouldAcceptMutationOp(op, opReferences) {
            return this.isAcceptedMutationOpClass(op);
        }
        createSyncAgent(peerGroupAgent) {
            return new HeaderBasedSyncAgent(peerGroupAgent, this, this.getResources(), this._acceptedMutationOpClasses, this.getSyncAgentStateFilter());
            //return new TerminalOpsSyncAgent(peerGroupAgent, this.getLastHash(), this.getStore(), this._acceptedMutationOpClasses);
        }
        getSyncAgentStateFilter() {
            return undefined;
        }
        getAcceptedMutationOpClasses() {
            return this._acceptedMutationOpClasses;
        }
    }
    MutableObject.controlLog = new Logger(MutableObject.name, LogLevel.INFO);
    MutableObject.prevOpsComputationLog = new Logger(MutableObject.name, LogLevel.INFO);

    class HashedLiteral extends HashedObject {
        constructor(value) {
            super();
            this.value = value;
        }
        getClassName() {
            return HashedLiteral.className;
        }
        init() {
        }
        async validate(references) {
            return true;
        }
        static valid(value, seen = new Set()) {
            let typ = typeof (value);
            if (typ === 'boolean' || typ === 'number' || typ === 'string') {
                return true;
            }
            else if (typ === 'object') {
                if (seen.has(value)) {
                    return false;
                }
                seen.add(value);
                if (Array.isArray(value)) {
                    for (const member of value) {
                        if (!HashedLiteral.valid(member, seen)) {
                            return false;
                        }
                    }
                    return true;
                }
                else {
                    let s = Object.prototype.toString.call(value);
                    if (s !== '[object Object]') {
                        return false;
                    }
                    for (const fieldName of Object.keys(value)) {
                        if (!HashedLiteral.valid(value[fieldName], seen)) {
                            return false;
                        }
                    }
                    return true;
                }
            }
            else {
                return false;
            }
        }
    }
    HashedLiteral.className = 'hhs/v0/HashedLiteral';
    HashedObject.registerClass(HashedLiteral.className, HashedLiteral);

    class Namespace {
        constructor(id) {
            this.id = id;
            this.definitions = new Map();
        }
        define(key, mut) {
            mut.setId(HashedObject.generateIdForPath(this.id, key));
            this.definitions.set(key, mut);
        }
        get(key) {
            return this.definitions.get(key);
        }
        getAll() {
            return this.definitions.values();
        }
    }

    class Types {
        static isTypeConstraint(types) {
            let valid = true;
            if (types !== undefined) {
                if (!Array.isArray(types)) {
                    valid = false;
                }
                else {
                    for (const typ of types) {
                        if ((typeof typ) !== 'string') {
                            valid = false;
                        }
                    }
                }
            }
            return valid;
        }
        static satisfies(value, types) {
            let satisfies = true;
            if (types !== undefined) {
                for (const typ of types) {
                    if (Types.hasType(value, typ)) {
                        satisfies = true;
                        break;
                    }
                }
            }
            return satisfies;
        }
        static hasType(value, typ) {
            if (typ === 'string') {
                return (typeof value) === 'string';
            }
            else if (typ === 'number') {
                return (typeof value) === 'number';
            }
            else {
                return (value instanceof HashedObject && value.getClassName() === typ);
            }
        }
    }

    // a simple mutable set with a single writer
    class MutableSetOp extends MutationOp {
        constructor(target) {
            super(target);
            if (target !== undefined) {
                let author = target.getAuthor();
                if (author !== undefined) {
                    this.setAuthor(author);
                }
            }
        }
        init() {
        }
        async validate(references) {
            var _a;
            if (!await super.validate(references)) {
                return false;
            }
            if (!(this.getTargetObject() instanceof MutableSet)) {
                return false;
                //throw new Error('MutableSetOp.target must be a MutableSet, got a ' + this.getTarget().getClassName() + ' instead.');
            }
            if (this.getTargetObject().getAuthor() !== undefined && !((_a = this.getTargetObject().getAuthor()) === null || _a === void 0 ? void 0 : _a.equals(this.getAuthor()))) {
                return false;
                //throw new Error('MutableSetOp has author ' + this.getAuthor()?.hash() + ' but points to a target authored by ' + this.getTarget().getAuthor()?.hash() + '.');
            }
            return true;
        }
    }
    class MutableSetAddOp extends MutableSetOp {
        constructor(target, element) {
            super(target);
            if (element !== undefined) {
                this.element = element;
                this.setRandomId();
            }
        }
        getClassName() {
            return MutableSetAddOp.className;
        }
        init() {
            super.init();
        }
        async validate(references) {
            if (!await super.validate(references)) {
                return false;
            }
            const constraints = this.getTargetObject().typeConstraints;
            if (!Types.satisfies(this.element, constraints)) {
                return false;
                //throw new Error('MutableSetAddOp contains a value with an unexpected type.')
            }
            return true;
        }
    }
    MutableSetAddOp.className = 'hhs/v0/MutableSetAddOp';
    MutableSetAddOp.registerClass(MutableSetAddOp.className, MutableSetAddOp);
    class MutableSetDeleteOp extends MutableSetOp {
        constructor(target, elementHash, addOps) {
            super(target);
            this.elementHash = elementHash;
            if (addOps !== undefined) {
                this.deletedOps = new HashedSet();
                for (const addOp of addOps) {
                    if (addOp.className !== MutableSetAddOp.className) {
                        throw new Error('Trying to create a delete op referencing an op that is not an addition op.');
                    }
                    this.deletedOps.add(addOp);
                }
            }
        }
        // need a valid() function, that is called only when an object is NEW and we don't yet
        // trust its integrity. init() will be called every time it is loaded (after all the
        // fields have been filled in, either by the constructor or by the deliteralization
        // mechanism, and after valid, if it is untrusted)
        // valid needs all the references also, already validated, to do its checks.
        // (all this follows from the need to validate deletedOps)
        init() {
            super.init();
        }
        async validate(references) {
            var _a, _b;
            if (!await super.validate(references)) {
                return false;
            }
            if (this.elementHash === undefined) {
                MutableSet.logger.warning('The field elementHash of type MutableSetDeletOp is mandatory.');
                return false;
            }
            if (typeof this.elementHash !== 'string') {
                MutableSet.logger.warning('The field elementHash of type MutebleSetDeleteOp should be a string.');
                return false;
            }
            if (this.deletedOps === undefined) {
                MutableSet.logger.warning('The field deletedOps of type MutableSetDeleteOp is mandatory');
                return false;
            }
            if (!(this.deletedOps instanceof HashedSet)) {
                MutableSet.logger.warning('The field deletedOps of type MutableSetDeleteOp should be a HashedSet.');
                return false;
            }
            for (const ref of this.deletedOps.values()) {
                const op = references.get(ref.hash);
                if (op === undefined) {
                    MutableSet.logger.warning('Addition op referenced in MutableSet deletion op is missing from references provided for validation.');
                }
                if (!(op instanceof MutableSetAddOp)) {
                    MutableSet.logger.warning('Addition op referenced in MutableSet deletion op has the wrong type in the references provided for validation.');
                    return false;
                }
                if (!((_a = op.targetObject) === null || _a === void 0 ? void 0 : _a.equals(this.targetObject))) {
                    MutableSet.logger.warning('Addition op referenced in MutableSet deletion op points to a different set.');
                    return false;
                }
                const addOp = op;
                if (((_b = addOp.element) === null || _b === void 0 ? void 0 : _b.hash()) !== this.elementHash) {
                    MutableSet.logger.warning('Addition op referenced in MutableSet deletion op contains an element whose hash does not match the one being deleted.');
                    return false;
                }
            }
            return true;
        }
        getClassName() {
            return MutableSetDeleteOp.className;
        }
    }
    MutableSetDeleteOp.className = 'hhs/v0/MutableSetDeleteOp';
    MutableSetDeleteOp.registerClass(MutableSetDeleteOp.className, MutableSetDeleteOp);
    class MutableSet extends MutableObject {
        constructor() {
            super(MutableSet.opClasses);
            this._logger = MutableSet.logger;
            this.setRandomId();
            this._elements = new Map();
            this._currentAddOpRefs = new Map();
            //this._unsavedAppliedOps = new Set();
        }
        init() {
        }
        async validate(references) {
            return Types.isTypeConstraint(this.typeConstraints);
        }
        async add(element) {
            let op = new MutableSetAddOp(this, element);
            await this.applyNewOp(op);
        }
        async delete(element) {
            return await this.deleteByHash(element.hash());
        }
        async deleteByHash(hash) {
            let addOpRefs = this._currentAddOpRefs.get(hash);
            if (addOpRefs !== undefined && addOpRefs.size() > 0) {
                let op = new MutableSetDeleteOp(this, hash, addOpRefs.values());
                await this.applyNewOp(op);
                return true;
            }
            else {
                return false;
            }
        }
        has(element) {
            return this.hasByHash(element.hash());
        }
        hasByHash(hash) {
            return this._elements.get(hash) !== undefined;
        }
        get(hash) {
            return this._elements.get(hash);
        }
        size() {
            return this._elements.size;
        }
        values() {
            return this._elements.values();
        }
        mutate(op) {
            let mutated = false;
            if (op instanceof MutableSetAddOp) {
                const addOp = op;
                let hash = op.element.hash();
                if (hash === undefined) {
                    throw new Error('Trying to add an element to set, but the element is undefined.');
                }
                let current = this._currentAddOpRefs.get(hash);
                if (current === undefined) {
                    current = new HashedSet();
                    this._currentAddOpRefs.set(hash, current);
                }
                mutated = current.size() === 0;
                current.add(addOp.createReference());
                this._elements.set(hash, addOp.element);
                if (mutated) {
                    if (this._addElementCallback !== undefined) {
                        try {
                            this._addElementCallback(addOp.element);
                        }
                        catch (e) {
                            this._logger.warning(() => ('Error calling MutableSet element addition callback on op ' + addOp.hash()));
                        }
                    }
                }
            }
            else if (op instanceof MutableSetDeleteOp) {
                const deleteOp = op;
                let hash = deleteOp.elementHash;
                if (hash === undefined) {
                    throw new Error('Trying to remove an element from set, but elementHash is undefined.');
                }
                let current = this._currentAddOpRefs.get(hash);
                if (current !== undefined) {
                    if (deleteOp.deletedOps !== undefined) {
                        for (const opRef of deleteOp.deletedOps.values()) {
                            current.remove(opRef);
                        }
                    }
                    if (current.size() === 0) {
                        mutated = true;
                        const deleted = this._elements.get(hash);
                        this._elements.delete(hash);
                        this._currentAddOpRefs.delete(hash);
                        if (this._deleteElementCallback !== undefined) {
                            try {
                                this._deleteElementCallback(deleted);
                            }
                            catch (e) {
                                this._logger.warning(() => ('Error calling MutableSet element deletion callback on op ' + deleteOp.hash()));
                            }
                        }
                    }
                }
            }
            else {
                throw new Error("Method not implemented.");
            }
            return Promise.resolve(mutated);
        }
        onAddition(callback) {
            this._addElementCallback = callback;
        }
        onDeletion(callback) {
            this._deleteElementCallback = callback;
        }
        getClassName() {
            return MutableSet.className;
        }
    }
    MutableSet.className = 'hss/v0/MutableSet';
    MutableSet.opClasses = [MutableSetAddOp.className, MutableSetDeleteOp.className];
    MutableSet.logger = new Logger(MutableSet.className, LogLevel.INFO);
    MutableSet.registerClass(MutableSet.className, MutableSet);

    class Timestamps {
        static currentTimestamp() {
            return 'T' + Date.now().toString(16).padStart(11, '0');
        }
        static uniqueTimestamp() {
            const random = new BrowserRNG().randomHexString(64);
            return Timestamps.currentTimestamp() + random;
        }
        static epochTimestamp() {
            return 'T' + ''.padStart(11 + 16, '0');
        }
        static parseUniqueTimestamp(unique) {
            return parseInt(unique.substring(1, 12), 16);
        }
        static compare(a, b) {
            a = a.toLowerCase();
            b = b.toLowerCase();
            // returns sign(a - b)
            return a.localeCompare(b);
        }
        static before(a, b) {
            return Timestamps.compare(a, b) < 0;
        }
        static after(a, b) {
            return Timestamps.compare(a, b) > 0;
        }
    }

    class MutableReference extends MutableObject {
        constructor() {
            super([RefUpdateOp.className]);
            this.setRandomId();
        }
        getValue() {
            return this._value;
        }
        async setValue(value) {
            let op = new RefUpdateOp(this, value, this._sequence);
            await this.applyNewOp(op);
        }
        mutate(op) {
            let refUpdateOp = op;
            let mutated = false;
            if (refUpdateOp.getTargetObject().equals(this)) {
                if (this._sequence === undefined ||
                    this._sequence < refUpdateOp.getSequence() ||
                    (this._sequence === refUpdateOp.getSequence() &&
                        Timestamps.after(refUpdateOp.getTimestamp(), this._timestamp))) {
                    this._sequence = refUpdateOp.getSequence();
                    this._timestamp = refUpdateOp.getTimestamp();
                    this._value = refUpdateOp.getValue();
                    mutated = true;
                }
            }
            return Promise.resolve(mutated);
        }
        getClassName() {
            return MutableReference.className;
        }
        init() {
        }
        async validate(references) {
            return Types.isTypeConstraint(this.typeConstraints);
        }
    }
    MutableReference.className = 'hhs/v0/MutableReference';
    class RefUpdateOp extends MutationOp {
        constructor(target, value, sequence) {
            super(target);
            if (target !== undefined) {
                this.value = value;
                this.sequence = sequence === undefined ? 0 : sequence + 1;
                this.timestamp = Timestamps.uniqueTimestamp();
            }
        }
        getClassName() {
            return RefUpdateOp.className;
        }
        init() {
        }
        async validate(references) {
            var _a;
            if (!super.validate(references)) {
                return false;
            }
            if (this.getTargetObject().getAuthor() !== undefined && !((_a = this.getTargetObject().getAuthor()) === null || _a === void 0 ? void 0 : _a.equals(this.getAuthor()))) {
                return false;
                //throw new Error('RefUpdateOp has author ' + this.getAuthor()?.hash() + ' but points to a target authored by ' + this.getTarget().getAuthor()?.hash() + '.');
            }
            if (this.sequence === undefined) {
                return false;
                //throw new Error('The field sequence is mandatory in class RefUpdateOp');
            }
            if ((typeof this.sequence) !== 'number') {
                return false;
                //throw new Error('The field sequence should be of type number in class RefUpdateop');
            }
            if (this.timestamp === undefined) {
                return false;
                //throw new Error('The field timestamp is mandatory in class RefUpdateOp');
            }
            if ((typeof this.timestamp) !== 'string') {
                return false;
                //throw new Error('The field timestamp should be of type timestamp in class RefUpdateop');
            }
            if (this.value === undefined) {
                return false;
                //throw new Error('The field value is mandatory in class REfUpdateop');
            }
            if (this.targetObject === undefined ||
                this.targetObject.getClassName() !== MutableReference.className) {
                return false;
                //throw new Error('A RefUpdateOp can only have a MutableReference as its target.');
            }
            let constraints = this.targetObject.typeConstraints;
            if (!Types.satisfies(this.value, constraints)) {
                return false;
                //throw new Error('RefUpdateOp contains a value with an unexpected type.')
            }
            return true;
        }
        getSequence() {
            return this.sequence;
        }
        getTimestamp() {
            return this.timestamp;
        }
        getValue() {
            return this.value;
        }
    }
    RefUpdateOp.className = 'hhs/v0/RefUpdateOp';
    HashedObject.registerClass(MutableReference.className, MutableReference);
    HashedObject.registerClass(RefUpdateOp.className, RefUpdateOp);

    // a simple mutable set with a single writer
    class ReversibleSetOp extends MutationOp {
        constructor(target, causalOps) {
            super(target);
            if (target !== undefined) {
                let author = target.getAuthor();
                if (author !== undefined) {
                    this.setAuthor(author);
                }
                if (causalOps !== undefined) {
                    this.setCausalOps(causalOps);
                }
            }
        }
        init() {
        }
        async validate(references) {
            var _a;
            if (!await super.validate(references)) {
                return false;
            }
            if (!(this.getTargetObject() instanceof ReversibleSet)) {
                return false;
                //throw new Error('ReversibleSetOp.target must be a ReversibleSet, got a ' + this.getTarget().getClassName() + ' instead.');
            }
            if (this.getTargetObject().getAuthor() !== undefined && !((_a = this.getTargetObject().getAuthor()) === null || _a === void 0 ? void 0 : _a.equals(this.getAuthor()))) {
                return false;
                //throw new Error('ReversibleSetOp has author ' + this.getAuthor()?.hash() + ' but points to a target authored by ' + this.getTarget().getAuthor()?.hash() + '.');
            }
            return true;
        }
    }
    class ReversibleSetAddOp extends ReversibleSetOp {
        constructor(target, element, causalOps) {
            super(target, causalOps);
            if (element !== undefined) {
                this.element = element;
                this.setRandomId();
            }
        }
        getClassName() {
            return ReversibleSetAddOp.className;
        }
        init() {
            super.init();
        }
        async validate(references) {
            if (!await super.validate(references)) {
                return false;
            }
            const constraints = this.getTargetObject().typeConstraints;
            if (!Types.satisfies(this.element, constraints)) {
                return false;
                //throw new Error('ReversibleSetAddOp contains a value with an unexpected type.')
            }
            return true;
        }
    }
    ReversibleSetAddOp.className = 'hhs/v0/ReversibleSetAddOp';
    ReversibleSetAddOp.registerClass(ReversibleSetAddOp.className, ReversibleSetAddOp);
    class ReversibleSetDeleteOp extends ReversibleSetOp {
        constructor(target, elementHash, addOps, causalOps) {
            super(target, causalOps);
            this.elementHash = elementHash;
            if (addOps !== undefined) {
                this.deletedOps = new HashedSet();
                for (const addOp of addOps) {
                    if (addOp.className !== ReversibleSetAddOp.className) {
                        throw new Error('Trying to create a delete op referencing an op that is not an addition op.');
                    }
                    this.deletedOps.add(addOp);
                }
            }
        }
        // need a valid() function, that is called only when an object is NEW and we don't yet
        // trust its integrity. init() will be called every time it is loaded (after all the
        // fields have been filled in, either by the constructor or by the deliteralization
        // mechanism, and after valid, if it is untrusted)
        // valid needs all the references also, already validated, to do its checks.
        // (all this follows from the need to validate deletedOps)
        init() {
            super.init();
        }
        async validate(references) {
            var _a, _b;
            if (!await super.validate(references)) {
                return false;
            }
            if (this.elementHash === undefined) {
                ReversibleSet.logger.warning('The field elementHash of type ReversibleSetDeletOp is mandatory.');
                return false;
            }
            if (typeof this.elementHash !== 'string') {
                ReversibleSet.logger.warning('The field elementHash of type MutebleSetDeleteOp should be a string.');
                return false;
            }
            if (this.deletedOps === undefined) {
                ReversibleSet.logger.warning('The field deletedOps of type ReversibleSetDeleteOp is mandatory');
                return false;
            }
            if (!(this.deletedOps instanceof HashedSet)) {
                ReversibleSet.logger.warning('The field deletedOps of type ReversibleSetDeleteOp should be a HashedSet.');
                return false;
            }
            for (const ref of this.deletedOps.values()) {
                const op = references.get(ref.hash);
                if (op === undefined) {
                    ReversibleSet.logger.warning('Addition op referenced in ReversibleSet deletion op is missing from references provided for validation.');
                }
                if (!(op instanceof ReversibleSetAddOp)) {
                    ReversibleSet.logger.warning('Addition op referenced in ReversibleSet deletion op has the wrong type in the references provided for validation.');
                    return false;
                }
                if (!((_a = op.targetObject) === null || _a === void 0 ? void 0 : _a.equals(this.targetObject))) {
                    ReversibleSet.logger.warning('Addition op referenced in ReversibleSet deletion op points to a different set.');
                    return false;
                }
                const addOp = op;
                if (((_b = addOp.element) === null || _b === void 0 ? void 0 : _b.hash()) !== this.elementHash) {
                    ReversibleSet.logger.warning('Addition op referenced in ReversibleSet deletion op contains an element whose hash does not match the one being deleted.');
                    return false;
                }
            }
            return true;
        }
        getClassName() {
            return ReversibleSetDeleteOp.className;
        }
    }
    ReversibleSetDeleteOp.className = 'hhs/v0/ReversibleSetDeleteOp';
    ReversibleSetDeleteOp.registerClass(ReversibleSetDeleteOp.className, ReversibleSetDeleteOp);
    class ReversibleSet extends MutableObject {
        constructor() {
            super(ReversibleSet.opClasses, true);
            this._logger = ReversibleSet.logger;
            this.setRandomId();
            this._elements = new Map();
            this._currentAddOpRefs = new MultiMap();
            this._currentDeleteOpRefs = new MultiMap();
            //this._unsavedAppliedOps = new Set();
        }
        init() {
        }
        async validate(references) {
            return Types.isTypeConstraint(this.typeConstraints);
        }
        async add(element, causalOps) {
            let op = new ReversibleSetAddOp(this, element, causalOps);
            await this.applyNewOp(op);
        }
        async delete(element, causalOps) {
            return await this.deleteByHash(element.hash(), causalOps);
        }
        async deleteByHash(hash, causalOps) {
            let addOpRefs = this._currentAddOpRefs.get(hash);
            if (addOpRefs !== undefined && addOpRefs.size > 0) {
                let toDelete = new Set();
                for (const hash of addOpRefs.values()) {
                    toDelete.add(new HashReference(hash, ReversibleSetAddOp.className));
                }
                let op = new ReversibleSetDeleteOp(this, hash, toDelete.values(), causalOps);
                await this.applyNewOp(op);
                return true;
            }
            else {
                return false;
            }
        }
        has(element) {
            return this.hasByHash(element.hash());
        }
        hasByHash(hash) {
            return this._elements.get(hash) !== undefined;
        }
        get(hash) {
            return this._elements.get(hash);
        }
        size() {
            return this._elements.size;
        }
        values() {
            return this._elements.values();
        }
        mutate(op) {
            return this.mutateWithInvalidation(op, true);
        }
        undo(op) {
            return this.mutateWithInvalidation(op, false);
        }
        redo(op) {
            return this.mutateWithInvalidation(op, true);
        }
        mutateWithInvalidation(op, valid) {
            //let mutated = false;
            let elmtHash;
            let wasPresent;
            let isPresent;
            if (op instanceof ReversibleSetAddOp) {
                const addOp = op;
                elmtHash = op.element.hash();
                wasPresent = this._currentAddOpRefs.hasKey(elmtHash);
                const addOpHash = op.hash();
                const canAdd = !this._currentDeleteOpRefs.hasKey(addOpHash);
                if (valid && canAdd) {
                    this._currentAddOpRefs.add(elmtHash, addOpHash);
                    this._elements.set(elmtHash, addOp.element);
                }
                isPresent = this._currentAddOpRefs.hasKey(elmtHash);
            }
            else if (op instanceof ReversibleSetDeleteOp) {
                const deleteOpHash = op.hash();
                elmtHash = op.elementHash;
                wasPresent = this._currentAddOpRefs.hasKey(elmtHash);
                for (const addOpRef of op.deletedOps.values()) {
                    const addOpHash = addOpRef.hash;
                    if (valid) {
                        this._currentDeleteOpRefs.add(addOpHash, deleteOpHash);
                    }
                    else {
                        this._currentDeleteOpRefs.delete(addOpHash, deleteOpHash);
                    }
                    if (this._currentDeleteOpRefs.hasKey(addOpHash)) {
                        this._currentAddOpRefs.delete(elmtHash, addOpHash);
                    }
                    else {
                        this._currentAddOpRefs.add(elmtHash, addOpHash);
                    }
                }
                isPresent = this._currentAddOpRefs.hasKey(elmtHash);
                if (!isPresent) {
                    this._elements.delete(elmtHash);
                }
            }
            else {
                throw new Error("Method not implemented.");
            }
            const mutated = wasPresent !== isPresent;
            if (mutated) {
                const elmt = this._elements.get(elmtHash);
                if (isPresent) {
                    if (this._addElementCallback !== undefined) {
                        try {
                            this._addElementCallback(elmt);
                        }
                        catch (e) {
                            this._logger.warning(() => ('Error calling ReversibleSet element addition callback on op ' + op.hash()));
                        }
                    }
                }
                else {
                    if (this._deleteElementCallback !== undefined) {
                        try {
                            this._deleteElementCallback(elmt);
                        }
                        catch (e) {
                            this._logger.warning(() => ('Error calling ReversibleSet element deletion callback on op ' + op.hash()));
                        }
                    }
                }
            }
            return Promise.resolve(mutated);
        }
        onAddition(callback) {
            this._addElementCallback = callback;
        }
        onDeletion(callback) {
            this._deleteElementCallback = callback;
        }
        getClassName() {
            return ReversibleSet.className;
        }
    }
    ReversibleSet.className = 'hss/v0/ReversibleSet';
    ReversibleSet.opClasses = [ReversibleSetAddOp.className, ReversibleSetDeleteOp.className];
    ReversibleSet.logger = new Logger(ReversibleSet.className, LogLevel.INFO);
    ReversibleSet.registerClass(ReversibleSet.className, ReversibleSet);

    class GrantCapabilityOp extends MutationOp {
        constructor(targetObject, grantee, capability) {
            super(targetObject);
            this.grantee = grantee;
            this.capability = capability;
        }
        async validate(references) {
            return await super.validate(references) && this.grantee !== undefined && this.capability !== undefined;
        }
        getClassName() {
            return GrantCapabilityOp.className;
        }
        init() {
        }
    }
    GrantCapabilityOp.className = 'hhs/v0/GrantCapabilityOp';
    class RevokeCapabilityAfterOp extends InvalidateAfterOp {
        constructor(grantOp, terminalOps) {
            super(grantOp, terminalOps);
        }
        async validate(references) {
            return await super.validate(references) && this.getTargetOp() instanceof GrantCapabilityOp;
        }
        getTargetOp() {
            return super.getTargetOp();
        }
        getClassName() {
            return RevokeCapabilityAfterOp.className;
        }
        init() {
        }
    }
    RevokeCapabilityAfterOp.className = 'hhs/v0/RevokeCapabilityAfterOp';
    class UseCapabilityOp extends MutationOp {
        constructor(grantOp, usageKey) {
            super(grantOp === null || grantOp === void 0 ? void 0 : grantOp.getTargetObject());
            if (grantOp !== undefined) {
                this.grantOp = grantOp;
                this.usageKey = usageKey;
                this.setAuthor(grantOp.grantee);
                this.setCausalOps([grantOp].values());
            }
        }
        getClassName() {
            return UseCapabilityOp.className;
        }
        init() {
        }
        async validate(references) {
            if (!await super.validate(references)) {
                return false;
            }
            if (this.getId() !== undefined) {
                return false;
            }
            const causalOps = this.causalOps;
            if (causalOps === undefined) {
                return false;
            }
            if (causalOps.size() !== 1) {
                return false;
            }
            const causalOp = causalOps.values().next().value;
            if (causalOp === undefined) {
                return false;
            }
            if (!(causalOp instanceof GrantCapabilityOp)) {
                return false;
            }
            if (!(causalOp.getTargetObject().equals(this.getTargetObject()))) {
                return false;
            }
            if (!(causalOp.grantee !== undefined && causalOp.grantee.equals(this.getAuthor()))) {
                return false;
            }
            if (this.grantOp === undefined || !(this.grantOp instanceof GrantCapabilityOp)) {
                return false;
            }
            if (!this.grantOp.equals(causalOp)) {
                return false;
            }
            return true;
        }
    }
    UseCapabilityOp.className = 'hhs/v0/UseCapabilityOp';
    class AbstractCapabilitySet extends MutableObject {
        constructor() {
            super(AbstractCapabilitySet.opClasses, true);
            this.setRandomId();
            this._grants = new MultiMap();
            this._revokes = new MultiMap();
            this._grantOps = new Map();
        }
        init() {
        }
        async mutate(op, valid, cascade) {
            let mutated = false;
            if (valid && !cascade) {
                if (op instanceof GrantCapabilityOp) {
                    const key = AbstractCapabilitySet.getGranteeCapabilityKeyForOp(op);
                    const hash = op.hash();
                    this._grants.add(key, hash);
                    this._grantOps.set(hash, op);
                }
                else if (op instanceof RevokeCapabilityAfterOp) {
                    const grantOp = op.getTargetOp();
                    this._revokes.add(grantOp.hash(), op.hash());
                }
            }
            return mutated;
        }
        async validate(references) {
            return true;
        }
        hasCapability(grantee, capability) {
            let result = false;
            for (const grantHash of this._grants.get(AbstractCapabilitySet.getGranteeCapabilityKey(grantee, capability))) {
                if (this.isValidOp(grantHash)) {
                    let revoked = false;
                    for (const revokeHash of this._revokes.get(grantHash)) {
                        if (this.isValidOp(revokeHash)) {
                            revoked = true;
                        }
                    }
                    if (!revoked) {
                        result = true;
                        break;
                    }
                }
            }
            return result;
        }
        useCapability(grantee, capability, usageKey) {
            let useOp = this.useCapabilityIfAvailable(grantee, capability, usageKey);
            if (useOp === undefined) {
                throw new Error(grantee + ' is trying to use capability ' + capability + ', but it is not available.');
            }
            return useOp;
        }
        useCapabilityIfAvailable(grantee, capability, usageKey) {
            let useOp = undefined;
            const grantOp = this.findValidGrant(grantee, capability);
            if (grantOp !== undefined) {
                useOp = new UseCapabilityOp(grantOp, usageKey);
                useOp.setAuthor(grantee);
                this.applyNewOp(useOp);
            }
            return useOp;
        }
        useCapabilityForOp(grantee, capability, op) {
            const usageKey = op.nonCausalHash();
            const useOp = this.useCapability(grantee, capability, usageKey);
            op.addCausalOp(useOp);
            return useOp;
        }
        useCapabilityForOpIfAvailable(grantee, capability, op) {
            const usageKey = op.nonCausalHash();
            const useOp = this.useCapabilityIfAvailable(grantee, capability, usageKey);
            if (useOp !== undefined) {
                op.addCausalOp(useOp);
                return useOp;
            }
            else {
                return undefined;
            }
        }
        checkCapabilityForOp(useOp, capability, op, grantee) {
            var _a;
            const usageKey = op.nonCausalHash();
            if (useOp.usageKey !== usageKey) {
                return false;
            }
            if (((_a = useOp.grantOp) === null || _a === void 0 ? void 0 : _a.capability) !== capability) {
                return false;
            }
            if (!op.hasCausalOps() || !op.getCausalOps().has(useOp)) {
                return false;
            }
            if (grantee !== undefined && !grantee.equals(useOp.getAuthor())) {
                return false;
            }
            return true;
        }
        isCapabilityUseForOp(op, useOp) {
            return useOp.usageKey === op.nonCausalHash();
        }
        findValidGrant(grantee, capability) {
            let chosenGrantOp = undefined;
            let chosenGrantOpHash = undefined;
            for (const grantOpHash of this._grants.get(AbstractCapabilitySet.getGranteeCapabilityKey(grantee, capability))) {
                if (this.isValidOp(grantOpHash)) {
                    let revoked = false;
                    for (const revokeHash of this._revokes.get(grantOpHash)) {
                        if (this.isValidOp(revokeHash)) {
                            revoked = true;
                        }
                    }
                    if (!revoked) {
                        if (chosenGrantOpHash === undefined || grantOpHash.localeCompare(chosenGrantOpHash) < 0) {
                            chosenGrantOpHash = grantOpHash;
                            chosenGrantOp = this._grantOps.get(grantOpHash);
                        }
                    }
                }
            }
            return chosenGrantOp;
        }
        findAllValidGrants(grantee, capability) {
            const all = new Map();
            for (const grantOpHash of this._grants.get(AbstractCapabilitySet.getGranteeCapabilityKey(grantee, capability))) {
                if (this.isValidOp(grantOpHash)) {
                    let revoked = false;
                    for (const revokeHash of this._revokes.get(grantOpHash)) {
                        if (this.isValidOp(revokeHash)) {
                            revoked = true;
                        }
                    }
                    if (!revoked) {
                        all.set(grantOpHash, this._grantOps.get(grantOpHash));
                    }
                }
            }
            return all;
        }
        static getGranteeCapabilityKeyForOp(op) {
            let revoke = false;
            if (op instanceof RevokeCapabilityAfterOp) {
                op = op.getTargetOp();
                revoke = true;
            }
            return AbstractCapabilitySet.getGranteeCapabilityKey(op.grantee, op.capability, revoke);
        }
        static getGranteeCapabilityKey(grantee, capability, revoke = false) {
            return (revoke ? 'revoke' : 'grant') + '-' + grantee.hash().replace(/-/g, '--') + '-' + capability.replace(/-/g, '--');
        }
    }
    AbstractCapabilitySet.opClasses = [GrantCapabilityOp.className, RevokeCapabilityAfterOp.className, UseCapabilityOp.className];
    HashedObject.registerClass(GrantCapabilityOp.className, GrantCapabilityOp);
    HashedObject.registerClass(RevokeCapabilityAfterOp.className, RevokeCapabilityAfterOp);
    HashedObject.registerClass(UseCapabilityOp.className, UseCapabilityOp);

    class EnableFeatureOp extends MutationOp {
        constructor(target, featureName) {
            super(target);
            if (featureName !== undefined) {
                this.featureName = featureName;
            }
        }
        init() {
        }
        async validate(references) {
            if (!(await super.validate(references))) {
                return false;
            }
            const target = this.getTargetObject();
            if (!(target instanceof AbstractFeatureSet)) {
                return false;
            }
            if (this.featureName === undefined || !target.getFeatureNames().has(this.featureName)) {
                return false;
            }
            if (this.hasCausalOps() && this.hasId()) {
                return false;
            }
            /*
            if (this.getCausalOps()?.size() !== 1) {
                return false;
            }

            const causalOpRef = this.getCausalOps().values().next().value as HashReference<MutationOp>;
            const causalOp = references.get(causalOpRef.hash);

            if (!(causalOp instanceof UseOp)) {
                return false;
            }

            if (this.getUsageKey() !== causalOp )
            */
            return true;
        }
        getClassName() {
            return EnableFeatureOp.className;
        }
    }
    EnableFeatureOp.className = 'hhs/v0/EnableFeatureOp';
    class DisableFeatureAfterOp extends InvalidateAfterOp {
        constructor(targetOp, terminalOps) {
            super(targetOp, terminalOps);
        }
        async validate(references) {
            var _a;
            if (!await super.validate(references)) {
                return false;
            }
            if (!(this.getTargetOp() instanceof EnableFeatureOp)) {
                return false;
            }
            if (!((_a = this.getTargetOp().getTargetObject()) === null || _a === void 0 ? void 0 : _a.equals(this.getTargetObject()))) {
                return false;
            }
            if (this.hasCausalOps() && this.hasId()) {
                return false;
            }
            return true;
        }
        getTargetOp() {
            return super.getTargetOp();
        }
        getClassName() {
            return DisableFeatureAfterOp.className;
        }
    }
    DisableFeatureAfterOp.className = 'hhs/v0/DisableFeatureAfterOp';
    class UseFeatureOp extends MutationOp {
        constructor(enableOp, usageKey) {
            super(enableOp === null || enableOp === void 0 ? void 0 : enableOp.getTargetObject());
            if (enableOp !== undefined) {
                this.enableOp = enableOp;
                this.usageKey = usageKey;
                this.setCausalOps([enableOp].values());
            }
        }
        async validate(references) {
            if (!await super.validate(references)) {
                return false;
            }
            const causalOps = this.causalOps;
            if (causalOps === undefined) {
                return false;
            }
            if (causalOps.size() !== 1) {
                return false;
            }
            const causalOp = causalOps.values().next().value;
            if (causalOp === undefined) {
                return false;
            }
            if (!(causalOp instanceof EnableFeatureOp)) {
                return false;
            }
            if (!(causalOp.getTargetObject().equals(this.getTargetObject()))) {
                return false;
            }
            if (this.enableOp === undefined || !(this.enableOp instanceof EnableFeatureOp)) {
                return false;
            }
            if (!this.enableOp.equals(causalOp)) {
                return false;
            }
            return true;
        }
        init() {
        }
        getClassName() {
            return UseFeatureOp.className;
        }
    }
    UseFeatureOp.className = 'hhs/v0/UseFeatureOp';
    class AbstractFeatureSet extends MutableObject {
        constructor(featureNames) {
            super(AbstractFeatureSet.opClasses, true);
            if (featureNames !== undefined) {
                this.featureNames = new HashedSet(featureNames);
            }
            this._allValidEnableOps = new Map();
            this._validEnableOpsPerFeature = new MultiMap();
        }
        init() {
        }
        useFeatureIfEnabled(featureName, usageKey, usingIdentity) {
            const validEnableOp = this.findValidEnableOp(featureName);
            let useOp = undefined;
            if (validEnableOp !== undefined) {
                const useOp = new UseFeatureOp(validEnableOp, usageKey);
                if (usingIdentity !== undefined) {
                    useOp.setAuthor(usingIdentity);
                }
                this.applyNewOp(useOp);
                return useOp;
            }
            return useOp;
        }
        useFeature(featureName, usageKey, usingIdentity) {
            const useOp = this.useFeatureIfEnabled(featureName, usageKey, usingIdentity);
            if (useOp === undefined) {
                throw new Error('Trying to use BooleanFeature ' + this.hash() + ', but it is currently disabled.');
            }
            return useOp;
        }
        findValidEnableOp(featureName) {
            for (const validEnableOpHash of this._validEnableOpsPerFeature.get(featureName).values()) {
                return this._allValidEnableOps.get(validEnableOpHash);
            }
            return undefined;
        }
        mutate(op) {
            let mutated = false;
            let enableOp;
            let featureName;
            if (op instanceof EnableFeatureOp) {
                enableOp = op;
                featureName = op.featureName;
            }
            else if (op instanceof DisableFeatureAfterOp) {
                enableOp = op.targetOp;
                featureName = op.targetOp.featureName;
            }
            if (enableOp !== undefined && featureName !== undefined) {
                const enableOpHash = enableOp.hash();
                const wasEnabled = this.isEnabled(featureName);
                if (this.isValidOp(enableOpHash)) {
                    this._allValidEnableOps.set(enableOpHash, enableOp);
                    this._validEnableOpsPerFeature.add(featureName, enableOpHash);
                }
                else {
                    this._allValidEnableOps.delete(enableOpHash);
                    this._validEnableOpsPerFeature.delete(featureName, enableOpHash);
                }
                mutated = wasEnabled === this.isEnabled(featureName);
            }
            return Promise.resolve(mutated);
        }
        async validate(references) {
            if (this.featureNames === undefined) {
                return false;
            }
            if (!(this.featureNames instanceof HashedSet)) {
                return false;
            }
            for (const featureName of this.featureNames.values()) {
                if (typeof (featureName) !== 'string') {
                    return false;
                }
            }
            // TODO: check that there are no superfluous fields to prevent malleability
            return true;
        }
        getFeatureNames() {
            if (this.featureNames === undefined) {
                throw new Error('FeatureSet ' + this.hash() + ' is missing its set of feature names.');
            }
            return this.featureNames;
        }
        isEnabled(feature) {
            const featureEnableOps = this._validEnableOpsPerFeature.get(feature);
            return featureEnableOps !== undefined && featureEnableOps.size > 0;
        }
    }
    AbstractFeatureSet.opClasses = [EnableFeatureOp.className, DisableFeatureAfterOp.className, UseFeatureOp.className];
    HashedObject.registerClass(EnableFeatureOp.className, EnableFeatureOp);
    HashedObject.registerClass(DisableFeatureAfterOp.className, DisableFeatureAfterOp);
    HashedObject.registerClass(UseFeatureOp.className, UseFeatureOp);

    const instanceOfAny = (object, constructors) => constructors.some((c) => object instanceof c);

    let idbProxyableTypes;
    let cursorAdvanceMethods;
    // This is a function to prevent it throwing up in node environments.
    function getIdbProxyableTypes() {
        return (idbProxyableTypes ||
            (idbProxyableTypes = [
                IDBDatabase,
                IDBObjectStore,
                IDBIndex,
                IDBCursor,
                IDBTransaction,
            ]));
    }
    // This is a function to prevent it throwing up in node environments.
    function getCursorAdvanceMethods() {
        return (cursorAdvanceMethods ||
            (cursorAdvanceMethods = [
                IDBCursor.prototype.advance,
                IDBCursor.prototype.continue,
                IDBCursor.prototype.continuePrimaryKey,
            ]));
    }
    const cursorRequestMap = new WeakMap();
    const transactionDoneMap = new WeakMap();
    const transactionStoreNamesMap = new WeakMap();
    const transformCache = new WeakMap();
    const reverseTransformCache = new WeakMap();
    function promisifyRequest(request) {
        const promise = new Promise((resolve, reject) => {
            const unlisten = () => {
                request.removeEventListener('success', success);
                request.removeEventListener('error', error);
            };
            const success = () => {
                resolve(wrap(request.result));
                unlisten();
            };
            const error = () => {
                reject(request.error);
                unlisten();
            };
            request.addEventListener('success', success);
            request.addEventListener('error', error);
        });
        promise
            .then((value) => {
            // Since cursoring reuses the IDBRequest (*sigh*), we cache it for later retrieval
            // (see wrapFunction).
            if (value instanceof IDBCursor) {
                cursorRequestMap.set(value, request);
            }
            // Catching to avoid "Uncaught Promise exceptions"
        })
            .catch(() => { });
        // This mapping exists in reverseTransformCache but doesn't doesn't exist in transformCache. This
        // is because we create many promises from a single IDBRequest.
        reverseTransformCache.set(promise, request);
        return promise;
    }
    function cacheDonePromiseForTransaction(tx) {
        // Early bail if we've already created a done promise for this transaction.
        if (transactionDoneMap.has(tx))
            return;
        const done = new Promise((resolve, reject) => {
            const unlisten = () => {
                tx.removeEventListener('complete', complete);
                tx.removeEventListener('error', error);
                tx.removeEventListener('abort', error);
            };
            const complete = () => {
                resolve();
                unlisten();
            };
            const error = () => {
                reject(tx.error || new DOMException('AbortError', 'AbortError'));
                unlisten();
            };
            tx.addEventListener('complete', complete);
            tx.addEventListener('error', error);
            tx.addEventListener('abort', error);
        });
        // Cache it for later retrieval.
        transactionDoneMap.set(tx, done);
    }
    let idbProxyTraps = {
        get(target, prop, receiver) {
            if (target instanceof IDBTransaction) {
                // Special handling for transaction.done.
                if (prop === 'done')
                    return transactionDoneMap.get(target);
                // Polyfill for objectStoreNames because of Edge.
                if (prop === 'objectStoreNames') {
                    return target.objectStoreNames || transactionStoreNamesMap.get(target);
                }
                // Make tx.store return the only store in the transaction, or undefined if there are many.
                if (prop === 'store') {
                    return receiver.objectStoreNames[1]
                        ? undefined
                        : receiver.objectStore(receiver.objectStoreNames[0]);
                }
            }
            // Else transform whatever we get back.
            return wrap(target[prop]);
        },
        set(target, prop, value) {
            target[prop] = value;
            return true;
        },
        has(target, prop) {
            if (target instanceof IDBTransaction &&
                (prop === 'done' || prop === 'store')) {
                return true;
            }
            return prop in target;
        },
    };
    function replaceTraps(callback) {
        idbProxyTraps = callback(idbProxyTraps);
    }
    function wrapFunction(func) {
        // Due to expected object equality (which is enforced by the caching in `wrap`), we
        // only create one new func per func.
        // Edge doesn't support objectStoreNames (booo), so we polyfill it here.
        if (func === IDBDatabase.prototype.transaction &&
            !('objectStoreNames' in IDBTransaction.prototype)) {
            return function (storeNames, ...args) {
                const tx = func.call(unwrap(this), storeNames, ...args);
                transactionStoreNamesMap.set(tx, storeNames.sort ? storeNames.sort() : [storeNames]);
                return wrap(tx);
            };
        }
        // Cursor methods are special, as the behaviour is a little more different to standard IDB. In
        // IDB, you advance the cursor and wait for a new 'success' on the IDBRequest that gave you the
        // cursor. It's kinda like a promise that can resolve with many values. That doesn't make sense
        // with real promises, so each advance methods returns a new promise for the cursor object, or
        // undefined if the end of the cursor has been reached.
        if (getCursorAdvanceMethods().includes(func)) {
            return function (...args) {
                // Calling the original function with the proxy as 'this' causes ILLEGAL INVOCATION, so we use
                // the original object.
                func.apply(unwrap(this), args);
                return wrap(cursorRequestMap.get(this));
            };
        }
        return function (...args) {
            // Calling the original function with the proxy as 'this' causes ILLEGAL INVOCATION, so we use
            // the original object.
            return wrap(func.apply(unwrap(this), args));
        };
    }
    function transformCachableValue(value) {
        if (typeof value === 'function')
            return wrapFunction(value);
        // This doesn't return, it just creates a 'done' promise for the transaction,
        // which is later returned for transaction.done (see idbObjectHandler).
        if (value instanceof IDBTransaction)
            cacheDonePromiseForTransaction(value);
        if (instanceOfAny(value, getIdbProxyableTypes()))
            return new Proxy(value, idbProxyTraps);
        // Return the same value back if we're not going to transform it.
        return value;
    }
    function wrap(value) {
        // We sometimes generate multiple promises from a single IDBRequest (eg when cursoring), because
        // IDB is weird and a single IDBRequest can yield many responses, so these can't be cached.
        if (value instanceof IDBRequest)
            return promisifyRequest(value);
        // If we've already transformed this value before, reuse the transformed value.
        // This is faster, but it also provides object equality.
        if (transformCache.has(value))
            return transformCache.get(value);
        const newValue = transformCachableValue(value);
        // Not all types are transformed.
        // These may be primitive types, so they can't be WeakMap keys.
        if (newValue !== value) {
            transformCache.set(value, newValue);
            reverseTransformCache.set(newValue, value);
        }
        return newValue;
    }
    const unwrap = (value) => reverseTransformCache.get(value);

    /**
     * Open a database.
     *
     * @param name Name of the database.
     * @param version Schema version.
     * @param callbacks Additional callbacks.
     */
    function openDB(name, version, { blocked, upgrade, blocking, terminated } = {}) {
        const request = indexedDB.open(name, version);
        const openPromise = wrap(request);
        if (upgrade) {
            request.addEventListener('upgradeneeded', (event) => {
                upgrade(wrap(request.result), event.oldVersion, event.newVersion, wrap(request.transaction));
            });
        }
        if (blocked)
            request.addEventListener('blocked', () => blocked());
        openPromise
            .then((db) => {
            if (terminated)
                db.addEventListener('close', () => terminated());
            if (blocking)
                db.addEventListener('versionchange', () => blocking());
        })
            .catch(() => { });
        return openPromise;
    }

    const readMethods = ['get', 'getKey', 'getAll', 'getAllKeys', 'count'];
    const writeMethods = ['put', 'add', 'delete', 'clear'];
    const cachedMethods = new Map();
    function getMethod(target, prop) {
        if (!(target instanceof IDBDatabase &&
            !(prop in target) &&
            typeof prop === 'string')) {
            return;
        }
        if (cachedMethods.get(prop))
            return cachedMethods.get(prop);
        const targetFuncName = prop.replace(/FromIndex$/, '');
        const useIndex = prop !== targetFuncName;
        const isWrite = writeMethods.includes(targetFuncName);
        if (
        // Bail if the target doesn't exist on the target. Eg, getAll isn't in Edge.
        !(targetFuncName in (useIndex ? IDBIndex : IDBObjectStore).prototype) ||
            !(isWrite || readMethods.includes(targetFuncName))) {
            return;
        }
        const method = async function (storeName, ...args) {
            // isWrite ? 'readwrite' : undefined gzipps better, but fails in Edge :(
            const tx = this.transaction(storeName, isWrite ? 'readwrite' : 'readonly');
            let target = tx.store;
            if (useIndex)
                target = target.index(args.shift());
            const returnVal = await target[targetFuncName](...args);
            if (isWrite)
                await tx.done;
            return returnVal;
        };
        cachedMethods.set(prop, method);
        return method;
    }
    replaceTraps((oldTraps) => ({
        ...oldTraps,
        get: (target, prop, receiver) => getMethod(target, prop) || oldTraps.get(target, prop, receiver),
        has: (target, prop) => !!getMethod(target, prop) || oldTraps.has(target, prop),
    }));

    class Store {
        constructor(backend) {
            this.backend = backend;
            this.backend.setStoredObjectCallback(async (literal) => {
                await this.fireCallbacks(literal);
            });
            this.classCallbacks = new MultiMap();
            this.referencesCallbacks = new MultiMap();
            this.classReferencesCallbacks = new MultiMap();
        }
        static registerBackend(name, loader) {
            Store.backendLoaders.set(name, loader);
        }
        static load(backendName, dbName) {
            const loader = Store.backendLoaders.get(backendName);
            if (loader === undefined) {
                return undefined;
            }
            else {
                return new Store(loader(dbName));
            }
        }
        // save: The saving of operations is not recursive.
        //
        //                         If an operation is itself mutable, you need to call save() again
        //       (* note 1)        on the operation if you want its mutations flushed to the database
        //                         as well. (All mutable dependencies are flushed if required - this
        //                         applies only to their mutation ops)
        setResources(resources) {
            this.resources = resources;
        }
        getResources() {
            return this.resources;
        }
        async save(object, flushMutations = true) {
            let context = object.toContext();
            let hash = context.rootHashes[0];
            let missing = await this.findMissingReferencesWithContext(hash, context);
            if (missing.size > 0) {
                Store.operationLog.debug(() => 'Cannot save ' + hash + ' (a ' + object.getClassName() + ') because the following references are missing: ' + Array.from(missing).join(', ') + '.');
                throw new Error('Cannot save object ' + hash + ' (a ' + object.getClassName() + ') because the following references are missing: ' + Array.from(missing).join(', ') + '.');
            }
            Store.operationLog.debug(() => 'Saving object with hash ' + hash + ' .');
            await this.saveWithContext(hash, context);
            // The following is necessary in case the object (or a subobject) was already in the store,
            // and hence saveWithContext didn't visit all subobjects setting hashes and stores.
            for (const [ctxHash, ctxObject] of context.objects.entries()) {
                ctxObject.setLastHash(ctxHash);
                ctxObject.setStore(this);
            }
            if (flushMutations) {
                if (object instanceof MutableObject) {
                    let queuedOps = await object.saveQueuedOps(); // see (* note 1) above
                    if (queuedOps) {
                        Store.operationLog.debug(() => 'Saved queued ops for object with hash ' + hash + ' .');
                    }
                }
                const literal = context.literals.get(hash);
                if (literal !== undefined) {
                    for (let dependency of literal.dependencies) {
                        if (dependency.type === 'literal') {
                            const depObject = context.objects.get(dependency.hash);
                            if (depObject !== undefined && depObject instanceof MutableObject) {
                                let queuedOps = await depObject.saveQueuedOps(); // see (* note 1) above
                                if (queuedOps) {
                                    Store.operationLog.debug('Saved queued ops for object with hash ' + hash + ' .');
                                }
                            }
                        }
                    }
                }
            }
        }
        async findMissingReferencesWithContext(hash, context, expectedClassName) {
            let literal = context.literals.get(hash);
            if (literal === undefined) {
                return new Set([hash]);
            }
            if (expectedClassName !== undefined && literal.value['_class'] !== expectedClassName) {
                throw new Error('Referenced dependency ' + hash + ' was found in the store with type ' + literal.value['_class'] + ' but was declared as being ' + expectedClassName + '.');
            }
            let missing = new Set();
            for (let dependency of literal.dependencies) {
                let depHash = dependency.hash;
                let dep = context.literals.get(depHash);
                if (dep === undefined) {
                    let storedDep = await this.load(depHash);
                    if (storedDep === undefined) {
                        missing.add(depHash);
                    }
                    else {
                        if (storedDep.getClassName() !== dependency.className) {
                            throw new Error('Referenced dependency ' + dependency.hash + ' was found in the store with type ' + storedDep.getClassName() + ' but was declared as being ' + dependency.className + ' on path ' + dependency.path + '.');
                        }
                    }
                }
                else {
                    let depMissing = await this.findMissingReferencesWithContext(dependency.hash, context, dependency.className);
                    for (const missingHash of depMissing) {
                        missing.add(missingHash);
                    }
                }
            }
            return missing;
        }
        // low level save: no mutation flush, no hash/store setting in objects
        async saveWithContext(hash, context) {
            const object = context.objects.get(hash);
            if (object === undefined) {
                throw new Error('Object with hash ' + hash + ' is missing from context, cannot save it.');
            }
            object.setStore(this);
            object.setLastHash(hash);
            const author = object.getAuthor();
            if (author !== undefined) {
                if (object.shouldSignOnSave()) {
                    object.setLastSignature(await author.sign(hash));
                    context.literals.get(hash).signature = object.getLastSignature();
                }
                if (!object.hasLastSignature()) {
                    throw new Error('Cannot save ' + hash + ', its signature is missing');
                }
            }
            const loaded = await this.load(hash);
            if (loaded === undefined) {
                const literal = context.literals.get(hash);
                if (literal === undefined) {
                    throw new Error('Trying to save ' + hash + ', but its literal is missing from the received context.');
                }
                if (literal !== undefined) {
                    for (let dependency of literal.dependencies) {
                        if (dependency.type === 'literal') {
                            await this.saveWithContext(dependency.hash, context);
                        }
                    }
                }
                let history = undefined;
                if (object instanceof MutationOp) {
                    const prevOpHeaders = new Map();
                    if (object.prevOps !== undefined) {
                        for (const hashRef of object.prevOps.values()) {
                            const prevOpHistory = await this.loadOpHeader(hashRef.hash);
                            if (prevOpHistory === undefined) {
                                throw new Error('Header of prevOp ' + hashRef.hash + ' of op ' + hash + ' is missing from store, cannot save');
                            }
                            prevOpHeaders.set(hashRef.hash, prevOpHistory);
                        }
                    }
                    const opHistory = new OpHeader(object, prevOpHeaders);
                    history = {
                        literal: opHistory.literalize()
                    };
                }
                await this.backend.store(literal, history);
                if (object instanceof MutationOp) {
                    if (object.causalOps !== undefined) {
                        // If any of the causal ops has been invalidated, check if we should cascade
                        for (const causalOp of object.causalOps.values()) {
                            const invalidations = await this.loadAllInvalidations(causalOp.getLastHash());
                            for (const inv of invalidations) {
                                // Note1: Since the invAfterOp was already saved and this op was not (loaded === undefined above)
                                //        we can be sure that object is outside of invAfterOp.terminalOps.
                                // Note2: invAfterOp only affects causal relationships within the same MutableObject (otherwise 
                                //        terminalOps is meaningless).
                                const shouldInv = inv instanceof InvalidateAfterOp && inv.getTargetObject().equals(object.getTargetObject());
                                const shouldCasc = inv instanceof CascadedInvalidateOp;
                                if (shouldInv || shouldCasc) {
                                    const casc = CascadedInvalidateOp.create(object, inv);
                                    casc.toContext(context);
                                    await this.saveWithContext(casc.getLastHash(), context);
                                }
                            }
                        }
                    }
                }
                if (object instanceof InvalidateAfterOp || object instanceof CascadedInvalidateOp) {
                    const consequences = await this.loadAllConsequences(object.getTargetOp().hash());
                    if (object instanceof InvalidateAfterOp) {
                        const validConsequences = await this.loadPrevOpsClosure(object.getTerminalOps());
                        for (const conseqOp of consequences.values()) {
                            if (!validConsequences.has(conseqOp.getLastHash())) {
                                const casc = CascadedInvalidateOp.create(conseqOp, object);
                                casc.toContext(context);
                                await this.saveWithContext(casc.getLastHash(), context);
                            }
                        }
                    }
                    else if (object instanceof CascadedInvalidateOp) {
                        for (const conseqOp of consequences.values()) {
                            const casc = CascadedInvalidateOp.create(conseqOp, object);
                            casc.toContext(context);
                            await this.saveWithContext(casc.getLastHash(), context);
                        }
                    }
                }
            }
        }
        async fireCallbacks(literal) {
            // fire watched classes callbacks
            for (const key of this.classCallbacks.keys()) {
                let className = Store.classForkey(key);
                if (literal.value['_class'] === className) {
                    for (const callback of this.classCallbacks.get(key)) {
                        await callback(literal.hash);
                    }
                }
            }
            // fire watched references callbacks
            for (const key of this.referencesCallbacks.keys()) {
                let reference = Store.referenceForKey(key);
                for (const dep of literal.dependencies) {
                    if (dep.path === reference.path && dep.hash === reference.hash) {
                        for (const callback of this.referencesCallbacks.get(key)) {
                            await callback(literal.hash);
                        }
                    }
                }
            }
            // fire watched class+reference pair callbacks
            for (const key of this.classReferencesCallbacks.keys()) {
                let classReference = Store.classReferenceForKey(key);
                if (classReference.className === literal.value['_class']) {
                    for (const dep of literal.dependencies) {
                        if (dep.path === classReference.path && dep.hash === dep.hash) {
                            for (const callback of this.classReferencesCallbacks.get(key)) {
                                await callback(literal.hash);
                            }
                        }
                    }
                }
            }
        }
        async loadLiteral(hash) {
            return this.backend.load(hash);
        }
        async loadRef(ref) {
            let obj = await this.load(ref.hash);
            if (obj !== undefined && ref.className !== obj.getClassName()) {
                throw new Error('Error loading reference to ' + ref.className + ': object with hash ' + ref.hash + ' has class ' + obj.getClassName() + ' instead.');
            }
            return obj;
        }
        async load(hash) {
            let context = new Context();
            context.resources = this.resources;
            return this.loadWithContext(hash, context);
        }
        async loadWithContext(hash, context) {
            var _a, _b;
            let obj = context.objects.get(hash);
            if (obj === undefined) {
                // load object's literal and its dependencies' literals into the context, if necessary
                let literal = context.literals.get(hash);
                if (literal === undefined) {
                    literal = await this.loadLiteral(hash);
                    if (literal === undefined) {
                        return undefined;
                    }
                    context.literals.set(literal.hash, literal);
                }
                for (let dependency of literal.dependencies) {
                    if (dependency.type === 'literal') {
                        if (((_b = (_a = context.resources) === null || _a === void 0 ? void 0 : _a.aliasing) === null || _b === void 0 ? void 0 : _b.get(dependency.hash)) === undefined &&
                            context.objects.get(dependency.hash) === undefined &&
                            context.literals.get(dependency.hash) === undefined) {
                            // NO NEED to this.loadLiteralWithContext(depLiteral as Literal, context)
                            // because all transitive deps are in object deps.
                            let depLiteral = await this.loadLiteral(dependency.hash);
                            context.literals.set(dependency.hash, depLiteral);
                        }
                    }
                }
                // use the context to create the object from all the loaded literals
                obj = HashedObject.fromContext(context, literal.hash);
                for (const ctxObj of context.objects.values()) {
                    if (!ctxObj.hasStore()) {
                        ctxObj.setStore(this);
                    }
                    if (ctxObj instanceof Identity) {
                        const id = ctxObj;
                        if (!id.hasKeyPair()) {
                            let kp = await this.load(id.getKeyPairHash());
                            if (kp !== undefined && kp instanceof RSAKeyPair) {
                                id.addKeyPair(kp);
                            }
                        }
                    }
                }
            }
            return obj;
        }
        async loadByClass(className, params) {
            let searchResults = await this.backend.searchByClass(className, params);
            return this.loadSearchResults(searchResults);
        }
        async loadByReference(referringPath, referencedHash, params) {
            let searchResults = await this.backend.searchByReference(referringPath, referencedHash, params);
            return this.loadSearchResults(searchResults);
        }
        async loadByReferencingClass(referringClassName, referringPath, referencedHash, params) {
            let searchResults = await this.backend.searchByReferencingClass(referringClassName, referringPath, referencedHash, params);
            return this.loadSearchResults(searchResults);
        }
        async loadOpHeader(opHash) {
            const stored = await this.backend.loadOpHeader(opHash);
            if (stored === undefined) {
                return undefined;
            }
            else {
                return new OpHeader(stored.literal);
            }
        }
        async loadOpHeaderByHeaderHash(headerHash) {
            const stored = await this.backend.loadOpHeaderByHeaderHash(headerHash);
            if (stored === undefined) {
                return undefined;
            }
            else {
                return new OpHeader(stored.literal);
            }
        }
        /*private async loadLiteral(hash: Hash) : Promise<Literal | undefined> {

            let packed = await this.backend.load(hash);
            
            if (packed === undefined) {
                return undefined;
            } else {

                return this.unpackLiteral(packed);
            }
           
        }*/
        /*private unpackLiteral(packed: PackedLiteral) : Literal {
            let literal = {} as Literal;

            literal.hash = packed.hash;
            literal.value = packed.value;
            literal.dependencies = new Set<Dependency>(packed.dependencies);
            if (packed.author !== undefined) {
                literal.author = packed.author;
            }
            literal.value['_flags'] = packed.flags;

            return literal;
        }*/
        async loadSearchResults(searchResults) {
            let context = new Context();
            let objects = [];
            for (let literal of searchResults.items) {
                context.literals.set(literal.hash, literal);
                let obj = await this.loadWithContext(literal.hash, context);
                objects.push(obj);
            }
            return { objects: objects, start: searchResults.start, end: searchResults.end };
        }
        async loadTerminalOpsForMutable(hash) {
            let info = await this.backend.loadTerminalOpsForMutable(hash);
            return info;
        }
        async loadPrevOpsClosure(init) {
            const initHashes = new Set(Array.from(init.values()).map((ref) => ref.hash));
            return this.loadClosure(initHashes, Store.extractPrevOps);
        }
        async loadClosure(init, next) {
            let closure = new Set();
            let pending = new Set(init);
            while (pending.size > 0) {
                let { done, value } = pending.values().next();
                pending.delete(value);
                closure.add(value);
                let obj = await this.load(value);
                let children = next(obj);
                for (const hash of children.values()) {
                    if (!closure.has(hash)) {
                        pending.add(hash);
                    }
                }
            }
            return closure;
        }
        watchClass(className, callback) {
            const key = Store.keyForClass(className);
            this.classCallbacks.add(key, callback);
        }
        watchReferences(referringPath, referencedHash, callback) {
            const key = Store.keyForReference(referringPath, referencedHash);
            this.referencesCallbacks.add(key, callback);
        }
        watchClassReferences(referringClassName, referringPath, referencedHash, callback) {
            const key = Store.keyForClassReference(referringClassName, referringPath, referencedHash);
            this.classReferencesCallbacks.add(key, callback);
        }
        removeClassWatch(className, callback) {
            const key = Store.keyForClass(className);
            return this.classCallbacks.delete(key, callback);
        }
        removeReferencesWatch(referringPath, referencedHash, callback) {
            const key = Store.keyForReference(referringPath, referencedHash);
            return this.referencesCallbacks.delete(key, callback);
        }
        removeClassReferencesWatch(referringClassName, referringPath, referencedHash, callback) {
            const key = Store.keyForClassReference(referringClassName, referringPath, referencedHash);
            return this.classReferencesCallbacks.delete(key, callback);
        }
        getName() {
            return this.backend.getName();
        }
        getBackendName() {
            return this.backend.getBackendName();
        }
        static keyForClass(className) {
            return className;
        }
        static keyForReference(referringPath, referencedHash) {
            return referringPath + '#' + referencedHash;
        }
        static keyForClassReference(referringClassName, referringPath, referencedHash) {
            return referringClassName + '->' + referringPath + '#' + referencedHash;
        }
        static classForkey(key) {
            return key;
        }
        static referenceForKey(key) {
            let parts = key.split('#');
            return { path: parts[0], hash: parts[1] };
        }
        static classReferenceForKey(key) {
            let parts = key.split('->');
            let className = parts[0];
            let result = Store.referenceForKey(parts[1]);
            result['className'] = className;
            return result;
        }
        async loadAllOps(targetObject, batchSize = 128) {
            const ops = new Array();
            let results = await this.loadByReference('targetObject', targetObject, {
                order: 'asc',
                limit: batchSize
            });
            while (results.objects.length > 0) {
                for (const obj of results.objects) {
                    if (obj instanceof MutationOp) {
                        ops.push(obj);
                    }
                }
                results = await this.loadByReference('targetObject', targetObject, {
                    order: 'asc',
                    limit: batchSize,
                    start: results.end
                });
            }
            return ops;
        }
        async loadAllInvalidations(targetOp) {
            const invalidations = new Array();
            let batchSize = 50;
            let results = await this.loadByReference('targetOp', targetOp, {
                order: 'asc',
                limit: batchSize
            });
            while (results.objects.length > 0) {
                for (const obj of results.objects) {
                    if (obj instanceof InvalidateAfterOp || obj instanceof CascadedInvalidateOp) {
                        invalidations.push(obj);
                    }
                }
                results = await this.loadByReference('targetOp', targetOp, {
                    order: 'asc',
                    limit: batchSize,
                    start: results.end
                });
            }
            return invalidations;
        }
        async loadAllConsequences(op) {
            const consequences = new Array();
            let batchSize = 50;
            let results = await this.loadByReference('causalOps', op, {
                order: 'asc',
                limit: batchSize
            });
            while (results.objects.length > 0) {
                for (const obj of results.objects) {
                    if (obj instanceof MutationOp) {
                        consequences.push(obj);
                    }
                }
                results = await this.loadByReference('causalOps', op, {
                    order: 'asc',
                    limit: batchSize,
                    start: results.end
                });
            }
            return consequences;
        }
        close() {
            this.backend.close();
        }
    }
    Store.operationLog = new Logger(MutableObject.name, LogLevel.INFO);
    Store.backendLoaders = new Map();
    Store.extractPrevOps = (obj) => new Set(Array.from(obj.getPrevOps()).map((ref) => ref.hash));

    class IdbBackend {
        constructor(name) {
            this.name = name;
            this.idbPromise = openDB(name, 1, {
                upgrade(db, _oldVersion, _newVersion, _transaction) {
                    let objectStore = db.createObjectStore(IdbBackend.OBJ_STORE, { keyPath: 'literal.hash' });
                    objectStore.createIndex(IdbBackend.CLASS_SEQUENCE_IDX_KEY + '_idx', 'indexes.' + IdbBackend.CLASS_SEQUENCE_IDX_KEY);
                    objectStore.createIndex(IdbBackend.REFERENCES_SEQUENCE_IDX_KEY + '_idx', 'indexes.' + IdbBackend.REFERENCES_SEQUENCE_IDX_KEY, { multiEntry: true });
                    objectStore.createIndex(IdbBackend.REFERENCING_CLASS_SEQUENCE_IDX_KEY + '_idx', 'indexes.' + IdbBackend.REFERENCING_CLASS_SEQUENCE_IDX_KEY, { multiEntry: true });
                    db.createObjectStore(IdbBackend.TERMINAL_OPS_STORE, { keyPath: 'mutableHash' });
                    let opHeadersStore = db.createObjectStore(IdbBackend.OP_HEADERS_STORE, { keyPath: 'literal.opHash' });
                    opHeadersStore.createIndex(IdbBackend.OP_HEADER_HASH_IDX_KEY + '_idx', 'literal.headerHash');
                    db.createObjectStore(IdbBackend.META_STORE, { keyPath: 'name' });
                },
                blocked() {
                    // …
                },
                blocking() {
                    // …
                },
                terminated() {
                    // …
                }
            });
            IdbBackend.register(this);
        }
        static register(backend) {
            IdbBackend.registered.add(backend.name, backend);
        }
        static deregister(backend) {
            IdbBackend.registered.delete(backend.name, backend);
        }
        static getRegisteredInstances(name) {
            return IdbBackend.registered.get(name);
        }
        static async fireCallbacks(dbName, literal) {
            for (const backend of IdbBackend.getRegisteredInstances(dbName)) {
                if (backend.objectStoreCallback !== undefined) {
                    await backend.objectStoreCallback(literal);
                }
            }
        }
        async processExternalStore(literal) {
        }
        getBackendName() {
            return IdbBackend.backendName;
        }
        getName() {
            return this.name;
        }
        async store(literal, opHeader) {
            let idb = await this.idbPromise;
            let storable = {};
            storable.literal = literal;
            storable.indexes = {};
            storable.timestamp = new Date().getTime().toString();
            let stores = [IdbBackend.OBJ_STORE, IdbBackend.META_STORE];
            const isOp = literal.value['_flags'].indexOf('op') >= 0;
            if (isOp) {
                stores.push(IdbBackend.TERMINAL_OPS_STORE);
                stores.push(IdbBackend.OP_HEADERS_STORE);
            }
            let tx = idb.transaction(stores, 'readwrite');
            let seqInfo = await tx.objectStore(IdbBackend.META_STORE).get('current_object_sequence');
            if (seqInfo === undefined) {
                seqInfo = { name: 'current_object_sequence', value: 0 };
            }
            storable.sequence = seqInfo.value;
            seqInfo.value = seqInfo.value + 1;
            IdbBackend.assignIdxValue(storable, IdbBackend.CLASS_SEQUENCE_IDX_KEY, storable.literal.value._class, { sequence: true });
            for (const dep of literal.dependencies) {
                let reference = dep.path + '#' + dep.hash;
                IdbBackend.assignIdxValue(storable, IdbBackend.REFERENCES_SEQUENCE_IDX_KEY, reference, { sequence: true, multi: true });
                let referencingClass = dep.className + '.' + dep.path + '#' + dep.hash;
                IdbBackend.assignIdxValue(storable, IdbBackend.REFERENCING_CLASS_SEQUENCE_IDX_KEY, referencingClass, { sequence: true, multi: true });
            }
            if (isOp) {
                if (opHeader === undefined) {
                    throw new Error('Missing causal history received by backend while trying to store op ' + literal.hash);
                }
                await tx.objectStore(IdbBackend.OP_HEADERS_STORE).put(opHeader);
                const mutableHash = LiteralUtils.getFields(storable.literal)['targetObject']['_hash'];
                const prevOpHashes = HashedSet.elementsFromLiteral(LiteralUtils.getFields(storable.literal)['prevOps']).map(HashReference.hashFromLiteral);
                IdbBackend.terminalOpsStorageLog.debug('updating stored last ops for ' + mutableHash +
                    ' on arrival of ' + storable.literal.hash +
                    ' with prevOps ' + prevOpHashes);
                let terminalOpsInfo = (await tx.objectStore(IdbBackend.TERMINAL_OPS_STORE)
                    .get(mutableHash));
                if (terminalOpsInfo === undefined) {
                    IdbBackend.terminalOpsStorageLog.trace('found no stored last ops, setting last ops to [' + storable.literal.hash + ']');
                    terminalOpsInfo = {
                        mutableHash: mutableHash,
                        terminalOps: [storable.literal.hash],
                        lastOp: storable.literal.hash
                    };
                }
                else {
                    IdbBackend.terminalOpsStorageLog.trace('stored last ops are: ' + terminalOpsInfo.terminalOps);
                    IdbBackend.terminalOpsStorageLog.trace('removing new op last ops which are ' + prevOpHashes);
                    for (const hash of prevOpHashes) {
                        let idx = terminalOpsInfo.terminalOps.indexOf(hash);
                        if (idx >= 0) {
                            terminalOpsInfo.terminalOps.splice(idx, 1);
                        }
                    }
                    if (terminalOpsInfo.terminalOps.indexOf(storable.literal.hash) < 0) { // this should always be true
                        terminalOpsInfo.terminalOps.push(storable.literal.hash);
                    }
                    IdbBackend.terminalOpsStorageLog.debug('final last ops after added new op if necessary:' + terminalOpsInfo.terminalOps);
                    terminalOpsInfo.lastOp = storable.literal.hash;
                }
                await tx.objectStore(IdbBackend.TERMINAL_OPS_STORE).put(terminalOpsInfo);
            }
            await tx.objectStore(IdbBackend.META_STORE).put(seqInfo);
            await tx.objectStore(IdbBackend.OBJ_STORE).put(storable);
            await IdbBackend.fireCallbacks(this.name, literal);
        }
        async load(hash) {
            let idb = await this.idbPromise;
            const loaded = await idb.get(IdbBackend.OBJ_STORE, hash);
            return loaded === null || loaded === void 0 ? void 0 : loaded.literal;
        }
        async loadTerminalOpsForMutable(hash) {
            let idb = await this.idbPromise;
            return idb.get(IdbBackend.TERMINAL_OPS_STORE, hash);
        }
        async searchByClass(className, params) {
            return this.searchByIndex(IdbBackend.CLASS_SEQUENCE_IDX_KEY + '_idx', className, params);
        }
        async searchByReference(referringPath, referencedHash, params) {
            return this.searchByIndex(IdbBackend.REFERENCES_SEQUENCE_IDX_KEY + '_idx', referringPath + '#' + referencedHash, params);
        }
        async searchByReferencingClass(referringClassName, referringPath, referencedHash, params) {
            return this.searchByIndex(IdbBackend.REFERENCING_CLASS_SEQUENCE_IDX_KEY + '_idx', referringClassName + '.' + referringPath + '#' + referencedHash, params);
        }
        async loadOpHeader(opHash) {
            let idb = await this.idbPromise;
            return await idb.get(IdbBackend.OP_HEADERS_STORE, opHash);
        }
        async loadOpHeaderByHeaderHash(headerHash) {
            let idb = await this.idbPromise;
            const stored = await idb.transaction([IdbBackend.OP_HEADERS_STORE], 'readonly').objectStore(IdbBackend.OP_HEADERS_STORE).index(IdbBackend.OP_HEADER_HASH_IDX_KEY + '_idx').get(headerHash);
            if (stored) {
                return stored;
            }
            else {
                return undefined;
            }
        }
        setStoredObjectCallback(objectStoreCallback) {
            this.objectStoreCallback = objectStoreCallback;
        }
        close() {
            IdbBackend.deregister(this);
            //this.idbPromise.then((idb: IDBPDatabase) => { idb.close(); IdbBackend.deregister(this);});
        }
        async searchByIndex(index, value, params) {
            let idb = await this.idbPromise;
            let order = (params === undefined || params.order === undefined) ? 'asc' : params.order.toLowerCase();
            let range_start = null;
            let range_end = null;
            if (params === undefined || params.start === undefined) {
                range_start = value + '_';
            }
            else {
                range_start = params.start;
            }
            range_end = value + '_Z';
            const range = IDBKeyRange.bound(range_start, range_end, true, true);
            const direction = order === 'desc' ? 'prev' : 'next';
            let searchResults = {};
            searchResults.items = [];
            searchResults.start = undefined;
            searchResults.end = undefined;
            //let ingestCursor = async () => {
            var cursor = await idb.transaction([IdbBackend.OBJ_STORE], 'readonly').objectStore(IdbBackend.OBJ_STORE).index(index).openCursor(range, direction);
            const limit = params === null || params === void 0 ? void 0 : params.limit;
            while ((limit === undefined || searchResults.items.length < limit) && cursor) {
                let storable = cursor.value;
                searchResults.items.push(storable.literal);
                if (searchResults.start === undefined) {
                    searchResults.start = cursor.key.toString();
                }
                searchResults.end = cursor.key.toString();
                cursor = await cursor.continue();
            }
            //}
            //await ingestCursor();
            return searchResults;
        }
        static assignIdxValue(storable, key, value, params) {
            if (params !== undefined && params.sequence !== undefined && params.sequence) {
                value = IdbBackend.addSequenceToValue(value, storable.sequence);
            }
            if (params !== undefined && params.multi !== undefined && params.multi) {
                let values = storable.indexes[key];
                if (values === undefined) {
                    values = [];
                    storable.indexes[key] = values;
                }
                values.push(value);
            }
            else {
                storable.indexes[key] = value;
            }
        }
        static addSequenceToValue(value, sequence) {
            return value + '_' + sequence.toString(16).padStart(16, '0');
        }
        async ready() {
            await this.idbPromise;
        }
    }
    IdbBackend.log = new Logger(IdbBackend.name, LogLevel.INFO);
    IdbBackend.terminalOpsStorageLog = new Logger(IdbBackend.name, LogLevel.INFO);
    IdbBackend.backendName = 'idb';
    IdbBackend.registered = new MultiMap();
    IdbBackend.META_STORE = 'meta_store';
    IdbBackend.OBJ_STORE = 'object_store';
    IdbBackend.TERMINAL_OPS_STORE = 'terminal_ops_store';
    IdbBackend.OP_HEADERS_STORE = 'op_headers_store';
    IdbBackend.CLASS_SEQUENCE_IDX_KEY = 'class_sequence';
    IdbBackend.REFERENCES_SEQUENCE_IDX_KEY = 'references_sequence';
    IdbBackend.REFERENCING_CLASS_SEQUENCE_IDX_KEY = 'referencing_class_sequence';
    IdbBackend.OP_HEADER_HASH_IDX_KEY = 'op_header_hash';
    Store.registerBackend(IdbBackend.backendName, (dbName) => new IdbBackend(dbName));

    class MemoryBackend {
        constructor(name) {
            this.name = name;
            const instances = MemoryBackend.getRegisteredInstances(name);
            if (instances.size > 0) {
                this.repr = instances.values().next().value.repr;
            }
            else {
                this.repr = {
                    objects: new Map(),
                    classIndex: new MultiMap(),
                    sortedClassIndex: new Map(),
                    referenceIndex: new MultiMap(),
                    sortedReferenceIndex: new Map(),
                    referencingClassIndex: new MultiMap(),
                    sortedReferencingClassIndex: new Map(),
                    terminalOps: new MultiMap(),
                    lastOps: new Map(),
                    opCausalHistories: new Map(),
                    opCausalHistoriesByHash: new Map()
                };
            }
            MemoryBackend.register(this);
        }
        static register(backend) {
            MemoryBackend.registered.add(backend.name, backend);
        }
        static deregister(backend) {
            MemoryBackend.registered.delete(backend.name, backend);
        }
        static getRegisteredInstances(name) {
            return MemoryBackend.registered.get(name);
        }
        close() {
            MemoryBackend.deregister(this);
        }
        setStoredObjectCallback(objectStoreCallback) {
            this.objectStoreCallback = objectStoreCallback;
        }
        getBackendName() {
            return MemoryBackend.backendName;
        }
        getName() {
            return this.name;
        }
        async store(literal, history) {
            // store object
            let storable = {};
            storable.literal = literal;
            storable.timestamp = new Date().getTime().toString();
            storable.sequence = this.repr.objects.size;
            this.repr.objects.set(literal.hash, storable);
            // update indexes 
            if (!this.repr.classIndex.has(storable.literal.value._class, literal.hash)) {
                this.repr.classIndex.add(storable.literal.value._class, literal.hash);
                let sorted = this.repr.sortedClassIndex.get(storable.literal.value._class);
                if (sorted === undefined) {
                    sorted = [];
                    this.repr.sortedClassIndex.set(storable.literal.value._class, sorted);
                }
                sorted.push(literal.hash);
            }
            for (const dep of literal.dependencies) {
                let reference = dep.path + '#' + dep.hash;
                if (!this.repr.referenceIndex.has(reference, literal.hash)) {
                    this.repr.referenceIndex.add(reference, literal.hash);
                    let sorted = this.repr.sortedReferenceIndex.get(reference);
                    if (sorted === undefined) {
                        sorted = [];
                        this.repr.sortedReferenceIndex.set(reference, sorted);
                    }
                    sorted.push(literal.hash);
                }
                let referencingClass = dep.className + '.' + dep.path + '#' + dep.hash;
                if (!this.repr.referencingClassIndex.has(referencingClass, literal.hash)) {
                    this.repr.referencingClassIndex.add(referencingClass, literal.hash);
                    let sorted = this.repr.sortedReferencingClassIndex.get(referencingClass);
                    if (sorted === undefined) {
                        sorted = [];
                        this.repr.sortedReferencingClassIndex.set(referencingClass, sorted);
                    }
                    sorted.push(literal.hash);
                }
            }
            // if necessary, update last ops
            const isOp = literal.value['_flags'].indexOf('op') >= 0;
            if (isOp) {
                if (history === undefined) {
                    throw new Error('Missing causal history received by backend while trying to store op ' + literal.hash);
                }
                const historyCopy = Object.assign({}, history);
                this.repr.opCausalHistories.set(literal.hash, historyCopy);
                this.repr.opCausalHistoriesByHash.set(history.literal.headerHash, historyCopy);
                const mutableHash = LiteralUtils.getFields(storable.literal)['targetObject']['_hash'];
                const prevOpHashes = HashedSet.elementsFromLiteral(LiteralUtils.getFields(storable.literal)['prevOps']).map(HashReference.hashFromLiteral);
                for (const prevOpHash of prevOpHashes) {
                    this.repr.terminalOps.delete(mutableHash, prevOpHash);
                }
                if (!this.repr.terminalOps.has(mutableHash, literal.hash)) {
                    this.repr.terminalOps.add(mutableHash, literal.hash);
                    this.repr.lastOps.set(mutableHash, literal.hash);
                }
            }
            for (const backend of MemoryBackend.getRegisteredInstances(this.name)) {
                if (backend.objectStoreCallback !== undefined) {
                    await backend.objectStoreCallback(literal);
                }
            }
        }
        async load(hash) {
            const loaded = this.repr.objects.get(hash);
            return loaded === null || loaded === void 0 ? void 0 : loaded.literal;
        }
        async loadTerminalOpsForMutable(hash) {
            const lastOp = this.repr.lastOps.get(hash);
            const terminalOps = this.repr.terminalOps.get(hash);
            if (lastOp !== undefined && terminalOps !== undefined && terminalOps.size > 0) {
                return { lastOp: lastOp, terminalOps: Array.from(terminalOps.values()) };
            }
            else {
                return undefined;
            }
        }
        searchByClass(className, params) {
            return this.searchByIndex(className, this.repr.sortedClassIndex, params);
        }
        searchByReference(referringPath, referencedHash, params) {
            let key = referringPath + '#' + referencedHash;
            return this.searchByIndex(key, this.repr.sortedReferenceIndex, params);
        }
        searchByReferencingClass(referringClassName, referringPath, referencedHash, params) {
            let key = referringClassName + '.' + referringPath + '#' + referencedHash;
            return this.searchByIndex(key, this.repr.sortedReferencingClassIndex, params);
        }
        async loadOpHeader(opHash) {
            return this.repr.opCausalHistories.get(opHash);
        }
        async loadOpHeaderByHeaderHash(causalHistoryHash) {
            return this.repr.opCausalHistoriesByHash.get(causalHistoryHash);
        }
        async searchByIndex(key, sortedIndex, params) {
            let classHashes = sortedIndex.get(key);
            if (classHashes === undefined) {
                return { items: [], start: '', end: '' };
            }
            else {
                let order = (params === undefined || params.order === undefined) ? 'asc' : params.order.toLowerCase();
                let segment;
                if (order === 'desc') {
                    classHashes.reverse();
                }
                let start = 0;
                if (params !== undefined && params.start !== undefined) {
                    start = Number.parseInt(params.start);
                }
                if (start >= classHashes.length) {
                    return { items: [], start: classHashes.length.toString(), end: classHashes.length.toString() };
                }
                let end = classHashes.length;
                if (params !== undefined && params.limit !== undefined) {
                    end = Math.min(start + params.limit, classHashes.length);
                }
                segment = classHashes.slice(start, end);
                let result = segment.map((hash) => { var _a; return (_a = this.repr.objects.get(hash)) === null || _a === void 0 ? void 0 : _a.literal; });
                return { start: start.toString(), end: end.toString(), items: result };
            }
        }
        async ready() {
        }
    }
    MemoryBackend.log = new Logger(MemoryBackend.name, LogLevel.INFO);
    MemoryBackend.instances = new Map();
    MemoryBackend.backendName = 'memory';
    MemoryBackend.registered = new MultiMap();
    Store.registerBackend(MemoryBackend.backendName, (dbName) => {
        let mb = MemoryBackend.instances.get(dbName);
        if (mb === undefined) {
            mb = new MemoryBackend(dbName);
            MemoryBackend.instances.set(dbName, mb);
        }
        return mb;
    });

    /**
     * returns true if the given object is a promise
     */
    function isPromise(obj) {
      if (obj && typeof obj.then === 'function') {
        return true;
      } else {
        return false;
      }
    }
    function sleep(time) {
      if (!time) time = 0;
      return new Promise(function (res) {
        return setTimeout(res, time);
      });
    }
    function randomInt(min, max) {
      return Math.floor(Math.random() * (max - min + 1) + min);
    }
    /**
     * https://stackoverflow.com/a/8084248
     */

    function randomToken() {
      return Math.random().toString(36).substring(2);
    }
    var lastMs = 0;
    var additional = 0;
    /**
     * returns the current time in micro-seconds,
     * WARNING: This is a pseudo-function
     * Performance.now is not reliable in webworkers, so we just make sure to never return the same time.
     * This is enough in browsers, and this function will not be used in nodejs.
     * The main reason for this hack is to ensure that BroadcastChannel behaves equal to production when it is used in fast-running unit tests.
     */

    function microSeconds$4() {
      var ms = new Date().getTime();

      if (ms === lastMs) {
        additional++;
        return ms * 1000 + additional;
      } else {
        lastMs = ms;
        additional = 0;
        return ms * 1000;
      }
    }
    /**
     * copied from the 'detect-node' npm module
     * We cannot use the module directly because it causes problems with rollup
     * @link https://github.com/iliakan/detect-node/blob/master/index.js
     */

    var isNode = Object.prototype.toString.call(typeof process !== 'undefined' ? process : 0) === '[object process]';

    var microSeconds$3 = microSeconds$4;
    var type$3 = 'native';
    function create$3(channelName) {
      var state = {
        messagesCallback: null,
        bc: new BroadcastChannel(channelName),
        subFns: [] // subscriberFunctions

      };

      state.bc.onmessage = function (msg) {
        if (state.messagesCallback) {
          state.messagesCallback(msg.data);
        }
      };

      return state;
    }
    function close$3(channelState) {
      channelState.bc.close();
      channelState.subFns = [];
    }
    function postMessage$3(channelState, messageJson) {
      try {
        channelState.bc.postMessage(messageJson, false);
        return Promise.resolve();
      } catch (err) {
        return Promise.reject(err);
      }
    }
    function onMessage$3(channelState, fn) {
      channelState.messagesCallback = fn;
    }
    function canBeUsed$3() {
      /**
       * in the electron-renderer, isNode will be true even if we are in browser-context
       * so we also check if window is undefined
       */
      if (isNode && typeof window === 'undefined') return false;

      if (typeof BroadcastChannel === 'function') {
        if (BroadcastChannel._pubkey) {
          throw new Error('BroadcastChannel: Do not overwrite window.BroadcastChannel with this module, this is not a polyfill');
        }

        return true;
      } else return false;
    }
    function averageResponseTime$3() {
      return 150;
    }
    var NativeMethod = {
      create: create$3,
      close: close$3,
      onMessage: onMessage$3,
      postMessage: postMessage$3,
      canBeUsed: canBeUsed$3,
      type: type$3,
      averageResponseTime: averageResponseTime$3,
      microSeconds: microSeconds$3
    };

    /**
     * this is a set which automatically forgets
     * a given entry when a new entry is set and the ttl
     * of the old one is over
     */
    var ObliviousSet = /** @class */ (function () {
        function ObliviousSet(ttl) {
            this.ttl = ttl;
            this.set = new Set();
            this.timeMap = new Map();
        }
        ObliviousSet.prototype.has = function (value) {
            return this.set.has(value);
        };
        ObliviousSet.prototype.add = function (value) {
            var _this = this;
            this.timeMap.set(value, now());
            this.set.add(value);
            /**
             * When a new value is added,
             * start the cleanup at the next tick
             * to not block the cpu for more important stuff
             * that might happen.
             */
            setTimeout(function () {
                removeTooOldValues(_this);
            }, 0);
        };
        ObliviousSet.prototype.clear = function () {
            this.set.clear();
            this.timeMap.clear();
        };
        return ObliviousSet;
    }());
    /**
     * Removes all entries from the set
     * where the TTL has expired
     */
    function removeTooOldValues(obliviousSet) {
        var olderThen = now() - obliviousSet.ttl;
        var iterator = obliviousSet.set[Symbol.iterator]();
        /**
         * Because we can assume the new values are added at the bottom,
         * we start from the top and stop as soon as we reach a non-too-old value.
         */
        while (true) {
            var value = iterator.next().value;
            if (!value) {
                return; // no more elements
            }
            var time = obliviousSet.timeMap.get(value);
            if (time < olderThen) {
                obliviousSet.timeMap.delete(value);
                obliviousSet.set.delete(value);
            }
            else {
                // We reached a value that is not old enough
                return;
            }
        }
    }
    function now() {
        return new Date().getTime();
    }

    function fillOptionsWithDefaults() {
      var originalOptions = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
      var options = JSON.parse(JSON.stringify(originalOptions)); // main

      if (typeof options.webWorkerSupport === 'undefined') options.webWorkerSupport = true; // indexed-db

      if (!options.idb) options.idb = {}; //  after this time the messages get deleted

      if (!options.idb.ttl) options.idb.ttl = 1000 * 45;
      if (!options.idb.fallbackInterval) options.idb.fallbackInterval = 150; //  handles abrupt db onclose events.

      if (originalOptions.idb && typeof originalOptions.idb.onclose === 'function') options.idb.onclose = originalOptions.idb.onclose; // localstorage

      if (!options.localstorage) options.localstorage = {};
      if (!options.localstorage.removeTimeout) options.localstorage.removeTimeout = 1000 * 60; // custom methods

      if (originalOptions.methods) options.methods = originalOptions.methods; // node

      if (!options.node) options.node = {};
      if (!options.node.ttl) options.node.ttl = 1000 * 60 * 2; // 2 minutes;

      if (typeof options.node.useFastPath === 'undefined') options.node.useFastPath = true;
      return options;
    }

    /**
     * this method uses indexeddb to store the messages
     * There is currently no observerAPI for idb
     * @link https://github.com/w3c/IndexedDB/issues/51
     */
    var microSeconds$2 = microSeconds$4;
    var DB_PREFIX = 'pubkey.broadcast-channel-0-';
    var OBJECT_STORE_ID = 'messages';
    var type$2 = 'idb';
    function getIdb() {
      if (typeof indexedDB !== 'undefined') return indexedDB;

      if (typeof window !== 'undefined') {
        if (typeof window.mozIndexedDB !== 'undefined') return window.mozIndexedDB;
        if (typeof window.webkitIndexedDB !== 'undefined') return window.webkitIndexedDB;
        if (typeof window.msIndexedDB !== 'undefined') return window.msIndexedDB;
      }

      return false;
    }
    function createDatabase(channelName) {
      var IndexedDB = getIdb(); // create table

      var dbName = DB_PREFIX + channelName;
      var openRequest = IndexedDB.open(dbName, 1);

      openRequest.onupgradeneeded = function (ev) {
        var db = ev.target.result;
        db.createObjectStore(OBJECT_STORE_ID, {
          keyPath: 'id',
          autoIncrement: true
        });
      };

      var dbPromise = new Promise(function (res, rej) {
        openRequest.onerror = function (ev) {
          return rej(ev);
        };

        openRequest.onsuccess = function () {
          res(openRequest.result);
        };
      });
      return dbPromise;
    }
    /**
     * writes the new message to the database
     * so other readers can find it
     */

    function writeMessage(db, readerUuid, messageJson) {
      var time = new Date().getTime();
      var writeObject = {
        uuid: readerUuid,
        time: time,
        data: messageJson
      };
      var transaction = db.transaction([OBJECT_STORE_ID], 'readwrite');
      return new Promise(function (res, rej) {
        transaction.oncomplete = function () {
          return res();
        };

        transaction.onerror = function (ev) {
          return rej(ev);
        };

        var objectStore = transaction.objectStore(OBJECT_STORE_ID);
        objectStore.add(writeObject);
      });
    }
    function getMessagesHigherThan(db, lastCursorId) {
      var objectStore = db.transaction(OBJECT_STORE_ID).objectStore(OBJECT_STORE_ID);
      var ret = [];

      function openCursor() {
        // Occasionally Safari will fail on IDBKeyRange.bound, this
        // catches that error, having it open the cursor to the first
        // item. When it gets data it will advance to the desired key.
        try {
          var keyRangeValue = IDBKeyRange.bound(lastCursorId + 1, Infinity);
          return objectStore.openCursor(keyRangeValue);
        } catch (e) {
          return objectStore.openCursor();
        }
      }

      return new Promise(function (res) {
        openCursor().onsuccess = function (ev) {
          var cursor = ev.target.result;

          if (cursor) {
            if (cursor.value.id < lastCursorId + 1) {
              cursor["continue"](lastCursorId + 1);
            } else {
              ret.push(cursor.value);
              cursor["continue"]();
            }
          } else {
            res(ret);
          }
        };
      });
    }
    function removeMessageById(db, id) {
      var request = db.transaction([OBJECT_STORE_ID], 'readwrite').objectStore(OBJECT_STORE_ID)["delete"](id);
      return new Promise(function (res) {
        request.onsuccess = function () {
          return res();
        };
      });
    }
    function getOldMessages(db, ttl) {
      var olderThen = new Date().getTime() - ttl;
      var objectStore = db.transaction(OBJECT_STORE_ID).objectStore(OBJECT_STORE_ID);
      var ret = [];
      return new Promise(function (res) {
        objectStore.openCursor().onsuccess = function (ev) {
          var cursor = ev.target.result;

          if (cursor) {
            var msgObk = cursor.value;

            if (msgObk.time < olderThen) {
              ret.push(msgObk); //alert("Name for SSN " + cursor.key + " is " + cursor.value.name);

              cursor["continue"]();
            } else {
              // no more old messages,
              res(ret);
              return;
            }
          } else {
            res(ret);
          }
        };
      });
    }
    function cleanOldMessages(db, ttl) {
      return getOldMessages(db, ttl).then(function (tooOld) {
        return Promise.all(tooOld.map(function (msgObj) {
          return removeMessageById(db, msgObj.id);
        }));
      });
    }
    function create$2(channelName, options) {
      options = fillOptionsWithDefaults(options);
      return createDatabase(channelName).then(function (db) {
        var state = {
          closed: false,
          lastCursorId: 0,
          channelName: channelName,
          options: options,
          uuid: randomToken(),

          /**
           * emittedMessagesIds
           * contains all messages that have been emitted before
           * @type {ObliviousSet}
           */
          eMIs: new ObliviousSet(options.idb.ttl * 2),
          // ensures we do not read messages in parrallel
          writeBlockPromise: Promise.resolve(),
          messagesCallback: null,
          readQueuePromises: [],
          db: db
        };
        /**
         * Handle abrupt closes that do not originate from db.close().
         * This could happen, for example, if the underlying storage is
         * removed or if the user clears the database in the browser's
         * history preferences.
         */

        db.onclose = function () {
          state.closed = true;
          if (options.idb.onclose) options.idb.onclose();
        };
        /**
         * if service-workers are used,
         * we have no 'storage'-event if they post a message,
         * therefore we also have to set an interval
         */


        _readLoop(state);

        return state;
      });
    }

    function _readLoop(state) {
      if (state.closed) return;
      readNewMessages(state).then(function () {
        return sleep(state.options.idb.fallbackInterval);
      }).then(function () {
        return _readLoop(state);
      });
    }

    function _filterMessage(msgObj, state) {
      if (msgObj.uuid === state.uuid) return false; // send by own

      if (state.eMIs.has(msgObj.id)) return false; // already emitted

      if (msgObj.data.time < state.messagesCallbackTime) return false; // older then onMessageCallback

      return true;
    }
    /**
     * reads all new messages from the database and emits them
     */


    function readNewMessages(state) {
      // channel already closed
      if (state.closed) return Promise.resolve(); // if no one is listening, we do not need to scan for new messages

      if (!state.messagesCallback) return Promise.resolve();
      return getMessagesHigherThan(state.db, state.lastCursorId).then(function (newerMessages) {
        var useMessages = newerMessages
        /**
         * there is a bug in iOS where the msgObj can be undefined some times
         * so we filter them out
         * @link https://github.com/pubkey/broadcast-channel/issues/19
         */
        .filter(function (msgObj) {
          return !!msgObj;
        }).map(function (msgObj) {
          if (msgObj.id > state.lastCursorId) {
            state.lastCursorId = msgObj.id;
          }

          return msgObj;
        }).filter(function (msgObj) {
          return _filterMessage(msgObj, state);
        }).sort(function (msgObjA, msgObjB) {
          return msgObjA.time - msgObjB.time;
        }); // sort by time

        useMessages.forEach(function (msgObj) {
          if (state.messagesCallback) {
            state.eMIs.add(msgObj.id);
            state.messagesCallback(msgObj.data);
          }
        });
        return Promise.resolve();
      });
    }

    function close$2(channelState) {
      channelState.closed = true;
      channelState.db.close();
    }
    function postMessage$2(channelState, messageJson) {
      channelState.writeBlockPromise = channelState.writeBlockPromise.then(function () {
        return writeMessage(channelState.db, channelState.uuid, messageJson);
      }).then(function () {
        if (randomInt(0, 10) === 0) {
          /* await (do not await) */
          cleanOldMessages(channelState.db, channelState.options.idb.ttl);
        }
      });
      return channelState.writeBlockPromise;
    }
    function onMessage$2(channelState, fn, time) {
      channelState.messagesCallbackTime = time;
      channelState.messagesCallback = fn;
      readNewMessages(channelState);
    }
    function canBeUsed$2() {
      if (isNode) return false;
      var idb = getIdb();
      if (!idb) return false;
      return true;
    }
    function averageResponseTime$2(options) {
      return options.idb.fallbackInterval * 2;
    }
    var IndexeDbMethod = {
      create: create$2,
      close: close$2,
      onMessage: onMessage$2,
      postMessage: postMessage$2,
      canBeUsed: canBeUsed$2,
      type: type$2,
      averageResponseTime: averageResponseTime$2,
      microSeconds: microSeconds$2
    };

    /**
     * A localStorage-only method which uses localstorage and its 'storage'-event
     * This does not work inside of webworkers because they have no access to locastorage
     * This is basically implemented to support IE9 or your grandmothers toaster.
     * @link https://caniuse.com/#feat=namevalue-storage
     * @link https://caniuse.com/#feat=indexeddb
     */
    var microSeconds$1 = microSeconds$4;
    var KEY_PREFIX = 'pubkey.broadcastChannel-';
    var type$1 = 'localstorage';
    /**
     * copied from crosstab
     * @link https://github.com/tejacques/crosstab/blob/master/src/crosstab.js#L32
     */

    function getLocalStorage() {
      var localStorage;
      if (typeof window === 'undefined') return null;

      try {
        localStorage = window.localStorage;
        localStorage = window['ie8-eventlistener/storage'] || window.localStorage;
      } catch (e) {// New versions of Firefox throw a Security exception
        // if cookies are disabled. See
        // https://bugzilla.mozilla.org/show_bug.cgi?id=1028153
      }

      return localStorage;
    }
    function storageKey(channelName) {
      return KEY_PREFIX + channelName;
    }
    /**
    * writes the new message to the storage
    * and fires the storage-event so other readers can find it
    */

    function postMessage$1(channelState, messageJson) {
      return new Promise(function (res) {
        sleep().then(function () {
          var key = storageKey(channelState.channelName);
          var writeObj = {
            token: randomToken(),
            time: new Date().getTime(),
            data: messageJson,
            uuid: channelState.uuid
          };
          var value = JSON.stringify(writeObj);
          getLocalStorage().setItem(key, value);
          /**
           * StorageEvent does not fire the 'storage' event
           * in the window that changes the state of the local storage.
           * So we fire it manually
           */

          var ev = document.createEvent('Event');
          ev.initEvent('storage', true, true);
          ev.key = key;
          ev.newValue = value;
          window.dispatchEvent(ev);
          res();
        });
      });
    }
    function addStorageEventListener(channelName, fn) {
      var key = storageKey(channelName);

      var listener = function listener(ev) {
        if (ev.key === key) {
          fn(JSON.parse(ev.newValue));
        }
      };

      window.addEventListener('storage', listener);
      return listener;
    }
    function removeStorageEventListener(listener) {
      window.removeEventListener('storage', listener);
    }
    function create$1(channelName, options) {
      options = fillOptionsWithDefaults(options);

      if (!canBeUsed$1()) {
        throw new Error('BroadcastChannel: localstorage cannot be used');
      }

      var uuid = randomToken();
      /**
       * eMIs
       * contains all messages that have been emitted before
       * @type {ObliviousSet}
       */

      var eMIs = new ObliviousSet(options.localstorage.removeTimeout);
      var state = {
        channelName: channelName,
        uuid: uuid,
        eMIs: eMIs // emittedMessagesIds

      };
      state.listener = addStorageEventListener(channelName, function (msgObj) {
        if (!state.messagesCallback) return; // no listener

        if (msgObj.uuid === uuid) return; // own message

        if (!msgObj.token || eMIs.has(msgObj.token)) return; // already emitted

        if (msgObj.data.time && msgObj.data.time < state.messagesCallbackTime) return; // too old

        eMIs.add(msgObj.token);
        state.messagesCallback(msgObj.data);
      });
      return state;
    }
    function close$1(channelState) {
      removeStorageEventListener(channelState.listener);
    }
    function onMessage$1(channelState, fn, time) {
      channelState.messagesCallbackTime = time;
      channelState.messagesCallback = fn;
    }
    function canBeUsed$1() {
      if (isNode) return false;
      var ls = getLocalStorage();
      if (!ls) return false;

      try {
        var key = '__broadcastchannel_check';
        ls.setItem(key, 'works');
        ls.removeItem(key);
      } catch (e) {
        // Safari 10 in private mode will not allow write access to local
        // storage and fail with a QuotaExceededError. See
        // https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API#Private_Browsing_Incognito_modes
        return false;
      }

      return true;
    }
    function averageResponseTime$1() {
      var defaultTime = 120;
      var userAgent = navigator.userAgent.toLowerCase();

      if (userAgent.includes('safari') && !userAgent.includes('chrome')) {
        // safari is much slower so this time is higher
        return defaultTime * 2;
      }

      return defaultTime;
    }
    var LocalstorageMethod = {
      create: create$1,
      close: close$1,
      onMessage: onMessage$1,
      postMessage: postMessage$1,
      canBeUsed: canBeUsed$1,
      type: type$1,
      averageResponseTime: averageResponseTime$1,
      microSeconds: microSeconds$1
    };

    var microSeconds = microSeconds$4;
    var type = 'simulate';
    var SIMULATE_CHANNELS = new Set();
    function create(channelName) {
      var state = {
        name: channelName,
        messagesCallback: null
      };
      SIMULATE_CHANNELS.add(state);
      return state;
    }
    function close(channelState) {
      SIMULATE_CHANNELS["delete"](channelState);
    }
    function postMessage(channelState, messageJson) {
      return new Promise(function (res) {
        return setTimeout(function () {
          var channelArray = Array.from(SIMULATE_CHANNELS);
          channelArray.filter(function (channel) {
            return channel.name === channelState.name;
          }).filter(function (channel) {
            return channel !== channelState;
          }).filter(function (channel) {
            return !!channel.messagesCallback;
          }).forEach(function (channel) {
            return channel.messagesCallback(messageJson);
          });
          res();
        }, 5);
      });
    }
    function onMessage(channelState, fn) {
      channelState.messagesCallback = fn;
    }
    function canBeUsed() {
      return true;
    }
    function averageResponseTime() {
      return 5;
    }
    var SimulateMethod = {
      create: create,
      close: close,
      onMessage: onMessage,
      postMessage: postMessage,
      canBeUsed: canBeUsed,
      type: type,
      averageResponseTime: averageResponseTime,
      microSeconds: microSeconds
    };

    var METHODS = [NativeMethod, // fastest
    IndexeDbMethod, LocalstorageMethod];
    /**
     * The NodeMethod is loaded lazy
     * so it will not get bundled in browser-builds
     */

    if (isNode) {
      /**
       * we use the non-transpiled code for nodejs
       * because it runs faster
       */
      var NodeMethod = require('../../src/methods/' + // use this hack so that browserify and others
      // do not import the node-method by default
      // when bundling.
      'node.js');
      /**
       * this will be false for webpackbuilds
       * which will shim the node-method with an empty object {}
       */


      if (typeof NodeMethod.canBeUsed === 'function') {
        METHODS.push(NodeMethod);
      }
    }

    function chooseMethod(options) {
      var chooseMethods = [].concat(options.methods, METHODS).filter(Boolean); // directly chosen

      if (options.type) {
        if (options.type === 'simulate') {
          // only use simulate-method if directly chosen
          return SimulateMethod;
        }

        var ret = chooseMethods.find(function (m) {
          return m.type === options.type;
        });
        if (!ret) throw new Error('method-type ' + options.type + ' not found');else return ret;
      }
      /**
       * if no webworker support is needed,
       * remove idb from the list so that localstorage is been chosen
       */


      if (!options.webWorkerSupport && !isNode) {
        chooseMethods = chooseMethods.filter(function (m) {
          return m.type !== 'idb';
        });
      }

      var useMethod = chooseMethods.find(function (method) {
        return method.canBeUsed();
      });
      if (!useMethod) throw new Error('No useable methode found:' + JSON.stringify(METHODS.map(function (m) {
        return m.type;
      })));else return useMethod;
    }

    var BroadcastChannel$1 = function BroadcastChannel(name, options) {
      this.name = name;

      if (ENFORCED_OPTIONS) {
        options = ENFORCED_OPTIONS;
      }

      this.options = fillOptionsWithDefaults(options);
      this.method = chooseMethod(this.options); // isListening

      this._iL = false;
      /**
       * _onMessageListener
       * setting onmessage twice,
       * will overwrite the first listener
       */

      this._onML = null;
      /**
       * _addEventListeners
       */

      this._addEL = {
        message: [],
        internal: []
      };
      /**
       * Unsend message promises
       * where the sending is still in progress
       * @type {Set<Promise>}
       */

      this._uMP = new Set();
      /**
       * _beforeClose
       * array of promises that will be awaited
       * before the channel is closed
       */

      this._befC = [];
      /**
       * _preparePromise
       */

      this._prepP = null;

      _prepareChannel(this);
    }; // STATICS

    /**
     * used to identify if someone overwrites
     * window.BroadcastChannel with this
     * See methods/native.js
     */

    BroadcastChannel$1._pubkey = true;
    /**
     * if set, this method is enforced,
     * no mather what the options are
     */

    var ENFORCED_OPTIONS;

    BroadcastChannel$1.prototype = {
      postMessage: function postMessage(msg) {
        if (this.closed) {
          throw new Error('BroadcastChannel.postMessage(): ' + 'Cannot post message after channel has closed');
        }

        return _post(this, 'message', msg);
      },
      postInternal: function postInternal(msg) {
        return _post(this, 'internal', msg);
      },

      set onmessage(fn) {
        var time = this.method.microSeconds();
        var listenObj = {
          time: time,
          fn: fn
        };

        _removeListenerObject(this, 'message', this._onML);

        if (fn && typeof fn === 'function') {
          this._onML = listenObj;

          _addListenerObject(this, 'message', listenObj);
        } else {
          this._onML = null;
        }
      },

      addEventListener: function addEventListener(type, fn) {
        var time = this.method.microSeconds();
        var listenObj = {
          time: time,
          fn: fn
        };

        _addListenerObject(this, type, listenObj);
      },
      removeEventListener: function removeEventListener(type, fn) {
        var obj = this._addEL[type].find(function (obj) {
          return obj.fn === fn;
        });

        _removeListenerObject(this, type, obj);
      },
      close: function close() {
        var _this = this;

        if (this.closed) {
          return;
        }

        this.closed = true;
        var awaitPrepare = this._prepP ? this._prepP : Promise.resolve();
        this._onML = null;
        this._addEL.message = [];
        return awaitPrepare // wait until all current sending are processed
        .then(function () {
          return Promise.all(Array.from(_this._uMP));
        }) // run before-close hooks
        .then(function () {
          return Promise.all(_this._befC.map(function (fn) {
            return fn();
          }));
        }) // close the channel
        .then(function () {
          return _this.method.close(_this._state);
        });
      },

      get type() {
        return this.method.type;
      },

      get isClosed() {
        return this.closed;
      }

    };
    /**
     * Post a message over the channel
     * @returns {Promise} that resolved when the message sending is done
     */

    function _post(broadcastChannel, type, msg) {
      var time = broadcastChannel.method.microSeconds();
      var msgObj = {
        time: time,
        type: type,
        data: msg
      };
      var awaitPrepare = broadcastChannel._prepP ? broadcastChannel._prepP : Promise.resolve();
      return awaitPrepare.then(function () {
        var sendPromise = broadcastChannel.method.postMessage(broadcastChannel._state, msgObj); // add/remove to unsend messages list

        broadcastChannel._uMP.add(sendPromise);

        sendPromise["catch"]().then(function () {
          return broadcastChannel._uMP["delete"](sendPromise);
        });
        return sendPromise;
      });
    }

    function _prepareChannel(channel) {
      var maybePromise = channel.method.create(channel.name, channel.options);

      if (isPromise(maybePromise)) {
        channel._prepP = maybePromise;
        maybePromise.then(function (s) {
          // used in tests to simulate slow runtime

          /*if (channel.options.prepareDelay) {
               await new Promise(res => setTimeout(res, this.options.prepareDelay));
          }*/
          channel._state = s;
        });
      } else {
        channel._state = maybePromise;
      }
    }

    function _hasMessageListeners(channel) {
      if (channel._addEL.message.length > 0) return true;
      if (channel._addEL.internal.length > 0) return true;
      return false;
    }

    function _addListenerObject(channel, type, obj) {
      channel._addEL[type].push(obj);

      _startListening(channel);
    }

    function _removeListenerObject(channel, type, obj) {
      channel._addEL[type] = channel._addEL[type].filter(function (o) {
        return o !== obj;
      });

      _stopListening(channel);
    }

    function _startListening(channel) {
      if (!channel._iL && _hasMessageListeners(channel)) {
        // someone is listening, start subscribing
        var listenerFn = function listenerFn(msgObj) {
          channel._addEL[msgObj.type].forEach(function (obj) {
            if (msgObj.time >= obj.time) {
              obj.fn(msgObj.data);
            }
          });
        };

        var time = channel.method.microSeconds();

        if (channel._prepP) {
          channel._prepP.then(function () {
            channel._iL = true;
            channel.method.onMessage(channel._state, listenerFn, time);
          });
        } else {
          channel._iL = true;
          channel.method.onMessage(channel._state, listenerFn, time);
        }
      }
    }

    function _stopListening(channel) {
      if (channel._iL && !_hasMessageListeners(channel)) {
        // noone is listening, stop subscribing
        channel._iL = false;
        var time = channel.method.microSeconds();
        channel.method.onMessage(channel._state, null, time);
      }
    }

    var _a, _b;
    let SafeBroadcastChannel = (_a = globalThis.window) === null || _a === void 0 ? void 0 : _a.BroadcastChannel;
    if (SafeBroadcastChannel === undefined) {
        SafeBroadcastChannel = (_b = globalThis.self) === null || _b === void 0 ? void 0 : _b.BroadcastChannel;
    }
    class BroadcastChannelPolyfill {
        //removeEventListener(type: string, listener: EventListenerOrEventListenerObject, options?: boolean | EventListenerOptions): void;
        constructor(name) {
            this.name = name;
            this.closed = false;
            const createChannel = () => {
                this.channel = new BroadcastChannel$1(name, {
                    idb: {
                        onclose: () => {
                            var _a;
                            // the onclose event is just the IndexedDB closing.
                            // you should also close the channel before creating
                            // a new one.
                            (_a = this.channel) === null || _a === void 0 ? void 0 : _a.close();
                            createChannel();
                        }
                    }
                });
            };
            createChannel();
            if (this.channel !== undefined) {
                this.channel.onmessage = (msg) => {
                    if (this.onmessage !== null) {
                        this.onmessage(msg);
                    }
                };
            }
            this.onmessage = null;
            this.onmessageerror = null;
        }
        /**
         * Closes the BroadcastChannel object, opening it up to garbage collection.
         */
        close() {
            var _a;
            this.closed = true;
            (_a = this.channel) === null || _a === void 0 ? void 0 : _a.close();
        }
        /**
         * Sends the given message to other BroadcastChannel objects set up for this channel. Messages can be structured objects, e.g. nested objects and arrays.
         */
        postMessage(message) {
            var _a;
            (_a = this.channel) === null || _a === void 0 ? void 0 : _a.postMessage({ data: message });
        }
        addEventListener(_type, _listener, _options) {
            throw new Error('BroadcastChannel.addEventListener is not supported in this platform');
        }
        removeEventListener(_type, _listener, _options) {
            throw new Error('BroadcastChannel.addEventListener is not supported in this platform');
        }
    }
    if (SafeBroadcastChannel === undefined) {
        SafeBroadcastChannel = BroadcastChannelPolyfill;
    }

    class WorkerSafeIdbBackend extends IdbBackend {
        constructor(name) {
            super(name);
            WorkerSafeIdbBackend.init();
        }
        static init() {
            if (WorkerSafeIdbBackend.broadcastId === undefined) {
                WorkerSafeIdbBackend.broadcastId = new BrowserRNG().randomHexString(128);
                WorkerSafeIdbBackend.broadcastChannel = new SafeBroadcastChannel(WorkerSafeIdbBackend.channelName);
                WorkerSafeIdbBackend.broadcastChannel.onmessage = (ev) => {
                    if (ev.data.broadcastId !== undefined &&
                        ev.data.broadcastId !== WorkerSafeIdbBackend.broadcastId) {
                        IdbBackend.fireCallbacks(ev.data.dbName, ev.data.literal);
                    }
                };
            }
        }
        getBackendName() {
            return WorkerSafeIdbBackend.backendName;
        }
        async store(literal, history) {
            await super.store(literal, history);
            WorkerSafeIdbBackend.broadcastChannel.postMessage({
                broadcastId: WorkerSafeIdbBackend.broadcastId,
                dbName: this.name,
                literal: literal
            });
        }
    }
    WorkerSafeIdbBackend.backendName = 'worker-safe-idb';
    WorkerSafeIdbBackend.channelName = 'idb-backend-trigger';
    Store.registerBackend(WorkerSafeIdbBackend.backendName, (dbName) => new WorkerSafeIdbBackend(dbName));

    const dictName$1 = 'en_01';
    const words$1 = ['aback', 'abandon', 'abate', 'abbey', 'abdomen', 'abduct', 'abet', 'abide', 'ability', 'able', 'abnormal', 'aboard', 'abolish', 'abortion', 'about', 'above', 'abroad', 'abrupt', 'absence', 'absolute', 'abstract', 'absurd', 'abundant', 'abuse', 'abyss', 'academic', 'accept', 'accident', 'acclaim', 'account', 'accredit', 'accuse', 'ache', 'achieve', 'acid', 'acne', 'acorn', 'acoustic', 'acquire', 'acre', 'across', 'acrylic', 'action', 'actor', 'actress', 'actual', 'acute', 'adamant', 'adapt', 'addition', 'address', 'adept', 'adequate', 'adhere', 'adjacent', 'adjoin', 'adjust', 'admit', 'admonish', 'adobe', 'adopt', 'adore', 'adrift', 'adult', 'advance', 'adverse', 'advice', 'advocate', 'aerial', 'aerobic', 'afar', 'affair', 'affect', 'affirm', 'afflict', 'afford', 'affront', 'afghan', 'afloat', 'afraid', 'after', 'again', 'agency', 'agitate', 'agony', 'agrarian', 'agree', 'ahead', 'ahold', 'aide', 'ailment', 'airborne', 'aircraft', 'airfield', 'airing', 'airline', 'airman', 'airport', 'airtight', 'airway', 'airy', 'aisle', 'akin', 'alarm', 'alas', 'albeit', 'album', 'alcohol', 'alert', 'algae', 'algebra', 'alias', 'alibi', 'alien', 'align', 'alike', 'alive', 'allege', 'alliance', 'allow', 'allude', 'ally', 'almanac', 'almighty', 'almost', 'aloft', 'along', 'aloof', 'aloud', 'alpha', 'alpine', 'already', 'alright', 'also', 'altar', 'alter', 'although', 'altitude', 'aluminum', 'always', 'amass', 'amateur', 'amaze', 'amber', 'ambition', 'amble', 'ambush', 'amend', 'amiable', 'amid', 'amiss', 'ammonia', 'amnesty', 'among', 'amount', 'ample', 'amuse', 'analysis', 'anarchy', 'anatomy', 'ancestor', 'anchor', 'ancient', 'android', 'anecdote', 'anemia', 'anew', 'angel', 'angle', 'angry', 'angst', 'anguish', 'animal', 'ankle', 'annex', 'announce', 'annual', 'anoint', 'anomaly', 'another', 'answer', 'antenna', 'anthem', 'antique', 'antler', 'anxiety', 'anybody', 'anyhow', 'anymore', 'anyone', 'anyplace', 'anything', 'anyway', 'apart', 'apathy', 'aperture', 'apex', 'apiece', 'apology', 'apostle', 'apparent', 'appear', 'apply', 'appoint', 'approach', 'apricot', 'apron', 'aptitude', 'aquarium', 'aquifer', 'arcade', 'arch', 'arctic', 'ardent', 'arduous', 'area', 'arena', 'argue', 'arid', 'arise', 'armchair', 'armor', 'armpit', 'army', 'aroma', 'around', 'arrange', 'arrest', 'arrive', 'arrogant', 'arsenal', 'arson', 'artery', 'article', 'artwork', 'asbestos', 'ascend', 'ascribe', 'ashamed', 'ashore', 'ashtray', 'aside', 'asleep', 'aspect', 'asphalt', 'aspire', 'assault', 'assembly', 'asshole', 'assign', 'assort', 'assume', 'asteroid', 'asthma', 'astonish', 'astute', 'asylum', 'atheist', 'athlete', 'atlas', 'atom', 'atop', 'atrocity', 'attack', 'attempt', 'attitude', 'attorney', 'attract', 'attune', 'atypical', 'auburn', 'auction', 'audience', 'augment', 'august', 'aunt', 'aura', 'auspice', 'austere', 'author', 'autism', 'auto', 'autumn', 'avail', 'avatar', 'avenue', 'average', 'aviation', 'avid', 'avocado', 'avoid', 'await', 'awake', 'award', 'awash', 'away', 'awesome', 'awful', 'awhile', 'awkward', 'axis', 'axle', 'babble', 'babe', 'baby', 'bachelor', 'back', 'bacon', 'bacteria', 'badge', 'baffle', 'bagel', 'baggage', 'bail', 'bait', 'bake', 'balance', 'balcony', 'bald', 'bale', 'balk', 'ball', 'balm', 'balsamic', 'bamboo', 'banana', 'band', 'bang', 'banish', 'bank', 'banner', 'banquet', 'banter', 'baptism', 'barbecue', 'bard', 'barely', 'bargain', 'bark', 'barley', 'barn', 'baron', 'barrier', 'barter', 'basal', 'base', 'bash', 'basic', 'basket', 'basque', 'bass', 'bastard', 'batch', 'bathroom', 'baton', 'battle', 'bayou', 'bazaar', 'beach', 'bead', 'beak', 'beam', 'bean', 'bear', 'beast', 'beat', 'beauty', 'beaver', 'because', 'beckon', 'become', 'bedding', 'bedroom', 'bedside', 'bedtime', 'beech', 'beef', 'beep', 'beer', 'beet', 'before', 'befriend', 'beggar', 'begin', 'behavior', 'behemoth', 'behind', 'behold', 'beige', 'belated', 'believe', 'bell', 'belong', 'belt', 'bemuse', 'bench', 'bend', 'benefit', 'benign', 'bereave', 'berry', 'berth', 'beset', 'beside', 'bestow', 'beta', 'betray', 'between', 'beverage', 'beware', 'bewilder', 'beyond', 'bias', 'bible', 'bicep', 'bicker', 'bicycle', 'bidder', 'bigot', 'bike', 'bikini', 'bile', 'bill', 'binary', 'bind', 'bingo', 'biology', 'biomass', 'biopsy', 'biotech', 'bipolar', 'birch', 'bird', 'birth', 'biscuit', 'bisexual', 'bishop', 'bison', 'bistro', 'bitch', 'bite', 'bitter', 'bizarre', 'black', 'blade', 'blah', 'blame', 'blank', 'blare', 'blast', 'blatant', 'blaze', 'bleak', 'bleed', 'blend', 'bless', 'blight', 'blind', 'bliss', 'blitz', 'blizzard', 'bloat', 'blob', 'block', 'blog', 'bloke', 'blond', 'blood', 'blossom', 'blot', 'blouse', 'blow', 'blue', 'bluff', 'blunt', 'blur', 'blush', 'board', 'boast', 'boat', 'body', 'bogey', 'bogus', 'bohemian', 'boil', 'bold', 'bolster', 'bolt', 'bomb', 'bonanza', 'bond', 'bone', 'bonfire', 'bonnet', 'bonus', 'bony', 'book', 'boom', 'boon', 'boost', 'boot', 'booze', 'border', 'bore', 'born', 'borough', 'borrow', 'bosom', 'boss', 'botch', 'both', 'bottle', 'boulder', 'boundary', 'bouquet', 'bourbon', 'bout', 'bowel', 'bowl', 'boxer', 'boycott', 'boyhood', 'brace', 'brag', 'brain', 'brake', 'branch', 'brass', 'brat', 'brave', 'brawl', 'brazen', 'break', 'breed', 'brew', 'bribe', 'brick', 'bridge', 'brief', 'bright', 'brim', 'bring', 'brisk', 'brittle', 'broad', 'brochure', 'broil', 'broker', 'bronco', 'brood', 'brother', 'brown', 'bruise', 'brunch', 'brush', 'brutal', 'bubble', 'buck', 'buddy', 'budget', 'buff', 'bugger', 'build', 'bulb', 'bulge', 'bulk', 'bullet', 'bump', 'bunch', 'bundle', 'bungalow', 'bunk', 'bunny', 'buoy', 'burden', 'bureau', 'burger', 'burial', 'burly', 'burn', 'burrow', 'burst', 'bury', 'bush', 'business', 'bust', 'busy', 'butcher', 'butler', 'butter', 'buyer', 'buyout', 'buzz', 'bygone', 'bypass', 'byte', 'cabaret', 'cabbage', 'cabinet', 'cable', 'cache', 'cactus', 'caddie', 'cadet', 'cadmium', 'cadre', 'cafe', 'caffeine', 'cage', 'cake', 'calamity', 'calcium', 'calendar', 'calf', 'caliber', 'call', 'calm', 'calorie', 'camera', 'campaign', 'canal', 'cancer', 'candle', 'cane', 'canine', 'cannon', 'canoe', 'canteen', 'canvas', 'canyon', 'capable', 'cape', 'capital', 'capsule', 'captain', 'caravan', 'carbon', 'carcass', 'card', 'care', 'cargo', 'caribou', 'carnival', 'carol', 'carpet', 'carry', 'cart', 'carve', 'cascade', 'case', 'cash', 'casino', 'casket', 'cassette', 'cast', 'casual', 'catalog', 'catch', 'category', 'catfish', 'catholic', 'cattle', 'catwalk', 'caucus', 'cause', 'caution', 'cavalier', 'cave', 'cavity', 'cayenne', 'cease', 'cedar', 'cede', 'ceiling', 'celery', 'cell', 'cement', 'census', 'center', 'ceramic', 'ceremony', 'certain', 'cervical', 'chair', 'chalk', 'chamber', 'change', 'chaos', 'chapter', 'charge', 'chase', 'chat', 'cheap', 'check', 'cheek', 'chef', 'chemical', 'cherish', 'chest', 'chew', 'chicken', 'chide', 'chief', 'child', 'chime', 'chin', 'chip', 'chirp', 'chisel', 'chive', 'chlorine', 'choice', 'choke', 'cholera', 'choose', 'chop', 'chore', 'chronic', 'chubby', 'chuckle', 'chug', 'chunk', 'church', 'chute', 'cider', 'cigar', 'cilantro', 'cinch', 'cinema', 'cinnamon', 'circle', 'citation', 'cite', 'citizen', 'citrus', 'city', 'civil', 'claim', 'clamp', 'clan', 'clap', 'clarify', 'class', 'clatter', 'clause', 'claw', 'clay', 'clear', 'clench', 'clerk', 'clever', 'click', 'client', 'cliff', 'climb', 'clinic', 'clip', 'cloak', 'clock', 'clog', 'clone', 'close', 'clothes', 'cloud', 'clove', 'clown', 'club', 'clue', 'clump', 'cluster', 'clutch', 'coach', 'coal', 'coarse', 'coast', 'coat', 'coauthor', 'coax', 'cobalt', 'cobble', 'cobra', 'cock', 'coconut', 'code', 'codify', 'coed', 'coercion', 'coexist', 'coffee', 'coherent', 'cohort', 'coil', 'coin', 'coke', 'cola', 'cold', 'colitis', 'college', 'color', 'colt', 'column', 'coma', 'combine', 'come', 'comfort', 'comic', 'common', 'company', 'comrade', 'concern', 'conduct', 'cone', 'confirm', 'congress', 'conjure', 'connect', 'conquer', 'consider', 'continue', 'convince', 'cook', 'cool', 'coop', 'cope', 'copper', 'copy', 'coral', 'cord', 'core', 'cork', 'corner', 'coronary', 'corps', 'correct', 'cortex', 'cosmetic', 'cost', 'cottage', 'couch', 'cough', 'could', 'country', 'couple', 'course', 'cousin', 'couture', 'cover', 'coward', 'cowboy', 'cower', 'coworker', 'coyote', 'cozy', 'crab', 'crack', 'cradle', 'craft', 'cramp', 'crane', 'crap', 'crash', 'crater', 'crave', 'crawl', 'crayon', 'crazy', 'create', 'credit', 'creek', 'creole', 'crepe', 'crest', 'crevice', 'crew', 'crib', 'cricket', 'crime', 'cringe', 'cripple', 'crisis', 'critic', 'croak', 'crony', 'crook', 'crop', 'cross', 'crotch', 'crouch', 'crowd', 'crucial', 'crude', 'cruel', 'cruise', 'crumble', 'crunch', 'crush', 'crutch', 'crypt', 'crystal', 'cube', 'cubic', 'cuckoo', 'cucumber', 'cuddle', 'cuff', 'cuisine', 'culinary', 'cull', 'culprit', 'culture', 'cumin', 'cunning', 'cupboard', 'cupcake', 'curator', 'curb', 'cure', 'curfew', 'curious', 'curl', 'current', 'curse', 'curtain', 'curve', 'cushion', 'customer', 'cutback', 'cute', 'cutoff', 'cutter', 'cycle', 'cylinder', 'cynical', 'cypress', 'cyst', 'czar', 'dabble', 'daddy', 'dagger', 'daily', 'dairy', 'daisy', 'damage', 'dame', 'dammit', 'damn', 'damp', 'dance', 'danger', 'dare', 'dark', 'darling', 'darn', 'dart', 'dash', 'data', 'date', 'daughter', 'daunt', 'dawn', 'daycare', 'daydream', 'daylight', 'daytime', 'daze', 'dazzle', 'deacon', 'dead', 'deaf', 'deal', 'dean', 'dear', 'death', 'debate', 'debit', 'debris', 'debt', 'debut', 'decade', 'decent', 'decide', 'deck', 'decline', 'decorate', 'decrease', 'dedicate', 'deduce', 'deed', 'deejay', 'deem', 'deep', 'deer', 'default', 'defense', 'define', 'deflect', 'deform', 'deft', 'defuse', 'defy', 'degree', 'deity', 'delay', 'delegate', 'deliver', 'delta', 'delusion', 'delve', 'demand', 'demeanor', 'demise', 'democrat', 'denial', 'denounce', 'dense', 'dentist', 'deny', 'depart', 'depend', 'depict', 'deploy', 'deposit', 'depress', 'depth', 'deputy', 'derail', 'derby', 'derelict', 'derive', 'describe', 'deserve', 'design', 'desk', 'desolate', 'despite', 'dessert', 'destroy', 'detail', 'detect', 'detonate', 'detract', 'devalue', 'develop', 'device', 'devote', 'diabetes', 'diagnose', 'dial', 'diamond', 'diary', 'diaspora', 'dice', 'dictate', 'diehard', 'diesel', 'diet', 'differ', 'digest', 'digger', 'digital', 'dignity', 'dilemma', 'diligent', 'dill', 'dilute', 'dime', 'diminish', 'dimple', 'dine', 'dinner', 'dinosaur', 'diocese', 'dioxide', 'diplomat', 'direct', 'dirt', 'disagree', 'disband', 'discuss', 'disdain', 'disease', 'disgust', 'dish', 'disk', 'dislike', 'dismiss', 'disorder', 'display', 'disrupt', 'dissolve', 'district', 'ditch', 'diva', 'dive', 'divide', 'divorce', 'divulge', 'dizzy', 'dock', 'doctor', 'document', 'dodge', 'doggy', 'dogma', 'dole', 'dollar', 'dolphin', 'domain', 'domestic', 'dominate', 'donate', 'donkey', 'donor', 'doom', 'door', 'dope', 'dorm', 'dosage', 'dose', 'double', 'dough', 'douse', 'down', 'dozen', 'drab', 'draft', 'drag', 'drain', 'drake', 'dramatic', 'drape', 'drastic', 'draw', 'dream', 'dredge', 'drench', 'dress', 'dribble', 'drift', 'drill', 'drink', 'drip', 'drive', 'drizzle', 'drone', 'drool', 'drop', 'drought', 'drown', 'drug', 'drum', 'drunken', 'dryer', 'dual', 'dubious', 'duchess', 'duck', 'duct', 'dude', 'duel', 'duet', 'dugout', 'duke', 'dull', 'duly', 'dumb', 'dummy', 'dump', 'dune', 'dung', 'dunk', 'dupe', 'durable', 'during', 'dusk', 'dust', 'dutch', 'duty', 'dwelling', 'dwindle', 'dynamic', 'each', 'eager', 'eagle', 'early', 'earmark', 'earn', 'earring', 'earth', 'ease', 'east', 'easy', 'eater', 'ebony', 'echo', 'eclectic', 'eclipse', 'ecology', 'economic', 'ecstasy', 'edge', 'edgy', 'edible', 'editor', 'educate', 'eerie', 'effect', 'efficacy', 'effluent', 'effort', 'eggplant', 'eight', 'either', 'eject', 'elapse', 'elastic', 'elbow', 'elder', 'election', 'elegant', 'element', 'elephant', 'elevator', 'elicit', 'eligible', 'elite', 'elongate', 'eloquent', 'else', 'elude', 'elusive', 'email', 'emanate', 'embassy', 'embed', 'emblem', 'embody', 'embrace', 'emerge', 'emigrant', 'eminent', 'emission', 'emit', 'emotion', 'empathy', 'emperor', 'emphasis', 'empire', 'employee', 'empower', 'empress', 'empty', 'emulate', 'enable', 'enact', 'enamel', 'encase', 'enchant', 'encircle', 'enclose', 'encode', 'encroach', 'endanger', 'endeavor', 'endorse', 'endure', 'enemy', 'energy', 'enforce', 'engage', 'engender', 'engine', 'engrave', 'engulf', 'enhance', 'enigma', 'enjoy', 'enlarge', 'enlist', 'enormous', 'enough', 'enrage', 'enrich', 'enroll', 'ensemble', 'enshrine', 'enslave', 'ensure', 'entail', 'enter', 'enthrall', 'entire', 'entrance', 'envelope', 'envision', 'envoy', 'envy', 'enzyme', 'epic', 'epidemic', 'epiphany', 'episode', 'epoch', 'equal', 'equip', 'erase', 'erection', 'erode', 'erosion', 'erotic', 'errand', 'error', 'erupt', 'escape', 'eschew', 'escort', 'esoteric', 'espouse', 'espresso', 'essay', 'essence', 'estate', 'esteem', 'estimate', 'estrogen', 'estuary', 'etch', 'eternal', 'ethanol', 'ethical', 'ethnic', 'ethos', 'euphoria', 'euro', 'evacuate', 'evade', 'evaluate', 'evasion', 'even', 'ever', 'evict', 'evidence', 'evil', 'evoke', 'evolve', 'exact', 'exalt', 'example', 'excavate', 'except', 'exchange', 'excite', 'exclude', 'excuse', 'execute', 'exempt', 'exercise', 'exhaust', 'exhibit', 'exile', 'exist', 'exit', 'exodus', 'exotic', 'expand', 'expect', 'expire', 'explain', 'export', 'express', 'extant', 'extend', 'extinct', 'extra', 'exude', 'eyebrow', 'eyelid', 'eyepiece', 'eyesight', 'fable', 'fabric', 'fabulous', 'facade', 'face', 'facility', 'fact', 'faculty', 'fade', 'fail', 'faint', 'fair', 'faith', 'fake', 'falcon', 'fall', 'false', 'falter', 'fame', 'family', 'famous', 'fanatic', 'fancy', 'fanfare', 'fang', 'fantasy', 'faraway', 'farce', 'fare', 'farm', 'fart', 'fascist', 'fashion', 'fast', 'fatal', 'fate', 'father', 'fatigue', 'fatty', 'faucet', 'fault', 'fauna', 'favor', 'fawn', 'fear', 'feasible', 'feature', 'federal', 'feeble', 'feed', 'feel', 'feign', 'feisty', 'fellow', 'felony', 'female', 'feminist', 'fence', 'fend', 'fennel', 'feral', 'ferment', 'fern', 'ferry', 'fertile', 'fervent', 'festival', 'fetal', 'fetch', 'fetus', 'feud', 'fever', 'fiance', 'fiasco', 'fiber', 'fiction', 'fiddle', 'fidelity', 'fidget', 'field', 'fierce', 'fifteen', 'fight', 'figure', 'filament', 'file', 'fill', 'film', 'filter', 'final', 'find', 'fine', 'finger', 'finish', 'fire', 'firm', 'first', 'fiscal', 'fish', 'fist', 'five', 'fixate', 'fixture', 'flag', 'flail', 'flake', 'flame', 'flank', 'flap', 'flare', 'flash', 'flat', 'flaunt', 'flavor', 'flaw', 'flea', 'fleck', 'flee', 'flesh', 'flexible', 'flick', 'flier', 'flight', 'flimsy', 'fling', 'flip', 'flirt', 'flit', 'float', 'flock', 'floor', 'flop', 'flora', 'flour', 'flow', 'fluent', 'fluffy', 'fluid', 'fluke', 'flurry', 'flush', 'flutter', 'flux', 'foam', 'focal', 'focus', 'fodder', 'foggy', 'foil', 'fold', 'foliage', 'folk', 'follow', 'fond', 'font', 'food', 'fool', 'foot', 'forage', 'forbid', 'force', 'foreign', 'forfeit', 'forget', 'fork', 'forlorn', 'form', 'forsake', 'forth', 'forum', 'forward', 'fossil', 'foster', 'foul', 'founder', 'four', 'foyer', 'fraction', 'fragment', 'frail', 'frame', 'frank', 'fraud', 'fray', 'freak', 'freckle', 'free', 'freight', 'frenzy', 'frequent', 'fresh', 'fret', 'friar', 'friction', 'fridge', 'friend', 'frighten', 'fringe', 'frog', 'from', 'front', 'frost', 'frown', 'fruit', 'fudge', 'fuel', 'fugitive', 'fulfill', 'full', 'fumble', 'fume', 'function', 'fund', 'funeral', 'fungus', 'funk', 'funny', 'furious', 'furnish', 'furrow', 'furtive', 'fury', 'fuse', 'fusion', 'fuss', 'futile', 'future', 'fuzzy', 'gable', 'gadget', 'gain', 'gait', 'galaxy', 'gale', 'gallery', 'gamble', 'game', 'gamma', 'gang', 'gape', 'garage', 'garbage', 'garden', 'garlic', 'garment', 'garnish', 'garrison', 'gash', 'gasoline', 'gasp', 'gastric', 'gate', 'gather', 'gauge', 'gaze', 'gear', 'geek', 'gender', 'general', 'genius', 'genocide', 'genre', 'gentle', 'genuine', 'geology', 'geometry', 'germ', 'gesture', 'getaway', 'ghastly', 'ghetto', 'ghost', 'giant', 'giddy', 'gift', 'gigantic', 'giggle', 'gild', 'gimmick', 'ginger', 'girl', 'give', 'glacier', 'glad', 'glamor', 'glance', 'glare', 'glass', 'glaze', 'gleam', 'glee', 'glide', 'glimpse', 'glint', 'glisten', 'glitter', 'gloat', 'global', 'gloom', 'glory', 'gloss', 'glove', 'glow', 'glucose', 'glue', 'glum', 'gnaw', 'goad', 'goal', 'goat', 'gobble', 'goblin', 'goddamn', 'goggle', 'gold', 'golf', 'good', 'goofy', 'goon', 'goose', 'gorgeous', 'gorilla', 'gosh', 'gospel', 'gossip', 'gothic', 'gouge', 'gourmet', 'governor', 'gown', 'grab', 'grace', 'grade', 'graft', 'grain', 'gram', 'grand', 'graph', 'grass', 'grateful', 'grave', 'gray', 'graze', 'great', 'green', 'grenade', 'grid', 'grief', 'grill', 'grim', 'grin', 'grip', 'grit', 'grizzly', 'groan', 'grocery', 'groin', 'groom', 'grope', 'gross', 'group', 'grove', 'grow', 'grub', 'grudge', 'grueling', 'gruff', 'grumble', 'grunt', 'guard', 'guess', 'guide', 'guilty', 'guise', 'guitar', 'gulf', 'gull', 'gulp', 'gunfire', 'gunman', 'gunner', 'gunpoint', 'gunshot', 'gurgle', 'guru', 'gush', 'gust', 'gutter', 'gypsy', 'habit', 'hack', 'hail', 'hair', 'half', 'hall', 'halo', 'halt', 'halve', 'hammer', 'hamper', 'hand', 'hang', 'happen', 'harass', 'harbor', 'hard', 'hare', 'harm', 'harness', 'harp', 'harrow', 'harsh', 'harvest', 'hash', 'hassle', 'hasty', 'hatch', 'hate', 'hatred', 'haul', 'haunt', 'have', 'havoc', 'hawk', 'hazard', 'haze', 'hazy', 'head', 'health', 'heap', 'hear', 'heat', 'heavy', 'heck', 'hectare', 'hedge', 'heed', 'heel', 'hefty', 'hegemony', 'height', 'heir', 'helium', 'hell', 'helmet', 'help', 'hence', 'herald', 'herb', 'herd', 'here', 'heritage', 'hero', 'herring', 'herself', 'hesitate', 'heyday', 'hiccup', 'hide', 'high', 'hijack', 'hike', 'hill', 'himself', 'hinder', 'hinge', 'hint', 'hippie', 'hire', 'hiss', 'history', 'hitch', 'hitherto', 'hitter', 'hive', 'hoard', 'hoax', 'hobby', 'hockey', 'hoist', 'hold', 'hole', 'holiday', 'hollow', 'holster', 'holy', 'homage', 'home', 'homicide', 'honest', 'honk', 'honor', 'hood', 'hoof', 'hook', 'hoop', 'hoot', 'hope', 'hopper', 'horde', 'horizon', 'hormone', 'horn', 'horrible', 'horse', 'hose', 'hospital', 'host', 'hotel', 'hotline', 'hound', 'hour', 'house', 'hover', 'however', 'howl', 'huddle', 'huff', 'huge', 'hulk', 'hull', 'human', 'humble', 'humidity', 'humor', 'hump', 'hunch', 'hundred', 'hungry', 'hunk', 'hunt', 'hurdle', 'hurl', 'hurry', 'hurt', 'husband', 'hush', 'husk', 'hustle', 'hybrid', 'hydrogen', 'hygiene', 'hymn', 'hype', 'hypnosis', 'hysteria', 'ibidem', 'iceberg', 'icing', 'icon', 'idea', 'identify', 'ideology', 'idiot', 'idle', 'idol', 'idyllic', 'ignite', 'ignore', 'illegal', 'illicit', 'illness', 'illusion', 'image', 'imam', 'imbue', 'imitate', 'immature', 'immense', 'imminent', 'immoral', 'immune', 'impact', 'imperial', 'imply', 'import', 'improve', 'impulse', 'inactive', 'incense', 'inch', 'incident', 'include', 'income', 'increase', 'incur', 'indeed', 'indicate', 'indoor', 'industry', 'inept', 'inequity', 'inert', 'infant', 'infect', 'infinite', 'inflict', 'inform', 'infrared', 'infuse', 'ingest', 'ingrain', 'inhabit', 'inherent', 'inhibit', 'initial', 'inject', 'injury', 'inland', 'inlet', 'inmate', 'innate', 'inner', 'inning', 'innocent', 'innuendo', 'input', 'inquiry', 'inroad', 'insane', 'inscribe', 'insect', 'inside', 'insofar', 'inspire', 'instead', 'insult', 'intact', 'interest', 'intimate', 'into', 'intrigue', 'inundate', 'invade', 'invest', 'invite', 'involve', 'inward', 'iron', 'irritate', 'island', 'isle', 'isolate', 'isotope', 'issue', 'itch', 'item', 'itself', 'ivory', 'jacket', 'jade', 'jagged', 'jaguar', 'jail', 'janitor', 'jargon', 'jasmine', 'jazz', 'jealous', 'jeans', 'jeep', 'jeez', 'jelly', 'jeopardy', 'jerk', 'jersey', 'jewelry', 'jingle', 'jinx', 'jockey', 'john', 'join', 'joke', 'jolly', 'jolt', 'jostle', 'journal', 'joyous', 'jubilee', 'judge', 'judicial', 'juggle', 'juice', 'jumble', 'jump', 'junction', 'jungle', 'junior', 'junk', 'juror', 'jury', 'just', 'juvenile', 'kaiser', 'karate', 'karma', 'kayak', 'keel', 'keen', 'keep', 'kennel', 'kernel', 'ketchup', 'kettle', 'keyboard', 'keynote', 'keystone', 'keyword', 'khaki', 'kick', 'kidnap', 'kill', 'kiln', 'kilogram', 'kind', 'kinetic', 'king', 'kinship', 'kiosk', 'kiss', 'kitchen', 'kite', 'kitten', 'knack', 'knead', 'knee', 'knife', 'knight', 'knit', 'knob', 'knock', 'knot', 'know', 'knuckle', 'kosher', 'label', 'labor', 'lace', 'lack', 'lacquer', 'lacrosse', 'ladder', 'laden', 'ladle', 'lady', 'lagoon', 'lake', 'lamb', 'lament', 'laminate', 'lamp', 'lance', 'land', 'lane', 'language', 'lantern', 'lapel', 'lapse', 'laptop', 'large', 'lark', 'larva', 'laser', 'lash', 'lass', 'last', 'latch', 'late', 'latino', 'latter', 'laud', 'laugh', 'launch', 'laureate', 'lava', 'lavender', 'lavish', 'lawmaker', 'lawn', 'lawsuit', 'lawyer', 'layer', 'layout', 'lazy', 'lead', 'leaf', 'league', 'leak', 'lean', 'leap', 'learn', 'lease', 'leather', 'leave', 'lecture', 'ledge', 'leek', 'leftist', 'legal', 'legend', 'legion', 'leisure', 'lemon', 'lend', 'length', 'lens', 'lentil', 'leopard', 'lesbian', 'lesion', 'less', 'lest', 'lethal', 'letter', 'leukemia', 'level', 'levy', 'lexical', 'liable', 'liaison', 'liar', 'liberal', 'library', 'license', 'lick', 'lieu', 'life', 'lift', 'ligament', 'light', 'likable', 'like', 'lilac', 'lily', 'limb', 'lime', 'limit', 'limo', 'limp', 'line', 'linger', 'link', 'linoleum', 'lion', 'lipstick', 'liquid', 'listen', 'litany', 'literal', 'little', 'liturgy', 'live', 'lizard', 'load', 'loaf', 'loan', 'loathe', 'lobby', 'lobe', 'lobster', 'local', 'lock', 'locus', 'lodge', 'loft', 'logger', 'logic', 'logo', 'loin', 'lonely', 'long', 'look', 'loom', 'loop', 'loose', 'loot', 'lopsided', 'lord', 'lore', 'lorry', 'lose', 'loss', 'lotion', 'lottery', 'lotus', 'loud', 'lounge', 'lousy', 'lovable', 'love', 'lowland', 'loyal', 'lucid', 'lucky', 'luggage', 'lull', 'lumber', 'luminous', 'lump', 'lunar', 'lunch', 'lung', 'lurch', 'lure', 'lurk', 'lush', 'lust', 'luxury', 'lymph', 'lyric', 'macaroni', 'machine', 'macro', 'madame', 'madden', 'madman', 'mafia', 'magazine', 'maggot', 'magic', 'magnet', 'mahogany', 'maid', 'mail', 'maim', 'main', 'maize', 'majestic', 'major', 'make', 'malaria', 'male', 'malice', 'mall', 'malt', 'mama', 'mammal', 'manage', 'mandate', 'maneuver', 'mango', 'manhood', 'manifest', 'mankind', 'manner', 'manor', 'manpower', 'mansion', 'mantle', 'manual', 'many', 'maple', 'marathon', 'marble', 'march', 'mare', 'margin', 'marine', 'market', 'maroon', 'marquee', 'marriage', 'marsh', 'martial', 'marvel', 'mascara', 'mash', 'mask', 'mason', 'mass', 'master', 'match', 'material', 'math', 'matrix', 'matter', 'mature', 'maverick', 'maximum', 'maybe', 'mayhem', 'mayor', 'maze', 'meadow', 'meager', 'meal', 'mean', 'measure', 'meat', 'mechanic', 'medal', 'meddle', 'media', 'medley', 'meek', 'meet', 'melanoma', 'meld', 'mellow', 'melody', 'melt', 'member', 'memento', 'memory', 'menace', 'mend', 'mention', 'menu', 'merchant', 'mere', 'merge', 'merit', 'mermaid', 'merry', 'mesh', 'message', 'metal', 'meter', 'method', 'metro', 'micro', 'midair', 'middle', 'midfield', 'midlife', 'midnight', 'midst', 'midterm', 'midway', 'might', 'migrant', 'mild', 'mile', 'military', 'milk', 'million', 'mime', 'mimic', 'mince', 'mind', 'mineral', 'mingle', 'minister', 'mink', 'minor', 'mint', 'minute', 'miracle', 'mire', 'mirror', 'mischief', 'misery', 'misguide', 'mishap', 'mislead', 'mismatch', 'misplace', 'miss', 'mistake', 'misuse', 'mite', 'mitigate', 'mitt', 'mixer', 'mixture', 'moan', 'moat', 'mobile', 'mobster', 'mock', 'model', 'modify', 'module', 'mogul', 'moist', 'mold', 'molecule', 'molten', 'moment', 'mommy', 'monarch', 'money', 'monitor', 'monkey', 'monopoly', 'monster', 'month', 'monument', 'mood', 'moon', 'moor', 'moot', 'moral', 'morbid', 'more', 'morgue', 'morning', 'morph', 'mortgage', 'mosaic', 'mosque', 'moss', 'most', 'motel', 'mother', 'motion', 'motor', 'motto', 'mountain', 'mourn', 'mouse', 'mouth', 'move', 'movie', 'mower', 'much', 'muck', 'muddy', 'muffin', 'mulch', 'mule', 'mull', 'multiple', 'mumble', 'mummy', 'munch', 'mundane', 'munition', 'mural', 'murder', 'murky', 'murmur', 'muscle', 'museum', 'mushroom', 'music', 'mussel', 'must', 'mutation', 'mute', 'mutter', 'mutual', 'muzzle', 'myriad', 'myself', 'mystery', 'myth', 'nail', 'naive', 'naked', 'name', 'nanny', 'napkin', 'narcotic', 'narrow', 'nasal', 'nascent', 'nasty', 'national', 'natural', 'naughty', 'nausea', 'naval', 'nave', 'navigate', 'navy', 'near', 'neat', 'nebula', 'neck', 'nectar', 'need', 'negative', 'neglect', 'neighbor', 'neither', 'neon', 'nephew', 'nerd', 'nerve', 'nest', 'network', 'neural', 'neutral', 'never', 'newborn', 'newcomer', 'newfound', 'newly', 'news', 'next', 'nibble', 'nice', 'niche', 'nickname', 'nicotine', 'niece', 'night', 'nimble', 'nine', 'ninth', 'nipple', 'nitrogen', 'nobility', 'noble', 'nobody', 'node', 'noise', 'nomad', 'nominee', 'none', 'nonsense', 'noodle', 'nook', 'noon', 'noose', 'nope', 'normal', 'north', 'nose', 'nostril', 'notable', 'notch', 'note', 'nothing', 'notice', 'noun', 'nourish', 'novel', 'novice', 'nowadays', 'nowhere', 'nozzle', 'nuance', 'nuclear', 'nude', 'nudge', 'nudity', 'nugget', 'nuisance', 'number', 'numerous', 'nurse', 'nurture', 'nutrient', 'nylon', 'oath', 'obesity', 'obey', 'object', 'oblige', 'obscure', 'observe', 'obsolete', 'obstacle', 'obtain', 'obvious', 'occasion', 'occur', 'ocean', 'odds', 'odor', 'offer', 'office', 'offset', 'often', 'okay', 'olive', 'ominous', 'omission', 'omit', 'onboard', 'once', 'oneself', 'onetime', 'ongoing', 'onion', 'online', 'only', 'onset', 'onstage', 'onto', 'onward', 'oops', 'ooze', 'opal', 'opaque', 'open', 'operate', 'opinion', 'oppose', 'oppress', 'option', 'oracle', 'oral', 'orange', 'orbit', 'orchard', 'ordain', 'order', 'ordinary', 'organize', 'orient', 'original', 'ornament', 'orphan', 'orthodox', 'other', 'ought', 'ounce', 'oust', 'outbreak', 'outcome', 'outdoor', 'outer', 'outfit', 'outgoing', 'outing', 'outline', 'output', 'outrage', 'outside', 'outward', 'oval', 'oven', 'over', 'owner', 'oxide', 'oxygen', 'oyster', 'ozone', 'pace', 'pack', 'pact', 'paddle', 'padre', 'pagan', 'page', 'pain', 'pair', 'pajama', 'palace', 'pale', 'palm', 'pamphlet', 'pancake', 'panel', 'panic', 'pants', 'papa', 'paper', 'parallel', 'parcel', 'pardon', 'parent', 'parish', 'park', 'parlor', 'parole', 'parrot', 'parsley', 'part', 'pass', 'past', 'patch', 'patent', 'path', 'patient', 'patrol', 'pattern', 'pause', 'pave', 'pavilion', 'pawn', 'payable', 'payback', 'paycheck', 'payment', 'payoff', 'payroll', 'peace', 'peak', 'peanut', 'pearl', 'peasant', 'pebble', 'pecan', 'peculiar', 'pedal', 'peek', 'peel', 'peer', 'penalty', 'pencil', 'pend', 'penny', 'pension', 'people', 'pepper', 'percent', 'perfect', 'perhaps', 'period', 'perjury', 'perk', 'permit', 'perplex', 'person', 'pertain', 'perverse', 'pest', 'petal', 'petition', 'petrol', 'petty', 'phantom', 'pharmacy', 'phase', 'phone', 'photo', 'phrase', 'physical', 'piano', 'pick', 'picnic', 'picture', 'piece', 'pier', 'pigeon', 'pigment', 'pile', 'pilgrim', 'pill', 'pilot', 'pinch', 'pine', 'pink', 'pinpoint', 'pint', 'pioneer', 'pipe', 'pirate', 'pistol', 'pitch', 'pity', 'pivotal', 'pixel', 'pizza', 'place', 'plague', 'plain', 'plan', 'plaque', 'plastic', 'plate', 'play', 'plaza', 'please', 'pledge', 'plenty', 'plight', 'plot', 'plow', 'pluck', 'plug', 'plum', 'plunge', 'plus', 'plywood', 'poach', 'pocket', 'podium', 'poem', 'poet', 'poignant', 'point', 'poison', 'poke', 'polar', 'pole', 'police', 'poll', 'polo', 'polymer', 'pond', 'pony', 'pool', 'poor', 'popcorn', 'pope', 'popular', 'porch', 'pore', 'pork', 'porn', 'port', 'pose', 'position', 'possible', 'post', 'potato', 'potent', 'pottery', 'pouch', 'poultry', 'pound', 'pour', 'poverty', 'powder', 'power', 'practice', 'praise', 'pray', 'preach', 'precise', 'predict', 'prefer', 'pregnant', 'preheat', 'premise', 'prepare', 'present', 'pretty', 'previous', 'prey', 'price', 'pride', 'priest', 'primary', 'print', 'prior', 'prison', 'private', 'prize', 'problem', 'process', 'produce', 'profit', 'program', 'prohibit', 'project', 'prolong', 'promise', 'prone', 'proof', 'property', 'prospect', 'protect', 'proud', 'provide', 'proxy', 'prudent', 'prune', 'psychic', 'public', 'pudding', 'pueblo', 'puff', 'pull', 'pulp', 'pulse', 'pump', 'punch', 'pundit', 'punish', 'punk', 'punt', 'pupil', 'puppy', 'purchase', 'pure', 'purge', 'purity', 'purpose', 'pursue', 'push', 'putt', 'puzzle', 'pyramid', 'quaint', 'quake', 'quality', 'quantity', 'quarter', 'queen', 'query', 'question', 'queue', 'quick', 'quid', 'quiet', 'quilt', 'quite', 'quiver', 'quiz', 'quote', 'rabbit', 'race', 'racial', 'rack', 'radar', 'radio', 'raft', 'rage', 'ragged', 'raid', 'rail', 'rain', 'raise', 'rake', 'rally', 'ramp', 'ranch', 'random', 'range', 'rank', 'ransom', 'rapid', 'rapper', 'rare', 'rash', 'rate', 'rather', 'rating', 'rattle', 'ravage', 'rave', 'razor', 'reach', 'read', 'reaffirm', 'real', 'reap', 'rear', 'reason', 'rebate', 'rebel', 'rebound', 'rebuild', 'recall', 'recent', 'recipe', 'reckless', 'reclaim', 'record', 'recruit', 'recur', 'recycle', 'redeem', 'redskin', 'reduce', 'reed', 'reef', 'reel', 'refer', 'refine', 'reflect', 'reform', 'refresh', 'refuse', 'regard', 'region', 'regret', 'regular', 'rehab', 'rehearse', 'reign', 'rein', 'reject', 'rejoice', 'relate', 'release', 'religion', 'relocate', 'rely', 'remain', 'remember', 'remind', 'remnant', 'remove', 'rename', 'render', 'renew', 'renown', 'rent', 'reopen', 'repair', 'repeat', 'replace', 'report', 'repress', 'reptile', 'republic', 'require', 'rescue', 'research', 'reshape', 'resident', 'resource', 'respect', 'rest', 'result', 'retain', 'rethink', 'retire', 'retort', 'retreat', 'return', 'reunion', 'reveal', 'review', 'revolt', 'reward', 'rewrite', 'rhetoric', 'rhyme', 'rhythm', 'ribbon', 'rice', 'rich', 'riddle', 'ride', 'ridge', 'ridicule', 'rifle', 'rift', 'right', 'rigid', 'rigorous', 'ring', 'rinse', 'riot', 'ripe', 'ripple', 'rise', 'risk', 'rite', 'ritual', 'rival', 'river', 'road', 'roam', 'roar', 'roast', 'robbery', 'robe', 'robot', 'robust', 'rock', 'rodent', 'rogue', 'role', 'roll', 'roman', 'roof', 'rookie', 'room', 'root', 'rope', 'rosemary', 'roster', 'rotate', 'rotten', 'rough', 'round', 'rouse', 'route', 'rover', 'royal', 'rubber', 'rude', 'ruffle', 'rugby', 'rugged', 'ruin', 'rule', 'ruling', 'rumble', 'rumor', 'runaway', 'rundown', 'runner', 'runoff', 'runway', 'rupture', 'rural', 'rush', 'rust', 'ruthless', 'sabotage', 'sack', 'sacred', 'saddle', 'safe', 'saga', 'sage', 'sail', 'saint', 'sake', 'salad', 'sale', 'salient', 'salmon', 'salon', 'salsa', 'salt', 'salute', 'salvage', 'same', 'sample', 'sanction', 'sand', 'sane', 'sanity', 'satisfy', 'saturate', 'sauce', 'sausage', 'savage', 'save', 'savior', 'savor', 'savvy', 'scale', 'scam', 'scan', 'scare', 'scatter', 'scene', 'schedule', 'school', 'science', 'scissor', 'scold', 'scoop', 'scope', 'score', 'scotch', 'scout', 'scowl', 'scramble', 'scream', 'script', 'scroll', 'scrub', 'sculpt', 'scurry', 'seafood', 'seal', 'seam', 'search', 'season', 'seat', 'second', 'secret', 'section', 'security', 'sedan', 'sediment', 'seduce', 'seed', 'seek', 'seem', 'seep', 'segment', 'seize', 'seldom', 'select', 'self', 'sell', 'semantic', 'semester', 'seminar', 'senate', 'send', 'senior', 'sense', 'sentence', 'separate', 'sequence', 'serene', 'sergeant', 'series', 'sermon', 'serum', 'serve', 'session', 'setback', 'settle', 'setup', 'several', 'sewage', 'sewer', 'sexual', 'sexy', 'shabby', 'shack', 'shadow', 'shaft', 'shake', 'shall', 'shame', 'shape', 'share', 'shatter', 'shave', 'shear', 'shed', 'sheet', 'sheik', 'shell', 'shepherd', 'sheriff', 'shield', 'shift', 'shimmer', 'shine', 'ship', 'shirt', 'shit', 'shiver', 'shock', 'shoe', 'shoot', 'shop', 'short', 'shotgun', 'should', 'shove', 'show', 'shred', 'shrimp', 'shroud', 'shrug', 'shudder', 'shuffle', 'shun', 'shut', 'sibling', 'sick', 'side', 'siege', 'sift', 'sight', 'sign', 'silence', 'silicon', 'silk', 'silly', 'silver', 'similar', 'simmer', 'simple', 'simulate', 'since', 'single', 'sinister', 'sink', 'sinus', 'siren', 'sister', 'sitcom', 'site', 'sitter', 'situate', 'sixth', 'sizable', 'size', 'sizzle', 'skate', 'skeleton', 'skeptic', 'sketch', 'skew', 'skid', 'skier', 'skill', 'skim', 'skin', 'skip', 'skirt', 'skull', 'skyline', 'slab', 'slack', 'slam', 'slant', 'slap', 'slash', 'slate', 'slavery', 'slay', 'sled', 'sleep', 'slender', 'slice', 'slide', 'slight', 'slim', 'sling', 'slip', 'slit', 'slogan', 'slope', 'slot', 'slow', 'slug', 'slump', 'slut', 'smack', 'small', 'smart', 'smash', 'smear', 'smell', 'smile', 'smirk', 'smoke', 'smooth', 'smother', 'smuggle', 'snack', 'snag', 'snail', 'snake', 'snap', 'snarl', 'snatch', 'sneak', 'sneer', 'sniff', 'sniper', 'snore', 'snow', 'snug', 'soak', 'soap', 'soar', 'sober', 'soccer', 'social', 'sock', 'soda', 'sodium', 'sofa', 'soft', 'soil', 'solar', 'soldier', 'sole', 'solid', 'solo', 'solution', 'solve', 'somber', 'some', 'song', 'soon', 'soothe', 'soprano', 'sore', 'sorry', 'sort', 'soul', 'sound', 'soup', 'source', 'south', 'souvenir', 'soviet', 'soybean', 'space', 'spade', 'span', 'spare', 'spatial', 'spawn', 'speak', 'special', 'speech', 'spell', 'spend', 'sperm', 'sphere', 'spice', 'spider', 'spike', 'spill', 'spin', 'spirit', 'spit', 'splash', 'splendid', 'split', 'spoil', 'sponsor', 'spoon', 'sport', 'spot', 'spouse', 'spray', 'spread', 'spring', 'sprout', 'spruce', 'spur', 'square', 'squeeze', 'squint', 'stable', 'stack', 'stadium', 'staff', 'stage', 'stair', 'stake', 'stalk', 'stamp', 'stand', 'staple', 'start', 'stash', 'state', 'stay', 'steal', 'steel', 'stellar', 'stem', 'step', 'stereo', 'stew', 'stick', 'stiff', 'stigma', 'still', 'stimulus', 'sting', 'stir', 'stitch', 'stock', 'stomach', 'stone', 'stool', 'stop', 'story', 'stout', 'stove', 'strategy', 'street', 'strike', 'strong', 'struggle', 'stubborn', 'student', 'stuff', 'stumble', 'stun', 'stupid', 'sturdy', 'style', 'subdue', 'subgroup', 'subject', 'sublime', 'submit', 'subpoena', 'subsidy', 'subtle', 'suburb', 'subway', 'success', 'such', 'suck', 'sudden', 'suffer', 'sugar', 'suggest', 'suicide', 'suit', 'sulfur', 'summer', 'sunlight', 'sunny', 'sunrise', 'sunset', 'super', 'support', 'supreme', 'sure', 'surface', 'surgery', 'surprise', 'surround', 'survey', 'suspect', 'sustain', 'swallow', 'swamp', 'swan', 'swap', 'swarm', 'swat', 'sway', 'swear', 'sweet', 'swell', 'swift', 'swim', 'swing', 'swipe', 'swirl', 'switch', 'swivel', 'swoop', 'sword', 'syllable', 'symbol', 'symmetry', 'symptom', 'syndrome', 'syringe', 'syrup', 'system', 'table', 'taboo', 'tackle', 'tactic', 'tail', 'taint', 'take', 'talent', 'talk', 'tall', 'tame', 'tamper', 'tangle', 'tank', 'tape', 'target', 'tariff', 'tart', 'task', 'taste', 'tattoo', 'taunt', 'taut', 'tavern', 'taxation', 'taxi', 'taxpayer', 'teacher', 'team', 'tear', 'teaspoon', 'tech', 'tedious', 'teenager', 'televise', 'tell', 'temper', 'tenant', 'tend', 'tenet', 'tennis', 'tenor', 'tension', 'tent', 'tenure', 'term', 'terrible', 'test', 'text', 'than', 'that', 'thaw', 'theater', 'theft', 'their', 'theme', 'then', 'theory', 'there', 'thesis', 'they', 'thick', 'thief', 'thigh', 'think', 'third', 'this', 'thorough', 'thousand', 'three', 'thrill', 'through', 'thrust', 'thud', 'thug', 'thumb', 'thunder', 'thus', 'thwart', 'thyme', 'ticket', 'tidal', 'tide', 'tidy', 'tier', 'tiger', 'tight', 'tile', 'till', 'tilt', 'timber', 'time', 'tingle', 'tinker', 'tint', 'tiny', 'tire', 'tissue', 'titan', 'title', 'toast', 'tobacco', 'today', 'toddler', 'together', 'toilet', 'token', 'tolerate', 'toll', 'tomato', 'tomb', 'tomorrow', 'tone', 'tongue', 'tonight', 'tool', 'tooth', 'topic', 'topple', 'torch', 'torment', 'tornado', 'torque', 'torso', 'torture', 'toss', 'total', 'tote', 'touch', 'tough', 'tour', 'tout', 'toward', 'tower', 'town', 'toxic', 'track', 'trade', 'traffic', 'tragedy', 'train', 'tramp', 'transfer', 'trap', 'trash', 'trauma', 'travel', 'tray', 'treat', 'tree', 'trek', 'tremble', 'trend', 'trial', 'tribal', 'trick', 'trigger', 'trillion', 'trim', 'trio', 'trip', 'triumph', 'trivial', 'troll', 'troop', 'tropical', 'trot', 'trouble', 'truck', 'true', 'trump', 'trunk', 'trust', 'truth', 'tsunami', 'tube', 'tuck', 'tuition', 'tumble', 'tumor', 'tuna', 'tune', 'tunnel', 'turbine', 'turf', 'turkey', 'turmoil', 'turn', 'turtle', 'tutor', 'tweak', 'twelve', 'twenty', 'twice', 'twig', 'twilight', 'twin', 'twist', 'twitch', 'type', 'typical', 'tyranny', 'ugly', 'ulcer', 'ultimate', 'umbrella', 'umpire', 'unable', 'unaware', 'unborn', 'uncle', 'uncommon', 'under', 'undo', 'uneasy', 'unequal', 'uneven', 'unfair', 'unfold', 'unhappy', 'uniform', 'union', 'unique', 'unison', 'unit', 'universe', 'unjust', 'unknown', 'unlawful', 'unless', 'unlike', 'unlock', 'unpack', 'unravel', 'unrest', 'unsafe', 'unseen', 'unstable', 'unsure', 'until', 'unto', 'unusual', 'unveil', 'unwanted', 'upbeat', 'upcoming', 'update', 'upgrade', 'upheaval', 'uphill', 'uphold', 'uplift', 'upon', 'upper', 'upright', 'upscale', 'upset', 'upside', 'upstairs', 'upward', 'uranium', 'urban', 'urge', 'urine', 'usable', 'usage', 'user', 'usher', 'usual', 'utility', 'utter', 'vacation', 'vaccine', 'vacuum', 'vague', 'vain', 'valid', 'valley', 'value', 'valve', 'vampire', 'vanguard', 'vanish', 'vantage', 'vapor', 'various', 'vary', 'vase', 'vast', 'vault', 'vector', 'veer', 'vehicle', 'veil', 'vein', 'velocity', 'velvet', 'vendor', 'venture', 'venue', 'verbal', 'verdict', 'verge', 'verify', 'version', 'vertical', 'very', 'vessel', 'vest', 'veteran', 'veto', 'viable', 'vial', 'vibe', 'vibrant', 'vice', 'vicious', 'victim', 'video', 'view', 'vigorous', 'viking', 'village', 'vine', 'vintage', 'vinyl', 'violence', 'viral', 'virtual', 'virus', 'visa', 'visit', 'visual', 'vital', 'vivid', 'vocal', 'vodka', 'voice', 'void', 'volatile', 'volcano', 'voltage', 'volume', 'vomit', 'vote', 'voucher', 'vowel', 'voyage', 'wade', 'wage', 'wagon', 'wail', 'waist', 'wait', 'waive', 'wake', 'walk', 'wall', 'walnut', 'waltz', 'wander', 'wane', 'want', 'ward', 'warfare', 'warhead', 'warm', 'warn', 'warp', 'warrant', 'wartime', 'wary', 'wash', 'wasp', 'waste', 'watch', 'water', 'wave', 'weak', 'wealth', 'weapon', 'wear', 'weather', 'weave', 'website', 'wedding', 'wedge', 'weed', 'week', 'weep', 'weight', 'weird', 'welcome', 'weld', 'welfare', 'well', 'welsh', 'west', 'wetland', 'whack', 'whale', 'what', 'wheat', 'wheel', 'when', 'where', 'whether', 'which', 'while', 'whim', 'whine', 'whip', 'whirl', 'whisper', 'white', 'whoa', 'whoever', 'whole', 'whoop', 'whose', 'wicked', 'wide', 'widow', 'width', 'wield', 'wife', 'wiggle', 'wild', 'will', 'wilt', 'wince', 'wind', 'wine', 'wing', 'wink', 'winner', 'winter', 'wipe', 'wire', 'wisdom', 'wise', 'wish', 'witch', 'with', 'witness', 'witty', 'wizard', 'wolf', 'woman', 'womb', 'wonder', 'wood', 'wool', 'word', 'work', 'world', 'worm', 'worry', 'worship', 'worth', 'would', 'wrap', 'wrath', 'wreath', 'wreck', 'wrench', 'wrestle', 'wretched', 'wrinkle', 'wrist', 'write', 'wrong', 'yacht', 'yank', 'yard', 'yarn', 'yawn', 'yeah', 'year', 'yeast', 'yellow', 'yield', 'yoga', 'yogurt', 'yolk', 'young', 'your', 'youth', 'zero', 'zest', 'zipper', 'zombie', 'zone', 'zoom'];

    const dictName = 'es_01';
    const normalizer = (word) => {
        let es_repl = [['á', 'a'], ['é', 'e'], ['í', 'i'], ['ó', 'o'], ['ú', 'u'], ['ü', 'u']];
        word = word.toLowerCase();
        for (const pair of es_repl) {
            while (word.indexOf(pair[0]) >= 0) {
                word = word.replace(pair[0], pair[1]);
            }
        }
        return word;
    };
    const words = ['abajo', 'abandonar', 'abarca', 'abel', 'abierto', 'abismo', 'abogado', 'abordar', 'aborto', 'abrazo', 'abre', 'abría', 'abriendo', 'abrieron', 'abrigo', 'abril', 'abrió', 'abrir', 'absoluta', 'absorción', 'abstracto', 'absurdo', 'abuela', 'abuelo', 'abundante', 'abuso', 'acaba', 'acabó', 'academia', 'acaso', 'acceder', 'acceso', 'accidente', 'acción', 'aceite', 'acento', 'aceptar', 'aceptó', 'acera', 'acerca', 'acercó', 'acero', 'ácido', 'acierto', 'aclarar', 'aclaró', 'acogida', 'acompaña', 'acordado', 'acorde', 'acordó', 'acoso', 'acosta', 'acta', 'actitud', 'activa', 'actividad', 'activo', 'acto', 'actriz', 'actuación', 'actuado', 'actual', 'actúan', 'actuar', 'actuó', 'acude', 'acudieron', 'acudió', 'acudir', 'acuerdo', 'acusación', 'acusado', 'acusó', 'adán', 'adaptarse', 'adecuada', 'adelante', 'además', 'adentro', 'adhesión', 'adicional', 'adiós', 'admirable', 'admite', 'admitir', 'adolfo', 'adónde', 'adopción', 'adoptar', 'adquiere', 'adquirir', 'adrián', 'adultos', 'adversario', 'advertir', 'advierte', 'advirtió', 'aérea', 'aéreo', 'aeropuerto', 'afán', 'afecta', 'afecto', 'afición', 'afiliados', 'afirma', 'afirmó', 'áfrica', 'afrontar', 'afuera', 'agencia', 'agenda', 'agentes', 'agonía', 'agosto', 'agotado', 'agradable', 'agraria', 'agrega', 'agregó', 'agresión', 'agrícola', 'agua', 'aguda', 'agudo', 'aguilar', 'aguirre', 'aguja', 'agujero', 'agustín', 'ahí', 'ahora', 'ahorro', 'aire', 'aislados', 'ajedrez', 'ajena', 'ajeno', 'ajuste', 'alarma', 'alas', 'alba', 'alberto', 'álbum', 'alcalá', 'alcalde', 'alcance', 'alcanzar', 'alcohol', 'aldea', 'alegre', 'alegría', 'alejado', 'alejandro', 'alejarse', 'alemania', 'alerta', 'alex', 'alfa', 'alfonso', 'alfredo', 'algo', 'alguien', 'algunas', 'algunos', 'aliados', 'alianza', 'alicante', 'alicia', 'aliento', 'alimentos', 'alivio', 'allá', 'allende', 'allí', 'alma', 'almirante', 'almuerzo', 'alonso', 'alquiler', 'alrededor', 'alta', 'alterar', 'alto', 'altura', 'alude', 'aluminio', 'alumnos', 'alusión', 'alvarez', 'alvaro', 'alza', 'alzó', 'amable', 'amado', 'amalia', 'amanecer', 'amante', 'amargo', 'amargura', 'amarillo', 'ambas', 'ambición', 'ambiente', 'ámbito', 'ambos', 'amelia', 'amenaza', 'américa', 'amiga', 'amigos', 'amistad', 'amnistía', 'amor', 'amparo', 'amplia', 'amplio', 'amplitud', 'añade', 'añadido', 'añadió', 'añadir', 'análisis', 'analizar', 'ancha', 'ancho', 'ancianos', 'andaba', 'andalucía', 'andan', 'andar', 'andes', 'andino', 'andrea', 'andrés', 'anécdota', 'ángel', 'anguita', 'ángulo', 'angustia', 'anillo', 'animales', 'ánimo', 'anoche', 'anomalías', 'años', 'anotó', 'anselmo', 'ansiedad', 'antaño', 'antemano', 'antena', 'anterior', 'antes', 'antiguo', 'antonio', 'anual', 'anunció', 'aparato', 'aparece', 'aparente', 'aparición', 'apariencia', 'apartado', 'aparte', 'apellido', 'apenas', 'apertura', 'apetito', 'aplausos', 'aplicar', 'aportar', 'aporte', 'apoyado', 'apoyan', 'apoyar', 'apoyo', 'apreciar', 'aprender', 'aprobado', 'aprobó', 'apropiado', 'aprovechar', 'apuesta', 'apunta', 'apuntó', 'aquel', 'aquí', 'árabe', 'arafat', 'aragón', 'árbitro', 'árboles', 'arce', 'archivo', 'arco', 'área', 'arena', 'argelia', 'argentina', 'argumento', 'arias', 'ariel', 'armadas', 'armado', 'armamento', 'armando', 'armario', 'armas', 'armonía', 'aroma', 'arquitecto', 'arranca', 'arranque', 'arreglo', 'arriba', 'arroyo', 'arroz', 'arte', 'artículo', 'artificial', 'artista', 'arturo', 'arzobispo', 'asalto', 'asamblea', 'ascendente', 'ascenso', 'asciende', 'asco', 'aseguró', 'asesinato', 'asesor', 'así', 'asociados', 'asombro', 'aspectos', 'aspirantes', 'asturias', 'asume', 'asumido', 'asumió', 'asumir', 'asunción', 'asunto', 'atacar', 'ataque', 'atardecer', 'atenas', 'atención', 'atender', 'atendiendo', 'atentado', 'atento', 'atiende', 'atlántico', 'atletas', 'atlético', 'atmósfera', 'átomos', 'atracción', 'atractivo', 'atraer', 'atrás', 'atravesar', 'atraviesa', 'atrevió', 'atribuye', 'audiencia', 'auditorio', 'auge', 'augusto', 'aula', 'aumento', 'aunque', 'aurora', 'ausencia', 'ausente', 'australia', 'austria', 'auténtico', 'autobús', 'automóvil', 'autonomía', 'autopista', 'autor', 'autos', 'auxiliar', 'avance', 'avanzar', 'avanzó', 'avenida', 'aventura', 'averiguar', 'aves', 'aviación', 'avión', 'aviraneta', 'aviso', 'ayala', 'ayer', 'ayuda', 'ayudó', 'azar', 'aznar', 'azúcar', 'azul', 'bacterias', 'bahía', 'bailar', 'baile', 'baja', 'bajo', 'balance', 'balanza', 'balas', 'balcón', 'baleares', 'ballet', 'balón', 'banca', 'banco', 'banda', 'bandeja', 'bandera', 'banesto', 'baño', 'barajas', 'barato', 'barba', 'barcelona', 'barco', 'bares', 'barra', 'barrera', 'barrio', 'barro', 'bartolomé', 'basada', 'basado', 'base', 'básica', 'básicos', 'bastaba', 'bastante', 'basura', 'batalla', 'batería', 'beatriz', 'beber', 'bebidas', 'becas', 'béisbol', 'belga', 'bélgica', 'bella', 'belleza', 'bello', 'beneficios', 'benítez', 'benito', 'benjamín', 'berlín', 'berlusconi', 'bernal', 'bernardo', 'beso', 'bestia', 'biblia', 'biblioteca', 'bicicleta', 'bien', 'bilbao', 'billetes', 'billones', 'biografía', 'biológica', 'blanca', 'blanco', 'blas', 'bloque', 'boca', 'boda', 'bogotá', 'bola', 'boletín', 'bolívar', 'bolivia', 'bolsa', 'bolsillo', 'bolso', 'bomba', 'bomberos', 'bondad', 'bonita', 'bonito', 'bonos', 'borde', 'bordo', 'borges', 'borracho', 'borrar', 'bosnia', 'bosque', 'botas', 'botella', 'botón', 'boxeo', 'brasil', 'bravo', 'brazos', 'bretaña', 'breve', 'brigada', 'brillante', 'brillo', 'brinda', 'brisa', 'británico', 'broma', 'bronce', 'brown', 'bruno', 'bruselas', 'brutal', 'bruto', 'buena', 'bueno', 'buque', 'burgos', 'burguesía', 'burla', 'burocracia', 'busca', 'buscó', 'bush', 'búsqueda', 'caballo', 'cabecera', 'cabello', 'cabeza', 'cable', 'cabo', 'cabrera', 'cáceres', 'cada', 'cadena', 'cádiz', 'caen', 'caer', 'café', 'caía', 'caída', 'caído', 'caja', 'cajón', 'calcio', 'cálculo', 'calderón', 'caldo', 'calendario', 'calidad', 'caliente', 'calificó', 'california', 'calla', 'calle', 'calma', 'calor', 'calvo', 'calzada', 'camacho', 'cámara', 'camarero', 'camas', 'cambiar', 'cambio', 'camilo', 'caminar', 'camino', 'camión', 'camisa', 'camiseta', 'campamento', 'campaña', 'campeón', 'campesinos', 'campo', 'canadá', 'canadiense', 'canal', 'canarias', 'cáncer', 'cancha', 'canciller', 'canciones', 'candidato', 'canela', 'cano', 'cansado', 'cansancio', 'cantabria', 'cantante', 'cantar', 'cantidad', 'canto', 'caos', 'capaces', 'capacidad', 'capas', 'capaz', 'capilla', 'capital', 'capítulo', 'captación', 'captar', 'captura', 'cara', 'carbón', 'cárcel', 'cardenal', 'carece', 'carencia', 'carga', 'cargo', 'caribe', 'caridad', 'cariño', 'carlitos', 'carlos', 'carlota', 'carmen', 'carnaval', 'carne', 'carolina', 'carrera', 'carretera', 'carrillo', 'carro', 'carta', 'cartel', 'cartera', 'cartón', 'casa', 'casco', 'casi', 'caso', 'castellano', 'castigo', 'castillo', 'castro', 'casualidad', 'catalán', 'catalina', 'catálogo', 'cataluña', 'catedral', 'categoría', 'católica', 'catorce', 'cauce', 'caudal', 'caudillo', 'causa', 'causó', 'cautela', 'cayendo', 'cayeron', 'cayó', 'caza', 'cebolla', 'cecilia', 'ceder', 'celda', 'celebrar', 'celeste', 'celos', 'celta', 'células', 'cementerio', 'cena', 'cenizas', 'censo', 'censura', 'centavos', 'centenar', 'central', 'centro', 'cerámica', 'cerca', 'cerco', 'cerdo', 'cereales', 'cerebro', 'ceremonia', 'cero', 'cerrado', 'cerrar', 'cerró', 'certamen', 'certeza', 'cervantes', 'cerveza', 'césar', 'cese', 'chaqueta', 'charla', 'charles', 'chaves', 'chávez', 'chiapas', 'chica', 'chico', 'chile', 'chimenea', 'china', 'chino', 'chocolate', 'choque', 'ciclo', 'ciega', 'ciego', 'cielo', 'ciencia', 'ciento', 'cierra', 'cierre', 'cierta', 'cierto', 'cifra', 'cigarrillo', 'cima', 'cinco', 'cincuenta', 'cine', 'cinta', 'cintura', 'circo', 'circuito', 'círculo', 'cirugía', 'cirujano', 'cita', 'ciudad', 'civil', 'clara', 'claridad', 'clarín', 'claro', 'clase', 'clásico', 'claudio', 'clausura', 'clave', 'clemente', 'clic', 'clientes', 'clima', 'clínica', 'club', 'coalición', 'cobertura', 'cobrar', 'cobre', 'cobro', 'coca', 'cocción', 'cochabamba', 'coche', 'cocido', 'cocina', 'coco', 'código', 'coge', 'coherente', 'cohesión', 'coinciden', 'cola', 'colección', 'colectivo', 'colegas', 'colegio', 'cólera', 'colesterol', 'colina', 'colmo', 'colocar', 'colocó', 'colombia', 'colonia', 'color', 'columna', 'comandante', 'comarca', 'combate', 'comedia', 'comedor', 'comentó', 'comenzó', 'comercio', 'cometer', 'cometido', 'comicios', 'comida', 'comienza', 'comisario', 'comisión', 'comité', 'como', 'compadre', 'compañía', 'compartir', 'compás', 'compensar', 'competir', 'completo', 'complicado', 'componente', 'compositor', 'compra', 'comprender', 'compromiso', 'compuesto', 'comuna', 'comunes', 'comunidad', 'concebir', 'concede', 'concejal', 'concepto', 'concesión', 'conciencia', 'concluyó', 'concreto', 'concurso', 'conde', 'condición', 'conducta', 'condujo', 'conexión', 'confesó', 'confianza', 'confiesa', 'confirmó', 'conflicto', 'conforme', 'confundir', 'confusión', 'congreso', 'conjunto', 'conlleva', 'conmigo', 'conocer', 'conocido', 'conozco', 'conquista', 'consciente', 'conseguir', 'consejo', 'consenso', 'conservar', 'considera', 'consiguió', 'consiste', 'consolidar', 'consorcio', 'constante', 'constituye', 'construir', 'consuelo', 'consulta', 'consumo', 'contaba', 'contacto', 'contado', 'contando', 'contar', 'contempla', 'contenido', 'contestó', 'contexto', 'contiene', 'contigo', 'continúa', 'contó', 'contra', 'contreras', 'contribuir', 'control', 'convenio', 'convertido', 'convierte', 'convirtió', 'convocado', 'copa', 'copia', 'coraje', 'coral', 'corazón', 'corbata', 'cordero', 'córdoba', 'cordón', 'corea', 'corona', 'coronel', 'corporal', 'corral', 'correa', 'correcta', 'corredor', 'corregir', 'corren', 'correo', 'correr', 'corría', 'corrida', 'corriente', 'corrió', 'corta', 'corte', 'cortina', 'corto', 'coruña', 'cosas', 'cosecha', 'costa', 'coste', 'costo', 'costumbre', 'cotidiana', 'coyuntura', 'cráneo', 'creación', 'creada', 'creado', 'creando', 'crear', 'creativo', 'crecen', 'crecer', 'crecido', 'creciente', 'creció', 'crédito', 'cree', 'creía', 'creído', 'crema', 'creo', 'creyendo', 'creyó', 'criado', 'criatura', 'crimen', 'criminal', 'crisis', 'cristal', 'cristina', 'cristo', 'criterios', 'crítica', 'crónica', 'cruce', 'crucial', 'crudo', 'cruel', 'cruz', 'cuaderno', 'cuadrados', 'cuadro', 'cual', 'cuando', 'cuantas', 'cuantía', 'cuanto', 'cuarenta', 'cuarta', 'cuartel', 'cuarto', 'cuatro', 'cuba', 'cubierta', 'cubre', 'cubrir', 'cucharadas', 'cuchillo', 'cuello', 'cuenca', 'cuenta', 'cuento', 'cuerda', 'cuero', 'cuerpo', 'cuesta', 'cuestión', 'cuevas', 'cuidado', 'cuidar', 'culo', 'culpa', 'cultivo', 'culto', 'cultura', 'cumbre', 'cumpla', 'cumple', 'cumplir', 'cuna', 'cuota', 'cúpula', 'cura', 'curiosidad', 'curso', 'curva', 'custodia', 'cuya', 'cuyo', 'daba', 'dada', 'dado', 'dama', 'damos', 'dando', 'daniel', 'daño', 'danza', 'dará', 'daría', 'darío', 'darle', 'darme', 'darse', 'darwin', 'data', 'datos', 'david', 'debajo', 'debate', 'debe', 'debía', 'debida', 'debido', 'debiera', 'débil', 'debió', 'debo', 'década', 'decadencia', 'decenas', 'decepción', 'decía', 'decida', 'decide', 'decidió', 'decimos', 'decir', 'decisión', 'declaró', 'decreto', 'dedicado', 'dedicó', 'dedos', 'defectos', 'defender', 'defensa', 'déficit', 'defiende', 'define', 'definitiva', 'dejaba', 'dejado', 'déjame', 'dejamos', 'dejando', 'dejar', 'deje', 'dejó', 'delante', 'delegado', 'delgado', 'delicado', 'delirio', 'delito', 'demanda', 'demás', 'democracia', 'demonio', 'demora', 'demostrar', 'demuestra', 'denominado', 'densidad', 'dentro', 'denuncia', 'depende', 'deporte', 'depósitos', 'depresión', 'derecho', 'derivados', 'derrota', 'desafío', 'desaparece', 'desarrollo', 'desastre', 'desayuno', 'descanso', 'descarga', 'descenso', 'desconoce', 'describe', 'descubrir', 'desde', 'desea', 'desempleo', 'desenlace', 'deseo', 'desfile', 'desgracia', 'desierto', 'designado', 'desigual', 'desnudo', 'desorden', 'despacho', 'despedida', 'despertar', 'despierta', 'despliegue', 'desprecio', 'después', 'destaca', 'destino', 'destruir', 'detalles', 'detección', 'detectar', 'detención', 'detener', 'detenido', 'deterioro', 'determinar', 'detiene', 'detrás', 'detuvo', 'deuda', 'devoción', 'devolver', 'día', 'dibujo', 'dice', 'dicha', 'dicho', 'diciembre', 'diciendo', 'dictadura', 'dictamen', 'dieciocho', 'dieciséis', 'diego', 'dientes', 'diera', 'dieron', 'dieta', 'diez', 'diferentes', 'difícil', 'dificultad', 'difusión', 'diga', 'digital', 'digna', 'dignidad', 'digno', 'digo', 'dije', 'dijiste', 'dijo', 'dimensión', 'dimisión', 'dinamarca', 'dinámica', 'dinero', 'dionisio', 'dios', 'diputados', 'dirá', 'dirección', 'director', 'diría', 'dirigentes', 'dirigido', 'disciplina', 'disco', 'discreto', 'discurso', 'discusión', 'discutir', 'diseñado', 'diseño', 'disfrutar', 'disgusto', 'disimular', 'disminuir', 'disparos', 'dispone', 'dispuesto', 'dispuso', 'disputa', 'distancia', 'distintos', 'distrito', 'diversos', 'divertido', 'divide', 'dividido', 'divina', 'divino', 'divisas', 'división', 'divorcio', 'doble', 'doce', 'doctor', 'doctrina', 'documento', 'dólares', 'dolor', 'doméstico', 'domicilio', 'dominante', 'domingo', 'dominio', 'doña', 'donde', 'dorada', 'dorado', 'dormía', 'dormido', 'dormir', 'dormitorio', 'doscientos', 'dosis', 'dotación', 'dotado', 'drama', 'drogas', 'duda', 'duele', 'duelo', 'dueña', 'dueño', 'duerme', 'duhalde', 'dulce', 'duque', 'duración', 'durante', 'duras', 'dureza', 'duro', 'ebro', 'echado', 'echar', 'echó', 'ecológico', 'economía', 'ecuación', 'ecuador', 'edad', 'edición', 'edificio', 'editorial', 'edmundo', 'eduardo', 'educación', 'educativo', 'eeuu', 'efectivo', 'efecto', 'efectuar', 'eficacia', 'eficaz', 'eficiencia', 'egipto', 'einstein', 'ejecución', 'ejecutivo', 'ejemplo', 'ejercer', 'ejército', 'ejes', 'elaborado', 'elecciones', 'electoral', 'eléctrica', 'elegante', 'elegido', 'elegir', 'elementos', 'elena', 'elevación', 'elevado', 'elevar', 'elías', 'eligió', 'eliminar', 'ella', 'ellos', 'eloy', 'elvira', 'embajador', 'embarazo', 'embargo', 'emergencia', 'emilia', 'emilio', 'emisión', 'emisora', 'emite', 'emitir', 'emoción', 'empate', 'empecé', 'empeño', 'emperador', 'empezar', 'empezó', 'empieza', 'empleados', 'empleo', 'emprender', 'empresa', 'enamorado', 'encanto', 'encargado', 'encender', 'encerrado', 'enciende', 'encierra', 'encima', 'encontrar', 'encuentra', 'encuesta', 'enemigo', 'energía', 'enero', 'énfasis', 'enfermedad', 'enfoque', 'enfrentar', 'engaño', 'enlace', 'enmienda', 'enorme', 'enrique', 'ensalada', 'ensayo', 'enseguida', 'enseñanza', 'enseñó', 'entender', 'entera', 'entero', 'entidad', 'entiende', 'entierro', 'entonces', 'entorno', 'entraba', 'entrada', 'entran', 'entrar', 'entre', 'entró', 'entusiasmo', 'enviado', 'enviar', 'envidia', 'envió', 'envuelto', 'epidemia', 'episcopal', 'episodio', 'época', 'equilibrio', 'equipo', 'equivale', 'equivocado', 'éramos', 'eran', 'eras', 'eres', 'ernesto', 'erosión', 'error', 'esas', 'escala', 'escalera', 'escándalo', 'escaños', 'escapar', 'escape', 'escasa', 'escasez', 'escasos', 'escena', 'esclavitud', 'escobar', 'escoger', 'escogido', 'escolar', 'escondido', 'escribir', 'escrito', 'escuchar', 'escudo', 'escuela', 'escultura', 'esencial', 'esfera', 'esfuerzo', 'esos', 'espacio', 'espada', 'espalda', 'españa', 'español', 'especial', 'espectador', 'espejo', 'espera', 'espero', 'espinosa', 'espíritu', 'esplendor', 'esposa', 'esposo', 'espuma', 'esquema', 'esquina', 'esta', 'este', 'esther', 'estilo', 'estima', 'estímulo', 'estómago', 'estos', 'estoy', 'estrategia', 'estrecha', 'estrellas', 'estreno', 'estrés', 'estricto', 'estructura', 'estudio', 'estuve', 'estuviera', 'estuvo', 'etapa', 'etarras', 'etcétera', 'eterna', 'eternidad', 'eterno', 'ética', 'ético', 'etiqueta', 'euforia', 'eugenio', 'europa', 'europea', 'euros', 'euskadi', 'evaluar', 'evento', 'eventual', 'evidente', 'evitando', 'evitar', 'evolución', 'exacta', 'exactitud', 'exacto', 'examen', 'examinar', 'excelente', 'excepción', 'excepto', 'excesiva', 'exceso', 'exclamó', 'exclusiva', 'excusa', 'exige', 'exigía', 'exigir', 'exilio', 'exista', 'existe', 'existir', 'éxito', 'expansión', 'expediente', 'expertos', 'explicó', 'explosión', 'explotar', 'expone', 'expresión', 'expuesto', 'expulsión', 'expuso', 'extendió', 'extensión', 'exterior', 'externa', 'extiende', 'extinción', 'extraer', 'extraño', 'extremo', 'fabio', 'fábrica', 'fachada', 'fácil', 'factores', 'factura', 'facultad', 'faena', 'falda', 'falla', 'falleció', 'fallo', 'falsa', 'falso', 'falta', 'faltó', 'fama', 'familia', 'famosa', 'famoso', 'fantasía', 'farc', 'fármacos', 'fase', 'fatal', 'fatiga', 'fauna', 'favor', 'febrero', 'fecha', 'federal', 'federico', 'felices', 'felicidad', 'felipe', 'félix', 'feliz', 'femenino', 'fenómeno', 'feria', 'fermín', 'fernando', 'feroz', 'ferrer', 'festival', 'feto', 'fibra', 'ficción', 'ficha', 'fidel', 'fiebre', 'fiel', 'fiesta', 'figueroa', 'figura', 'fija', 'fijo', 'filas', 'filial', 'film', 'filosofía', 'final', 'financiero', 'finanzas', 'finas', 'finca', 'fines', 'fino', 'firma', 'firme', 'firmó', 'fiscal', 'física', 'físico', 'flamenco', 'flexible', 'flora', 'florentino', 'flores', 'florida', 'flota', 'flujo', 'foco', 'fomento', 'fondo', 'ford', 'forestal', 'forma', 'formó', 'fórmula', 'foro', 'fortaleza', 'fortuna', 'fósiles', 'foto', 'fracaso', 'fracción', 'fraga', 'frágil', 'fragmentos', 'franca', 'francés', 'francisco', 'franco', 'franja', 'frank', 'frase', 'fraude', 'fray', 'frecuencia', 'frenar', 'freno', 'frente', 'fresca', 'fresco', 'freud', 'fría', 'frío', 'frontal', 'frontera', 'frutas', 'fruto', 'fuego', 'fuentes', 'fuera', 'fueron', 'fuerte', 'fuerza', 'fuese', 'fuga', 'fuimos', 'fujimori', 'fumar', 'función', 'fundación', 'fundador', 'fundamento', 'fundó', 'furia', 'fusión', 'fútbol', 'futura', 'futuro', 'gabinete', 'gabriel', 'gafas', 'gala', 'galería', 'galicia', 'gallego', 'gallina', 'gallo', 'gama', 'ganadería', 'ganado', 'ganancias', 'ganando', 'ganar', 'ganas', 'ganó', 'garantizar', 'garcía', 'garganta', 'garzón', 'gases', 'gasolina', 'gastos', 'gato', 'general', 'género', 'genes', 'genética', 'genial', 'genio', 'gente', 'geografía', 'geometría', 'george', 'gerardo', 'gerente', 'germán', 'gestación', 'gestión', 'gesto', 'gibraltar', 'gigante', 'gijón', 'gimnasia', 'ginebra', 'gira', 'giro', 'global', 'globo', 'gloria', 'glucosa', 'gobernador', 'gobierno', 'goles', 'golfo', 'golpe', 'goma', 'gómez', 'gonzález', 'gorbachov', 'gorda', 'gordo', 'gotas', 'goya', 'goza', 'grabación', 'grabado', 'gracias', 'grado', 'gradual', 'gráfico', 'gramos', 'gran', 'grasa', 'gratis', 'gratuita', 'grave', 'grecia', 'gregorio', 'gremio', 'griega', 'griego', 'gris', 'gritaba', 'gritando', 'gritar', 'gritos', 'gruesa', 'grueso', 'grupo', 'guadalupe', 'guapa', 'guarda', 'guardia', 'guatemala', 'guerra', 'guerrero', 'guerrilla', 'guevara', 'guía', 'guillermo', 'guión', 'guitarra', 'gusta', 'gusto', 'gutiérrez', 'guzmán', 'habana', 'habéis', 'haber', 'había', 'habido', 'habiendo', 'habilidad', 'habitantes', 'hábitos', 'habitual', 'hablaba', 'hablado', 'hablamos', 'hablando', 'hablar', 'hable', 'habló', 'habrá', 'habría', 'hace', 'hacia', 'haciendo', 'haga', 'hago', 'haití', 'hallaba', 'hallan', 'hallar', 'hallazgo', 'hambre', 'hans', 'hará', 'haré', 'haría', 'harina', 'harto', 'hasta', 'haya', 'hecha', 'hecho', 'hectáreas', 'héctor', 'hegemonía', 'helado', 'hembra', 'hemisferio', 'hemos', 'henry', 'herald', 'heredero', 'herencia', 'heridas', 'heridos', 'hermano', 'hermosa', 'hernández', 'héroe', 'heroína', 'herrera', 'hervir', 'hice', 'hicieron', 'hicimos', 'hidalgo', 'hidrógeno', 'hielo', 'hierba', 'hierro', 'hígado', 'higiene', 'hija', 'hijo', 'hilo', 'himno', 'hipótesis', 'hispano', 'historia', 'hitler', 'hizo', 'hogar', 'hojas', 'holanda', 'hollywood', 'hombre', 'hombros', 'homenaje', 'homicidio', 'homo', 'honda', 'hondo', 'honduras', 'hongos', 'honor', 'horacio', 'horario', 'horas', 'horizonte', 'hormonas', 'horno', 'horrible', 'horror', 'hortalizas', 'hospital', 'hotel', 'hubiera', 'hubiese', 'hubo', 'hueco', 'huele', 'huelga', 'huellas', 'huerta', 'huesos', 'huevos', 'hugo', 'huida', 'huir', 'humana', 'humanidad', 'humanos', 'humberto', 'humedad', 'húmedo', 'humilde', 'humor', 'huracán', 'íbamos', 'iban', 'ibarra', 'iberia', 'ibérica', 'idea', 'identidad', 'ideología', 'idioma', 'iglesia', 'ignacio', 'ignorancia', 'igual', 'ilegal', 'ilusión', 'ilustre', 'imagen', 'imaginar', 'impacto', 'impedir', 'imperio', 'impide', 'impidió', 'implacable', 'implica', 'impone', 'importante', 'imposible', 'impotencia', 'impresión', 'impuesto', 'impulso', 'impunidad', 'impuso', 'inauguró', 'incapaz', 'incendio', 'incidencia', 'incluido', 'incluso', 'incluye', 'incómodo', 'incorporar', 'increíble', 'incremento', 'india', 'indica', 'índice', 'indicios', 'indicó', 'indígenas', 'indios', 'individuo', 'índole', 'indudable', 'industria', 'inés', 'inevitable', 'infancia', 'infantil', 'infarto', 'infección', 'inferior', 'infierno', 'infinito', 'inflación', 'influencia', 'influir', 'influye', 'informe', 'ingeniero', 'ingesta', 'inglaterra', 'inglés', 'ingresos', 'iniciativa', 'inicio', 'injusticia', 'inmediato', 'inmensa', 'inminente', 'inmóvil', 'inocente', 'inquietud', 'insectos', 'inserción', 'insistió', 'insólito', 'insomnio', 'inspector', 'instalado', 'instante', 'instinto', 'instituto', 'insulina', 'insultos', 'integral', 'intención', 'intensidad', 'intento', 'interés', 'interior', 'intermedio', 'internet', 'interpreta', 'intervenir', 'íntima', 'intimidad', 'íntimo', 'introducir', 'intuición', 'inútil', 'invasión', 'invención', 'invento', 'inversión', 'invertir', 'investigar', 'invierno', 'invisible', 'invitados', 'invitó', 'irak', 'irán', 'irene', 'iría', 'iris', 'irlanda', 'irme', 'ironía', 'irregular', 'irse', 'isabel', 'isidro', 'isla', 'israel', 'italia', 'iván', 'izquierda', 'jacinto', 'jackson', 'jacques', 'jaime', 'jamás', 'james', 'jamón', 'japón', 'jardín', 'javier', 'jazz', 'jean', 'jefatura', 'jefe', 'jerarquía', 'jerez', 'jerusalén', 'jesús', 'jiménez', 'jinete', 'joan', 'joaquín', 'john', 'jones', 'jordi', 'jorge', 'jornada', 'josé', 'joven', 'joyas', 'juan', 'juárez', 'jubilados', 'judicial', 'judíos', 'jueces', 'juega', 'juego', 'jueves', 'juez', 'jugaba', 'jugada', 'jugadores', 'jugando', 'jugar', 'jugo', 'juicio', 'julián', 'julio', 'junio', 'junta', 'junto', 'jurado', 'jurídico', 'juro', 'justamente', 'justicia', 'justificar', 'justo', 'juvenil', 'juventud', 'juzgado', 'juzgar', 'kilómetro', 'kilos', 'laberinto', 'labios', 'labor', 'lado', 'ladrillos', 'ladrones', 'lago', 'lágrimas', 'laguna', 'lamentable', 'láminas', 'lámpara', 'lana', 'lanza', 'lanzó', 'lapso', 'lara', 'larga', 'largo', 'lástima', 'lata', 'lateral', 'latina', 'laura', 'lavado', 'lavar', 'lázaro', 'lazos', 'lealtad', 'lección', 'leche', 'lecho', 'lector', 'lectura', 'leer', 'legado', 'legal', 'legislador', 'legítimo', 'leía', 'leído', 'lejana', 'lejano', 'lejos', 'lema', 'leña', 'lenguaje', 'lentamente', 'lentitud', 'lento', 'león', 'leopoldo', 'lesiones', 'letras', 'levantó', 'leve', 'leyenda', 'leyes', 'leyó', 'liberal', 'libertad', 'libras', 'libre', 'libro', 'licenciado', 'líder', 'lidia', 'liga', 'ligera', 'ligero', 'lima', 'limitado', 'límites', 'limitó', 'limón', 'limpia', 'limpieza', 'limpio', 'linda', 'lindo', 'línea', 'líquido', 'lisboa', 'lista', 'listo', 'literatura', 'litoral', 'litros', 'llamaba', 'llamado', 'llamamos', 'llaman', 'llamar', 'llamas', 'llamó', 'llano', 'llanto', 'llave', 'llegaba', 'llegado', 'llegamos', 'llegan', 'llegar', 'llegó', 'llegue', 'llena', 'lleno', 'lleva', 'lleve', 'llevó', 'llorando', 'llorar', 'lluvia', 'lobo', 'local', 'loco', 'locura', 'lógica', 'lógico', 'lograba', 'logrado', 'logran', 'lograr', 'logró', 'lola', 'lomo', 'londres', 'longitud', 'lópez', 'lorca', 'lord', 'lorenzo', 'lozano', 'lucas', 'luces', 'lucha', 'lucía', 'luego', 'lugar', 'luis', 'lujo', 'luminoso', 'luna', 'lunes', 'machado', 'madame', 'madera', 'madre', 'madrid', 'madrileño', 'madrugada', 'madurez', 'maestro', 'magdalena', 'magia', 'mágica', 'mágico', 'magistrado', 'magnífico', 'magnitud', 'maíz', 'majestad', 'mala', 'maldito', 'malestar', 'maleta', 'mallorca', 'malo', 'mamá', 'managua', 'mañana', 'mancha', 'mandar', 'mandato', 'mando', 'manejar', 'manejo', 'manera', 'manga', 'manifestó', 'manifiesto', 'maniobra', 'mano', 'manta', 'manteca', 'mantener', 'mantiene', 'manto', 'mantuvo', 'manual', 'manuel', 'manzana', 'mapa', 'máquina', 'maradona', 'maravilla', 'marca', 'marcelo', 'marcha', 'marchó', 'marco', 'mares', 'margarita', 'margen', 'maría', 'marido', 'marina', 'marino', 'mario', 'mariscal', 'mark', 'mármol', 'marqués', 'marruecos', 'marta', 'martes', 'martín', 'martirio', 'marx', 'marzo', 'más', 'matado', 'matanza', 'matar', 'mateo', 'materia', 'maternidad', 'matías', 'matices', 'matilde', 'mató', 'matrícula', 'matrimonio', 'matriz', 'mauricio', 'máxima', 'máximo', 'maya', 'mayor', 'mecanismos', 'medalla', 'medellín', 'media', 'médica', 'medicina', 'médico', 'medida', 'medieval', 'medina', 'medio', 'medir', 'mejía', 'mejillas', 'mejor', 'melilla', 'melodía', 'memoria', 'mencionado', 'méndez', 'mendoza', 'menem', 'menéndez', 'menor', 'menos', 'mensaje', 'mensuales', 'mental', 'mente', 'mentira', 'menudo', 'mera', 'mercado', 'mercantil', 'mercedes', 'mercosur', 'mercurio', 'merece', 'mérida', 'mérito', 'mero', 'mesa', 'meses', 'meta', 'meter', 'metido', 'metió', 'método', 'metros', 'mexicano', 'méxico', 'mezcla', 'miami', 'michael', 'michel', 'microsoft', 'mide', 'miedo', 'miel', 'miembros', 'mientras', 'miércoles', 'mierda', 'miguel', 'milagro', 'milán', 'milenio', 'miles', 'militar', 'millas', 'millones', 'minas', 'minerales', 'mineros', 'mínima', 'mínimo', 'ministro', 'minoría', 'minutos', 'mío', 'miraba', 'mirada', 'mirando', 'mirar', 'miras', 'mire', 'miró', 'misa', 'miserable', 'miseria', 'misiles', 'misión', 'misma', 'mismo', 'misterio', 'mística', 'mitad', 'mito', 'mixta', 'moción', 'moda', 'modelo', 'moderado', 'moderna', 'modesto', 'modificar', 'modo', 'módulo', 'moisés', 'molde', 'moléculas', 'molesta', 'molina', 'momento', 'monarca', 'monarquía', 'monasterio', 'moncloa', 'moneda', 'monetaria', 'mónica', 'monjas', 'monopolio', 'monseñor', 'monstruo', 'montado', 'montaje', 'montaña', 'montar', 'monte', 'montón', 'montoya', 'monumento', 'moral', 'moreno', 'morir', 'mortalidad', 'moscú', 'mostrar', 'mostró', 'motivo', 'motor', 'moverse', 'movía', 'móvil', 'movimiento', 'movió', 'mozart', 'mozo', 'muchacho', 'muchas', 'muchísimo', 'mucho', 'muebles', 'muelle', 'muere', 'muerta', 'muerte', 'muerto', 'muestra', 'mueve', 'mujer', 'multa', 'multimedia', 'múltiples', 'multitud', 'mundial', 'mundo', 'muñeca', 'municipal', 'muñoz', 'murcia', 'murieron', 'murió', 'muro', 'músculos', 'museo', 'música', 'músicos', 'muslos', 'musulmanes', 'mutua', 'nace', 'nacido', 'nacimiento', 'nacional', 'nada', 'nadie', 'napoleón', 'naranja', 'nariz', 'narración', 'narrador', 'narrativa', 'natalia', 'nativos', 'naturaleza', 'naval', 'navarro', 'nave', 'navidad', 'necesario', 'necesidad', 'negación', 'negado', 'negar', 'negativa', 'negocios', 'negra', 'negro', 'nelson', 'nervioso', 'néstor', 'newton', 'nicaragua', 'nicolás', 'niebla', 'niega', 'nieto', 'nieve', 'niña', 'niñez', 'ningún', 'niños', 'nivel', 'nobel', 'noble', 'noche', 'noción', 'nocturno', 'nomás', 'nombrado', 'nombre', 'nómina', 'normal', 'normas', 'normativa', 'noroeste', 'norte', 'nosotros', 'nostalgia', 'nota', 'noticia', 'novedad', 'novela', 'novelista', 'noventa', 'novia', 'noviembre', 'novio', 'nubes', 'nuboso', 'nuca', 'nuclear', 'núcleo', 'nuestro', 'nueva', 'nueve', 'nuevo', 'número', 'nunca', 'núñez', 'nutrición', 'nutrientes', 'obedece', 'obesidad', 'obispo', 'objetivo', 'objeto', 'obligado', 'obligó', 'obra', 'obrera', 'obreros', 'observar', 'obsesión', 'obstáculo', 'obstante', 'obtención', 'obtener', 'obtenido', 'obtiene', 'obtuvieron', 'obtuvo', 'obviamente', 'obvio', 'ocasiones', 'occidental', 'océano', 'ochenta', 'ocho', 'ocio', 'octavio', 'octubre', 'oculta', 'oculto', 'ocupa', 'ocupó', 'ocurra', 'ocurre', 'ocurrió', 'odio', 'oeste', 'ofensiva', 'oferta', 'oficial', 'oficina', 'oficio', 'ofrece', 'ofreció', 'oía', 'oído', 'oiga', 'oír', 'ojalá', 'ojos', 'olas', 'olga', 'olímpico', 'oliva', 'olla', 'olor', 'olvidar', 'olvido', 'omar', 'once', 'onda', 'opción', 'operación', 'operadores', 'operan', 'operar', 'operativo', 'opina', 'opinión', 'opone', 'oportuno', 'oposición', 'optar', 'óptica', 'optimismo', 'optó', 'opuesto', 'oración', 'oral', 'órbita', 'orden', 'ordinario', 'ordóñez', 'oreja', 'organismo', 'órganos', 'orgullo', 'oriente', 'origen', 'original', 'orilla', 'orlando', 'orquesta', 'ortega', 'ortiz', 'oscar', 'oscura', 'oscuridad', 'oscuro', 'osvaldo', 'otan', 'otero', 'otoño', 'otorga', 'otra', 'otro', 'oviedo', 'oxígeno', 'oyó', 'pabellón', 'pablo', 'pacheco', 'pacientes', 'pacífico', 'paco', 'pacto', 'padece', 'padre', 'pagado', 'pagan', 'pagar', 'páginas', 'pago', 'país', 'pájaros', 'palabras', 'palacio', 'palestinos', 'pálido', 'palma', 'paloma', 'palos', 'pamplona', 'panamá', 'pánico', 'panorama', 'pantalla', 'pañuelo', 'papá', 'papel', 'paquete', 'para', 'parcial', 'pardo', 'parece', 'parecía', 'paredes', 'pareja', 'pares', 'parezca', 'parientes', 'parís', 'parlamento', 'paro', 'párpados', 'parque', 'párrafo', 'parroquia', 'parte', 'particular', 'partido', 'partiendo', 'partió', 'partir', 'parto', 'pasaba', 'pasada', 'pasado', 'pasajeros', 'pasamos', 'pasando', 'pasaporte', 'pasar', 'pascual', 'pase', 'pasillo', 'pasión', 'paso', 'pasta', 'pastor', 'patas', 'patatas', 'patente', 'patio', 'patología', 'patria', 'patricia', 'patrimonio', 'patrocinio', 'patrón', 'paul', 'pausa', 'pautas', 'pecado', 'peces', 'pecho', 'peculiar', 'pedazos', 'pedía', 'pedido', 'pedir', 'pedro', 'pegado', 'pekín', 'pelea', 'película', 'peligro', 'pelo', 'pena', 'pendiente', 'penetrar', 'península', 'pensaba', 'pensado', 'pensamos', 'pensando', 'pensar', 'pensé', 'pensiones', 'pensó', 'penumbra', 'peor', 'pepe', 'pequeño', 'percibir', 'perder', 'perdía', 'perdido', 'perdiendo', 'perdió', 'perdón', 'perejil', 'pérez', 'perfecto', 'perfil', 'perfume', 'período', 'perjuicio', 'permanente', 'permiso', 'permite', 'pero', 'perro', 'persigue', 'personas', 'pertenece', 'perú', 'pesada', 'pesadilla', 'pesado', 'pesar', 'pescado', 'pesetas', 'peso', 'peter', 'petición', 'petróleo', 'pianista', 'piano', 'picada', 'picado', 'picasso', 'pico', 'pide', 'pidiendo', 'pidieron', 'pidió', 'pido', 'piedad', 'piedra', 'piel', 'piensa', 'piense', 'pienso', 'pierde', 'piernas', 'pierre', 'pies', 'piezas', 'pilar', 'piloto', 'pimienta', 'pinochet', 'pinos', 'pintado', 'pintar', 'pintor', 'pintura', 'pío', 'piscina', 'piso', 'pista', 'pistola', 'pizarro', 'placas', 'placer', 'plan', 'plástico', 'plata', 'plato', 'playa', 'plaza', 'plazo', 'plena', 'plenitud', 'pleno', 'plomo', 'pluma', 'población', 'poblado', 'pobre', 'pocas', 'poco', 'podamos', 'podemos', 'poder', 'podía', 'podido', 'podrá', 'podremos', 'podría', 'poema', 'poesía', 'poeta', 'poética', 'polémica', 'policía', 'política', 'pollo', 'polo', 'polvo', 'ponce', 'pondrá', 'ponemos', 'ponen', 'poner', 'ponga', 'pongo', 'ponía', 'poniendo', 'popular', 'poquito', 'porcentaje', 'porción', 'porque', 'portada', 'portal', 'portavoz', 'portero', 'portugal', 'porvenir', 'posee', 'poseía', 'posesión', 'posible', 'posición', 'positivo', 'posterior', 'postre', 'postura', 'potable', 'potencia', 'potente', 'pozo', 'práctica', 'prado', 'precedente', 'precio', 'preciso', 'precoz', 'predominio', 'preferido', 'prefiere', 'prefirió', 'pregunta', 'prejuicios', 'premio', 'prendas', 'prensa', 'preocupa', 'preparado', 'presa', 'presencia', 'preservar', 'presidente', 'presión', 'presos', 'prestar', 'prestigio', 'presunto', 'pretende', 'pretexto', 'prevé', 'previa', 'previo', 'previsto', 'prieto', 'primaria', 'primas', 'primavera', 'primera', 'primitivo', 'primo', 'princesa', 'principio', 'prioridad', 'prisa', 'prisión', 'privada', 'privilegio', 'probable', 'probado', 'probar', 'problemas', 'procede', 'proceso', 'procurador', 'productos', 'produjo', 'produzca', 'profesor', 'profunda', 'programa', 'progreso', 'prohibido', 'prólogo', 'prolongado', 'promedio', 'promesa', 'prometió', 'promoción', 'promover', 'pronto', 'pronunció', 'propaganda', 'propia', 'propiedad', 'propio', 'propone', 'propósito', 'propuesta', 'propuso', 'prosa', 'protector', 'proteger', 'proteínas', 'protesta', 'protocolo', 'provecho', 'proviene', 'provincia', 'provoca', 'próximo', 'proyecto', 'prudencia', 'prueba', 'psicosis', 'ptas', 'público', 'pude', 'pudiendo', 'pudiera', 'pudiese', 'pudimos', 'pudo', 'puebla', 'pueblo', 'pueda', 'puede', 'puedo', 'puente', 'puerta', 'puerto', 'pues', 'pujol', 'pulmones', 'pulso', 'puñado', 'puño', 'punta', 'punto', 'pura', 'pureza', 'puro', 'puse', 'pusieron', 'puso', 'qué', 'quiebra', 'quien', 'quiera', 'quiere', 'quiero', 'quieto', 'quijote', 'química', 'quince', 'quinientos', 'quinta', 'quinto', 'quise', 'quisiera', 'quiso', 'quita', 'quito', 'quizá', 'rabia', 'racing', 'racional', 'radiación', 'radical', 'radio', 'rafael', 'raíces', 'raíz', 'rallado', 'ramas', 'ramírez', 'ramiro', 'ramón', 'ramos', 'rango', 'rápida', 'rapidez', 'rápido', 'raquel', 'rara', 'raro', 'rasgos', 'rastro', 'ratas', 'rato', 'raúl', 'raya', 'rayos', 'raza', 'razón', 'reacción', 'reagan', 'reales', 'realice', 'realidad', 'realismo', 'realizar', 'realmente', 'rebaja', 'rebeldes', 'rebelión', 'recepción', 'receptor', 'recesión', 'receta', 'rechazo', 'recibe', 'recibió', 'recibo', 'recién', 'recinto', 'recipiente', 'reclama', 'recoge', 'recogida', 'recomienda', 'reconocer', 'recordar', 'recorrido', 'recorte', 'recta', 'rector', 'recuento', 'recuerdo', 'recuperar', 'recurrir', 'recursos', 'redacción', 'redactor', 'redes', 'redondo', 'reducción', 'reduce', 'reducir', 'redujo', 'referencia', 'referirse', 'refiere', 'refirió', 'refleja', 'reflexión', 'reforma', 'reforzar', 'refugio', 'regalo', 'régimen', 'región', 'registro', 'reglamento', 'reglas', 'regreso', 'regular', 'rehenes', 'reina', 'reino', 'reír', 'reiteró', 'relación', 'relativa', 'relato', 'relevante', 'relevo', 'relieve', 'religión', 'relleno', 'reloj', 'remate', 'remedio', 'rencor', 'rené', 'renfe', 'renovar', 'renta', 'renuncia', 'reparar', 'reparto', 'repente', 'repertorio', 'repetir', 'repite', 'repitió', 'replicó', 'reportaje', 'reposo', 'representa', 'reproducir', 'república', 'requiere', 'requisitos', 'resaltar', 'rescate', 'reserva', 'residencia', 'residuos', 'resistir', 'resolver', 'respaldo', 'respecto', 'respeto', 'respirar', 'respondió', 'respuesta', 'restantes', 'resto', 'resuelto', 'resultados', 'resumen', 'retención', 'retirada', 'retiro', 'retórica', 'retorno', 'retraso', 'retrato', 'retroceso', 'reúne', 'reunido', 'reunieron', 'reunión', 'reunir', 'revela', 'reveló', 'revés', 'revisar', 'revisión', 'revista', 'reyes', 'ribera', 'ricardo', 'ricas', 'richard', 'rico', 'ridículo', 'riego', 'riesgo', 'rigor', 'riguroso', 'rincón', 'río', 'riqueza', 'risa', 'ritmo', 'rito', 'ritual', 'rival', 'rivas', 'rivera', 'robado', 'roberto', 'robles', 'robo', 'roca', 'rocío', 'rock', 'rodaje', 'rodeado', 'rodean', 'rodillas', 'rodolfo', 'rodríguez', 'roja', 'rojo', 'roldán', 'roma', 'romero', 'romper', 'rompió', 'ronda', 'ropa', 'roque', 'rosa', 'rostro', 'rotación', 'roto', 'rubén', 'rubia', 'rubio', 'rueda', 'ruido', 'ruinas', 'ruiz', 'rumbo', 'rumores', 'ruptura', 'rural', 'rusa', 'rusia', 'ruso', 'ruta', 'rutina', 'sábado', 'sábanas', 'sabe', 'sabía', 'sabido', 'sabiduría', 'sabiendo', 'sabio', 'sabor', 'sacado', 'sacar', 'sacerdote', 'sacó', 'sacrificio', 'sagrado', 'sala', 'saldo', 'saldrá', 'sale', 'salga', 'salía', 'salida', 'salido', 'saliendo', 'salieron', 'salimos', 'salinas', 'salió', 'salir', 'saliva', 'salón', 'salsa', 'saltar', 'salto', 'salud', 'salvación', 'salvador', 'salvaje', 'salvar', 'salvo', 'samper', 'samuel', 'sana', 'sánchez', 'sancho', 'sanciones', 'sandinista', 'sandra', 'sangre', 'sanidad', 'sanitaria', 'sano', 'santa', 'santiago', 'santo', 'santuario', 'sara', 'sargento', 'sartén', 'satélite', 'satisfacer', 'sean', 'seas', 'sebastián', 'seca', 'sección', 'seco', 'secretario', 'sector', 'secuencia', 'secuestro', 'secundaria', 'seda', 'sede', 'segmento', 'segovia', 'seguía', 'seguido', 'seguimos', 'seguir', 'según', 'segura', 'seguridad', 'seguro', 'seis', 'selección', 'sello', 'selva', 'semana', 'semejante', 'semestre', 'semillas', 'seminario', 'senado', 'señala', 'señales', 'señaló', 'señas', 'sencillo', 'sendero', 'señor', 'senos', 'sensación', 'sensible', 'sentado', 'sentarse', 'sentencia', 'sentía', 'sentido', 'sentimos', 'sentir', 'sentó', 'sepa', 'septiembre', 'séptimo', 'será', 'serbios', 'serena', 'serenidad', 'seres', 'sergio', 'sería', 'serie', 'serio', 'serlo', 'serpiente', 'serrano', 'servía', 'servicio', 'servido', 'servir', 'sesenta', 'sesión', 'setenta', 'setiembre', 'severa', 'severo', 'sevilla', 'sexta', 'sexto', 'sexuales', 'show', 'sido', 'siembra', 'siempre', 'siendo', 'sienta', 'siente', 'siento', 'sierra', 'siete', 'siga', 'siglo', 'significa', 'signo', 'sigo', 'sigue', 'siguiente', 'siguió', 'silencio', 'silla', 'sillón', 'silueta', 'silva', 'silvestre', 'silvia', 'símbolo', 'similar', 'simón', 'simpatía', 'simple', 'sinceridad', 'sindicatos', 'síndrome', 'singular', 'siniestro', 'sino', 'síntesis', 'sintió', 'síntomas', 'siquiera', 'sirva', 'sirve', 'sirvió', 'sistema', 'sitio', 'situación', 'situado', 'sitúan', 'situar', 'soberanía', 'sobra', 'sobre', 'sobrino', 'social', 'sociedad', 'socios', 'sodio', 'sofá', 'sofía', 'software', 'sola', 'soldados', 'soledad', 'solemne', 'solía', 'solicitud', 'sólida', 'sólido', 'solitario', 'sólo', 'soltó', 'solución', 'sombra', 'sombrero', 'someterse', 'sometido', 'somos', 'sonar', 'sonido', 'sonora', 'sonreír', 'sonríe', 'sonrió', 'sonrisa', 'sopa', 'soportar', 'soria', 'sorpresa', 'sosa', 'sospecha', 'sostener', 'sostiene', 'sostuvo', 'soto', 'soviético', 'status', 'street', 'suárez', 'suave', 'subasta', 'sube', 'subida', 'subido', 'subiendo', 'subió', 'subir', 'subrayó', 'sucede', 'sucedido', 'sucesión', 'sucesos', 'sucia', 'sucio', 'sudor', 'suecia', 'sueldo', 'suele', 'suelo', 'suelta', 'suena', 'sueño', 'suerte', 'suficiente', 'sufre', 'sufrido', 'sufrieron', 'sufrió', 'sufrir', 'sugiere', 'sugirió', 'suicidio', 'suiza', 'suizo', 'sujeta', 'sujeto', 'suma', 'suministro', 'sumo', 'superar', 'superficie', 'superior', 'superó', 'supiera', 'supone', 'supongo', 'suponía', 'supremo', 'supresión', 'supuesto', 'supuso', 'surge', 'surgido', 'surgieron', 'surgió', 'surgir', 'susana', 'suscrito', 'suspender', 'sustancias', 'sustituir', 'susto', 'sutil', 'suya', 'suyo', 'tabaco', 'tabla', 'táctica', 'tacto', 'talento', 'tales', 'talla', 'taller', 'tamaño', 'también', 'tampoco', 'tango', 'tantas', 'tanto', 'tapa', 'tarde', 'tardó', 'tarea', 'tarifas', 'tarjeta', 'tasa', 'taxi', 'taza', 'teatral', 'teatro', 'techo', 'técnica', 'tejido', 'tela', 'teléfono', 'telescopio', 'televisor', 'telón', 'tema', 'temblor', 'teme', 'temía', 'temor', 'templo', 'temporada', 'temprano', 'tendencia', 'tendido', 'tendrá', 'tendremos', 'tendría', 'tenemos', 'tener', 'tenga', 'tengo', 'tenía', 'tenido', 'teniendo', 'tenis', 'tenor', 'tensión', 'tentación', 'teoría', 'teórico', 'terapia', 'tercera', 'tercio', 'teresa', 'términos', 'ternura', 'terraza', 'terremoto', 'terreno', 'terrestre', 'terrible', 'territorio', 'terror', 'tesis', 'tesoro', 'testigos', 'testimonio', 'texto', 'textura', 'thomas', 'tía', 'tiempo', 'tienda', 'tiende', 'tiene', 'tierno', 'tierra', 'tigre', 'timbre', 'times', 'tinta', 'tío', 'típica', 'típico', 'tipo', 'tira', 'tiro', 'titular', 'título', 'tocaba', 'tocado', 'tocando', 'tocar', 'tocó', 'todas', 'todavía', 'todo', 'tokio', 'toledo', 'tolerancia', 'tomaba', 'tomada', 'tomado', 'tomamos', 'tomando', 'tomar', 'tomás', 'tomate', 'tome', 'tomó', 'toneladas', 'tono', 'tonto', 'tope', 'toque', 'torero', 'tormenta', 'torneo', 'torno', 'toro', 'torres', 'tortura', 'total', 'tour', 'trabajo', 'tradición', 'traduce', 'trae', 'tráfico', 'tragedia', 'trágico', 'trago', 'traía', 'traición', 'traído', 'traje', 'trajo', 'trama', 'trámite', 'tramo', 'trampa', 'trance', 'tranquilo', 'transcurso', 'transforma', 'tránsito', 'transmitir', 'transporte', 'tras', 'trata', 'trate', 'trato', 'través', 'trayecto', 'trazado', 'trece', 'tregua', 'treinta', 'tremendo', 'tren', 'tres', 'triángulo', 'tribunal', 'tributaria', 'trigo', 'trimestre', 'trinidad', 'triple', 'triste', 'triunfo', 'trofeo', 'tronco', 'trono', 'tropas', 'tropical', 'trozos', 'trujillo', 'tubo', 'tumba', 'tumores', 'túnel', 'turco', 'turismo', 'turistas', 'turno', 'turquía', 'tuve', 'tuvieron', 'tuvimos', 'tuvo', 'tuya', 'tuyo', 'ubicación', 'ubicado', 'ulises', 'última', 'último', 'umbral', 'unanimidad', 'unas', 'unen', 'única', 'único', 'unidad', 'unidas', 'unidos', 'uniforme', 'unión', 'unir', 'universal', 'unos', 'urbana', 'urbanismo', 'urbano', 'urgencia', 'urgente', 'urnas', 'uruguay', 'usaba', 'usado', 'usan', 'usar', 'usos', 'usted', 'usuarios', 'útiles', 'utilidad', 'utilizar', 'utopía', 'vacaciones', 'vacas', 'vacía', 'vacío', 'vacuna', 'valdés', 'valencia', 'valía', 'válida', 'validez', 'válido', 'valiente', 'valioso', 'valladolid', 'valle', 'valor', 'vamos', 'vanguardia', 'vano', 'vapor', 'vargas', 'variables', 'variación', 'variados', 'variantes', 'variar', 'varias', 'variedad', 'varios', 'varones', 'vasca', 'vasco', 'vaso', 'vaticano', 'vaya', 'vázquez', 'veamos', 'vean', 'véase', 'veces', 'vecina', 'vecinos', 'vega', 'vegetales', 'vehículos', 'veía', 'veinte', 'vejez', 'velada', 'velas', 'velázquez', 'vélez', 'velocidad', 'vemos', 'venas', 'vencedor', 'vencer', 'vencido', 'venció', 'vendedores', 'venden', 'vender', 'vendido', 'vendrá', 'vendría', 'venecia', 'veneno', 'venezolano', 'venezuela', 'venga', 'vengo', 'venía', 'venido', 'venir', 'venta', 'venus', 'veracruz', 'verano', 'veras', 'verbal', 'verdad', 'verde', 'verduras', 'veremos', 'verificar', 'verla', 'verle', 'verlo', 'verme', 'verse', 'versión', 'versos', 'verte', 'vertical', 'vértigo', 'vestido', 'vestir', 'vestuario', 'veterano', 'viabilidad', 'viajar', 'viaje', 'viajó', 'vías', 'vicente', 'viceversa', 'vicio', 'víctimas', 'victoria', 'vida', 'vídeo', 'vidrio', 'vieja', 'viejo', 'viena', 'viendo', 'viene', 'viento', 'vientre', 'viera', 'viernes', 'vieron', 'vietnam', 'vigencia', 'vigente', 'vigilancia', 'vigor', 'villa', 'vimos', 'vinagre', 'vínculos', 'vinieron', 'vino', 'violencia', 'violeta', 'virginia', 'virtual', 'virtud', 'virus', 'visible', 'visión', 'visita', 'visitó', 'víspera', 'vista', 'viste', 'visto', 'visual', 'vital', 'vitamina', 'viuda', 'viva', 'vive', 'vivía', 'vivido', 'vivienda', 'vivimos', 'vivió', 'vivir', 'vivo', 'vocación', 'vocales', 'vocero', 'voces', 'volante', 'volar', 'volumen', 'voluntad', 'volver', 'volvía', 'volvieron', 'volvió', 'vosotros', 'votación', 'votantes', 'votar', 'votos', 'vuelo', 'vuelta', 'vuelto', 'vuelva', 'vuelve', 'vuelvo', 'vuestra', 'vulgar', 'walter', 'washington', 'whisky', 'william', 'wilson', 'windows', 'xavier', 'yemas', 'yendo', 'york', 'yugoslavia', 'zamora', 'zapatero', 'zapatos', 'zaragoza', 'zarzuela', 'zedillo', 'zona', 'zumo'];

    class WordCode {
        constructor(dictName, words, normalizer) {
            this.dictName = dictName;
            this.words = words;
            this.bitsPerWord = Math.log2(this.words.length);
            this.normalizer = normalizer === undefined ? (x) => x.toLowerCase() : normalizer;
        }
        fillWordPositions() {
            if (this.wordPositions === undefined) {
                this.wordPositions = new Map();
                let pos = 0;
                for (const word of this.words) {
                    this.wordPositions.set(this.normalizer(word), pos);
                    pos = pos + 1;
                }
            }
        }
        // encode: get a hex string (containing a multiple of bitsPerWord bits), 
        // and get a sequence of words encoding it
        encode(hex) {
            const nibblesPerWord = this.bitsPerWord / 4;
            let wordNibbles = '';
            let words = [];
            for (let i = 0; i < hex.length; i++) {
                wordNibbles = wordNibbles + hex[i];
                if (wordNibbles.length === nibblesPerWord) {
                    words.push(this.encodeWord(wordNibbles));
                    wordNibbles = '';
                }
            }
            if (wordNibbles.length !== 0) {
                throw new Error('Trying to word-encode a hex string whose lenght does not correspond to a multiple of the bits-per-word constant.');
            }
            return words;
        }
        encodeWord(hex) {
            const pos = Number.parseInt(hex, 16);
            if (pos >= this.words.length) {
                throw new Error('Number is too large to encode as a single word');
            }
            return this.words[pos];
        }
        // decode: get a sequence of words, return the hex value they encode.
        decode(words) {
            var _a;
            this.fillWordPositions();
            let result = '';
            const nibblesPerWord = this.bitsPerWord / 4;
            for (let word of words) {
                let position = (_a = this.wordPositions) === null || _a === void 0 ? void 0 : _a.get(this.normalizer(word));
                if (position === undefined) {
                    throw new Error('Trying to decode wordcoded number but received a word that is not in the dictionary "' + this.dictName + '":' + word);
                }
                result = result + position.toString(16).padStart(nibblesPerWord, '0');
            }
            return result.toUpperCase();
        }
    }
    WordCode.english = new WordCode(dictName$1, words$1);
    WordCode.spanish = new WordCode(dictName, words, normalizer);
    WordCode.lang = new Map([['es', WordCode.spanish], ['en', WordCode.english]]);
    WordCode.all = [WordCode.english, WordCode.spanish];

    class ObjectBroadcastAgent {
        constructor(object, broadcastedSuffixBits) {
            if (broadcastedSuffixBits === undefined) {
                broadcastedSuffixBits = ObjectBroadcastAgent.defaultBroadcastedSuffixBits;
            }
            this.literalContext = object.toLiteralContext();
            this.listening = new MultiMap();
            this.broadcastedSuffixBits = broadcastedSuffixBits;
        }
        static agentIdForHash(hash, suffixBits = this.defaultBroadcastedSuffixBits) {
            return ObjectBroadcastAgent.agentIdForHexHashSuffix(Hashing.toHex(hash), suffixBits);
        }
        static agentIdForHexHashSuffix(hexSuffix, suffixBits = this.defaultBroadcastedSuffixBits) {
            return 'object-broadcast-agent-for-' + ObjectBroadcastAgent.trimHexSuffix(hexSuffix, suffixBits);
        }
        static hexSuffixFromHash(hash, suffixBits) {
            return ObjectBroadcastAgent.trimHexSuffix(Hashing.toHex(hash), suffixBits);
        }
        static trimHexSuffix(hashSuffix, suffixBits) {
            if (suffixBits % 4 !== 0) {
                throw new Error('ObjectBroadcastAgent: suffixBits needs to be ' +
                    'a multiple of 4 (received ' + suffixBits + ')');
            }
            const suffixNibbles = suffixBits / 4;
            return hashSuffix.slice(-suffixNibbles);
        }
        static linkupIdForHexHashSuffix(hexSuffix) {
            return 'broadcast-' + hexSuffix;
        }
        getAgentId() {
            return ObjectBroadcastAgent.agentIdForHash(this.literalContext.rootHashes[0], this.broadcastedSuffixBits);
        }
        ready(pod) {
            this.pod = pod;
            for (const linkupServer of this.listening.keys()) {
                this.createListener(linkupServer);
            }
            ObjectBroadcastAgent.log.debug('Started ObjectBroadcastAgent for ' + this.literalContext.rootHashes[0] + ', broadcasted bits: ' + this.broadcastedSuffixBits);
        }
        listenOn(linkupServers, replyEndpoints) {
            for (const linkupServer of linkupServers) {
                for (const replyEndpoint of replyEndpoints) {
                    this.listening.add(linkupServer, replyEndpoint);
                    ObjectBroadcastAgent.log.trace('Listening on ' + linkupServer + ' with replyEndpoint=' + replyEndpoint);
                }
                if (this.pod !== undefined) {
                    this.createListener(linkupServer);
                }
            }
        }
        createListener(linkupServer) {
            const networkAgent = this.getNetworkAgent();
            const broadcastLinkupId = ObjectBroadcastAgent.linkupIdForHexHashSuffix(ObjectBroadcastAgent.hexSuffixFromHash(this.literalContext.rootHashes[0], this.broadcastedSuffixBits));
            let address = new LinkupAddress(linkupServer, broadcastLinkupId);
            networkAgent.listenForLinkupMessages(address.url());
            ObjectBroadcastAgent.log.trace(() => 'Listening for linkup messages on ' + address.url()) + ' for ' + this.literalContext.rootHashes[0];
        }
        receiveLocalEvent(ev) {
            const MIN_BITS_TO_ANSWER = 36;
            if (ev.type === exports.NetworkEventType.LinkupMessageReceived) {
                const msg = ev.content;
                if (msg.agentId === this.getAgentId()) {
                    const req = msg.content;
                    ObjectBroadcastAgent.log.trace(() => 'Received object broadcast query for ' + req.hashSuffix + ' (match: ' + this.hashSuffixMatch(req.hashSuffix) + ')');
                    if (req.hashSuffix.length * 4 >= MIN_BITS_TO_ANSWER && this.hashSuffixMatch(req.hashSuffix)) {
                        const networkAgent = this.getNetworkAgent();
                        const dstAddress = LinkupAddress.fromURL(msg.destination);
                        for (const replyEndpoint of this.listening.get(dstAddress.serverURL)) {
                            if (msg.source !== replyEndpoint) {
                                ObjectBroadcastAgent.log.debug('Answering query from ' + msg.source + ' for suffix ' + req.hashSuffix + ' from endpoint ' + replyEndpoint);
                                const reply = {
                                    source: replyEndpoint,
                                    literalContext: this.literalContext
                                };
                                networkAgent.sendLinkupMessage(LinkupAddress.fromURL(replyEndpoint), LinkupAddress.fromURL(msg.source), req.agentId, reply);
                            }
                        }
                    }
                }
            }
        }
        shutdown() {
            // TODO: stop listening on the linkup addresses
        }
        hashSuffixMatch(suffix) {
            //const receivedBits = suffix.length * 4;
            let ownSuffix = Hashing.toHex(this.literalContext.rootHashes[0]).slice(-suffix.length);
            return ownSuffix === suffix;
        }
        // shorthand functions
        getNetworkAgent() {
            var _a;
            return (_a = this.pod) === null || _a === void 0 ? void 0 : _a.getAgent(NetworkAgent.AgentId);
        }
    }
    ObjectBroadcastAgent.log = new Logger(ObjectBroadcastAgent.name, LogLevel.INFO);
    ObjectBroadcastAgent.defaultBroadcastedSuffixBits = 36;

    /*
        What we want to achieve is to have a stream that can be consumed multiple times
        at the same time, asynchronically, by several clients that may join it over a
        lapse of time.

        The AsyncStreamSource ingests the source of the stream and keeps some or all of
        the contents that it has received, so AsyncStream clients may get some or all of
        the history from before their creation.

        AsyncStreams can then be used to traverse the stream concurrently, with each one
        keeping track of how far in the stream its reader is.

    */
    /*
        Default implementation f an AsyncStreamSource, buffering items
        so clients who create AsyncStreams later can see the full stream.
    */
    class BufferingAsyncStreamSource {
        constructor(maxBufferSize) {
            this.maxBufferSize = maxBufferSize;
            this.buffer = [];
            this.itemSubscriptions = new Set();
            this.endSubscriptions = new Set();
        }
        ingest(item) {
            if (this.maxBufferSize !== undefined &&
                this.maxBufferSize === this.buffer.length) {
                this.buffer.shift();
            }
            this.buffer.push(item);
            for (const itemCallback of this.itemSubscriptions) {
                itemCallback(item);
            }
        }
        ;
        end() {
            for (const endCallback of this.endSubscriptions) {
                endCallback();
            }
        }
        ;
        current() {
            return this.buffer.slice();
        }
        subscribeNewItem(cb) {
            this.itemSubscriptions.add(cb);
        }
        subscribeEnd(cb) {
            this.endSubscriptions.add(cb);
        }
        unsubscribeNewItem(cb) {
            this.itemSubscriptions.delete(cb);
        }
        unsubscribeEnd(cb) {
            this.endSubscriptions.delete(cb);
        }
    }
    class FilteredAsyncStreamSource {
        constructor(upstream, filter) {
            this.upstream = upstream;
            this.filter = filter;
            this.itemSubscribers = new Set();
            this.endSubscribers = new Set();
            this.upstreamItemCallback = (elem) => {
                if (this.filter(elem)) {
                    for (const subscribeItem of this.itemSubscribers) {
                        subscribeItem(elem);
                    }
                }
            };
            this.upstreamEndCallback = () => {
                for (const subscribeEnd of this.endSubscribers) {
                    subscribeEnd();
                }
            };
        }
        current() {
            return this.upstream.current().filter(this.filter);
        }
        subscribeNewItem(cb) {
            const doSubscribe = this.itemSubscribers.size === 0;
            this.itemSubscribers.add(cb);
            if (doSubscribe) {
                this.upstream.subscribeNewItem(this.upstreamItemCallback);
            }
        }
        subscribeEnd(cb) {
            const doSubscribe = this.endSubscribers.size === 0;
            this.endSubscribers.add(cb);
            if (doSubscribe) {
                this.upstream.subscribeEnd(this.upstreamEndCallback);
            }
        }
        unsubscribeNewItem(cb) {
            const beforeSize = this.itemSubscribers.size;
            this.itemSubscribers.delete(cb);
            if (beforeSize > 0 && this.itemSubscribers.size === 0) {
                this.upstream.unsubscribeNewItem(this.upstreamItemCallback);
            }
        }
        unsubscribeEnd(cb) {
            const beforeSize = this.endSubscribers.size;
            this.endSubscribers.delete(cb);
            if (beforeSize > 0 && this.endSubscribers.size === 0) {
                this.upstream.unsubscribeEnd(this.upstreamEndCallback);
            }
        }
    }
    class BufferedAsyncStream {
        constructor(provider) {
            this.isAtEnd = false;
            this.isClosed = false;
            this.provider = provider;
            this.buffer = this.provider.current();
            this.pending = [];
            this.itemCallback = (elem) => {
                var _a;
                if (this.pending.length > 0) {
                    (_a = this.pending.shift()) === null || _a === void 0 ? void 0 : _a.resolve(elem);
                }
                else {
                    this.buffer.push(elem);
                }
            };
            this.endCallback = () => {
                let toReject = this.pending;
                this.pending = [];
                for (const p of toReject) {
                    p.reject('end');
                }
                this.isAtEnd = true;
            };
            this.provider.subscribeNewItem(this.itemCallback);
            this.provider.subscribeEnd(this.endCallback);
        }
        next(timeoutMillis) {
            if (this.buffer.length > 0) {
                return Promise.resolve(this.buffer.shift());
            }
            else {
                let p = new Promise((resolve, reject) => {
                    this.pending.push({ resolve: resolve, reject: reject });
                    if (timeoutMillis !== undefined) {
                        setTimeout(() => {
                            let idx = -1;
                            for (let i = 0; i < this.pending.length; i++) {
                                if (this.pending[i].resolve === resolve) {
                                    idx = i;
                                }
                            }
                            if (idx >= 0) {
                                this.pending.splice(idx, 1);
                            }
                            reject('timeout');
                        }, timeoutMillis);
                    }
                });
                return p;
            }
        }
        nextIfAvailable() {
            if (this.buffer.length > 0) {
                return this.buffer.shift();
            }
            else {
                return undefined;
            }
        }
        countAvailableItems() {
            return this.buffer.length;
        }
        close() {
            this.provider.unsubscribeNewItem(this.itemCallback);
            this.provider.unsubscribeEnd(this.endCallback);
            this.isClosed = true;
        }
        atEnd() {
            return this.isClosed || (this.isAtEnd && this.buffer.length === 0);
        }
    }
    // in case we want to make this support async iteration, this
    /*

    class Stream<T> implements AsyncIterator<T> {
        next(...args: [] | [undefined]) : Promise<IteratorResult<T, any>> {

            throw new Error();

        }
    }


    class InterruptibleStream<T> extends Stream<T> {

    }

    class Stream2<T> {

        [Symbol.iterator]() : AsyncIterator<T> {
            return new Stream<T>();
        }

    }

    class SequencePromise<T> {

        seq: T[];

        constructor() {
            this.seq = [];
        }

        async t() {
            let s = new Stream2<number>();

            for await (const x of s) {
                
            }
        }

        values(): IterableIterator<T> {
            throw new Error();
        }

        next(_timeout: number): Promise<T> {
            throw new Error();
        }

    }

    */

    class ObjectDiscoveryAgent {
        constructor(hexHashSuffix, params) {
            this.wasShutdown = false;
            this.hexHashSuffix = hexHashSuffix;
            if (params === undefined) {
                params = {};
            }
            this.params = {
                broadcastedSuffixBits: (params === null || params === void 0 ? void 0 : params.broadcastedSuffixBits) === undefined ? ObjectBroadcastAgent.defaultBroadcastedSuffixBits : params.broadcastedSuffixBits,
                maxQueryFreq: (params === null || params === void 0 ? void 0 : params.maxQueryFreq) === undefined ? 2 : params.maxQueryFreq,
                maxStoredReplies: (params === null || params === void 0 ? void 0 : params.maxStoredReplies) === undefined ? 15 : params.maxStoredReplies
            };
            this.localEndpoints = new Set();
            this.lastQueryingTimePerServer = new Map();
            this.streamSource = new BufferingAsyncStreamSource(this.params.maxStoredReplies);
        }
        static agentIdForHexHashSuffix(suffix) {
            return 'object-discovery-for-' + suffix;
        }
        getAgentId() {
            return ObjectDiscoveryAgent.agentIdForHexHashSuffix(this.hexHashSuffix);
        }
        ready(pod) {
            this.pod = pod;
        }
        query(linkupServers, localEndpoint, count = 1) {
            if (this.pod === undefined) {
                throw new Error('This ObjectDiscoveryAgent has not been registered to a mesh so it cannot accept queries yet.');
            }
            if (this.wasShutdown) {
                throw new Error('This ObjectDiscoveryAgent was shut down, it cannot accept more queries.');
            }
            const currentTime = Date.now();
            const request = {
                hashSuffix: this.hexHashSuffix,
                agentId: this.getAgentId()
            };
            if (!this.localEndpoints.has(localEndpoint)) {
                ObjectDiscoveryAgent.log.trace('listening on ' + localEndpoint);
                this.getNetworkAgent().listenForLinkupMessages(localEndpoint);
                this.localEndpoints.add(localEndpoint);
            }
            for (const linkupServer of linkupServers) {
                const lastQueryingTime = this.lastQueryingTimePerServer.get(linkupServer);
                if (lastQueryingTime === undefined ||
                    currentTime >= lastQueryingTime + this.params.maxQueryFreq * 1000) {
                    this.lastQueryingTimePerServer.set(linkupServer, currentTime);
                    const broadcasted = ObjectBroadcastAgent.trimHexSuffix(this.hexHashSuffix, this.params.broadcastedSuffixBits);
                    ObjectDiscoveryAgent.log.trace(() => 'Sending peer query from endpoint ' +
                        localEndpoint +
                        ' to endpoint ' +
                        new LinkupAddress(linkupServer, ObjectBroadcastAgent.linkupIdForHexHashSuffix(broadcasted)).url() +
                        ' for suffix ' + this.hexHashSuffix);
                    this.getNetworkAgent().sendLinkupMessage(LinkupAddress.fromURL(localEndpoint), new LinkupAddress(linkupServer, ObjectBroadcastAgent.linkupIdForHexHashSuffix(broadcasted)), ObjectBroadcastAgent.agentIdForHexHashSuffix(this.hexHashSuffix, this.params.broadcastedSuffixBits), request, Math.ceil(count * 1.5));
                }
                else {
                    ObjectDiscoveryAgent.log.trace(() => 'Object discovery query ignored for server ' + linkupServer + ', we queried too recently there.');
                }
            }
        }
        getReplyStream(filterParams) {
            let source = this.streamSource;
            const maxAge = filterParams === null || filterParams === void 0 ? void 0 : filterParams.maxAge;
            const linkupServers = filterParams === null || filterParams === void 0 ? void 0 : filterParams.linkupServers;
            const localEndpoints = filterParams === null || filterParams === void 0 ? void 0 : filterParams.localEndpoints;
            if (maxAge !== undefined ||
                linkupServers !== undefined ||
                localEndpoints !== undefined) {
                let filter = (elem) => {
                    let now = Date.now();
                    let accept = true;
                    accept = accept && (maxAge === undefined || elem.timestamp >= now - maxAge * 1000);
                    accept = accept && (linkupServers === undefined || linkupServers.indexOf(LinkupAddress.fromURL(elem.source).serverURL) >= 0);
                    accept = accept && (localEndpoints === undefined || localEndpoints.indexOf(elem.destination) >= 0);
                    return accept;
                };
                source = new FilteredAsyncStreamSource(source, filter);
            }
            return new BufferedAsyncStream(source);
        }
        receiveLocalEvent(ev) {
            if (!this.wasShutdown && ev.type === exports.NetworkEventType.LinkupMessageReceived) {
                const msg = ev.content;
                if (msg.agentId === this.getAgentId()) {
                    const reply = msg.content;
                    let replyHash = '';
                    let object = undefined;
                    try {
                        object = HashedObject.fromLiteralContext(reply.literalContext);
                        replyHash = object.hash();
                    }
                    catch (e) {
                        ObjectDiscoveryAgent.log.warning('Error deliteralizing object discovery reply:' + e);
                        object = undefined;
                    }
                    if (object !== undefined && replyHash === reply.literalContext.rootHashes[0] &&
                        this.hexHashSuffix === Hashing.toHex(replyHash).slice(-this.hexHashSuffix.length) &&
                        this.localEndpoints.has(msg.destination)) {
                        ObjectDiscoveryAgent.log.trace(() => 'Received object with hash ' + replyHash + ' from ' + msg.source + ' at ' + msg.destination);
                        let item = { source: msg.source, destination: msg.destination, hash: replyHash, object: object, timestamp: Date.now() };
                        this.streamSource.ingest(item);
                    }
                    else {
                        ObjectDiscoveryAgent.log.debug('Error validating object discovery reply');
                    }
                }
            }
        }
        shutdown() {
            // TODO: stop listening on linkup endpoints
            this.wasShutdown = true;
            this.streamSource.end();
        }
        getNetworkAgent() {
            var _a;
            return (_a = this.pod) === null || _a === void 0 ? void 0 : _a.getAgent(NetworkAgent.AgentId);
        }
    }
    ObjectDiscoveryAgent.log = new Logger(ObjectDiscoveryAgent.name, LogLevel.INFO);
    ObjectDiscoveryAgent.newestReplyFirst = (a, b) => (b.timestamp - a.timestamp);

    class ConstantPeerSource {
        constructor(peers) {
            this.peers = new Map(Array.from(peers).map((pi) => [pi.endpoint, pi]));
        }
        async getPeers(count) {
            let peers = Array.from(this.peers.values());
            Shuffle.array(peers);
            if (peers.length > count) {
                peers = peers.slice(0, count);
            }
            return peers;
        }
        async getPeerForEndpoint(endpoint) {
            return this.peers.get(endpoint);
        }
    }

    class HashBasedPeerSource {
        constructor(sources) {
            if (sources === undefined) {
                sources = [];
            }
            this.sources = sources.map(HashBasedPeerSource.toHashedPeerContainer);
        }
        addSource(source) {
            this.sources.push(HashBasedPeerSource.toHashedPeerContainer(source));
        }
        async getPeers(count) {
            let peers = await this.getPeersFromAllSources();
            Shuffle.array(peers);
            if (peers.length > count) {
                peers = peers.slice(0, count);
            }
            return peers;
        }
        async getPeerForEndpoint(endpoint) {
            for (const source of this.sources) {
                let peerInfo = await HashBasedPeerSource.lookupEndpointInSource(endpoint, source);
                if (peerInfo !== undefined) {
                    return peerInfo;
                }
            }
            return undefined;
        }
        static async lookupEndpointInSource(ep, source) {
            let hash = source.parseEndpoint(ep);
            let found = undefined;
            if (hash !== undefined) {
                if (source.items instanceof Map) {
                    found = source.items.get(hash);
                }
                else if (source.items instanceof MutableSet ||
                    source.items instanceof HashedSet) {
                    found = source.items.get(hash);
                }
                else {
                    throw new Error('Unexpected type for peer source.items: ' + (typeof source.items));
                }
            }
            return found !== undefined ? await found.asPeer() : undefined;
        }
        async getPeersFromSource(source) {
            let ts;
            if (source.items instanceof Map) {
                ts = Array.from(source.items.values());
            }
            else if (source instanceof MutableSet ||
                source instanceof HashedSet) {
                ts = Array.from(source.values());
            }
            else {
                throw new Error('Unexpected type for peer source: ' + (typeof source));
            }
            let pis = new Array();
            for (const t of ts) {
                pis.push(await t.asPeer());
            }
            return pis;
            //let x = ts.map((t:T) => t.asPeer());
            //return x.map(async (p: Promise<PeerInfo>) => await p);
        }
        async getPeersFromAllSources() {
            let result = [];
            for (const source of this.sources) {
                result = result.concat(await this.getPeersFromSource(source));
            }
            return result;
        }
        static toHashedPeerContainer(c) {
            let items = c.items instanceof HashedSet || c.items instanceof MutableSet || c.items instanceof Map ?
                c.items : new Map(Array.from(c.items).map((t) => [t.hash(), t]));
            return { items: items, parseEndpoint: c.parseEndpoint };
        }
    }

    class EmptyPeerSource {
        async getPeers(count) {
            return [];
        }
        async getPeerForEndpoint(endpoint) {
            return undefined;
        }
    }

    var JoinMode;
    (function (JoinMode) {
        JoinMode["interleave"] = "interleave";
        JoinMode["eager"] = "eager";
        JoinMode["random"] = "random";
    })(JoinMode || (JoinMode = {}));
    class JoinPeerSources {
        constructor(sources, mode = JoinMode.interleave) {
            this.sources = sources;
            this.mode = mode;
        }
        async getPeers(count) {
            let allPIs = [];
            let total = 0;
            let toFetch = count;
            for (const source of this.sources) {
                let pi = await source.getPeers(toFetch);
                allPIs.push(pi);
                total = total + pi.length;
                if (this.mode === JoinMode.eager) {
                    toFetch = toFetch - pi.length;
                    if (toFetch === 0) {
                        break;
                    }
                }
            }
            let result = [];
            if (this.mode === JoinMode.interleave) {
                while (total > 0 && result.length < count) {
                    for (const pis of allPIs) {
                        if (pis.length > 0 && result.length < count) {
                            let pi = pis.pop();
                            total = total - 1;
                            result.push(pi);
                        }
                    }
                }
            }
            else if (this.mode === JoinMode.random) {
                let all = [];
                for (const pis of allPIs) {
                    all = all.concat(pis);
                }
                Shuffle.array(all);
                result = all.slice(0, count);
            }
            else if (this.mode === JoinMode.eager) {
                for (const pis of allPIs) {
                    result = result.concat(pis);
                }
            }
            return result;
        }
        async getPeerForEndpoint(endpoint) {
            for (const source of this.sources) {
                let pi = await source.getPeerForEndpoint(endpoint);
                if (pi !== undefined) {
                    return pi;
                }
            }
            return undefined;
        }
    }

    class ObjectDiscoveryPeerSource {
        constructor(mesh, object, linkupServers, replyEndpoint, parseEndpoint, timeout = 3) {
            this.mesh = mesh;
            this.object = object;
            this.parseEndpoint = parseEndpoint;
            this.linkupServers = linkupServers;
            this.replyEndpoint = replyEndpoint;
            this.timeoutMillis = timeout * 1000;
            this.hash = object.hash();
        }
        async getPeers(count) {
            let unique = new Set();
            let found = [];
            let now = Date.now();
            let limit = now + this.timeoutMillis;
            if (this.replyStream === undefined) {
                this.replyStream = this.tryObjectDiscovery(count);
            }
            else {
                let reply = this.replyStream.nextIfAvailable();
                while (reply !== undefined && found.length < count) {
                    const peerInfo = await this.parseEndpoint(reply.source);
                    if (peerInfo !== undefined && !unique.has(peerInfo.endpoint)) {
                        found.push(peerInfo);
                        unique.add(peerInfo.endpoint);
                    }
                    reply = this.replyStream.nextIfAvailable();
                }
                if (found.length < count) {
                    this.retryObjectDiscovery(count);
                }
            }
            while (found.length < count && now < limit) {
                now = Date.now();
                try {
                    const reply = await this.replyStream.next(limit - now);
                    const peerInfo = await this.parseEndpoint(reply.source);
                    if (peerInfo !== undefined && !unique.has(peerInfo.endpoint)) {
                        found.push(peerInfo);
                        unique.add(peerInfo.endpoint);
                    }
                }
                catch (reason) {
                    if (reason === 'timeout') {
                        break;
                    }
                    else if (reason === 'end') {
                        this.replyStream = this.tryObjectDiscovery(count - found.length);
                        break;
                    }
                    else {
                        console.log(reason);
                        // something odd happened TODO: log this
                        break;
                    }
                }
            }
            return found;
        }
        getPeerForEndpoint(endpoint) {
            return this.parseEndpoint(endpoint);
        }
        tryObjectDiscovery(count) {
            return this.mesh.findObjectByHash(this.hash, this.linkupServers, this.replyEndpoint, count);
        }
        retryObjectDiscovery(count) {
            this.mesh.findObjectByHashRetry(this.hash, this.linkupServers, this.replyEndpoint, count);
        }
    }

    /* Takes a secret string and a pre-existing peer source, and masks all linkupIds
     *  (the portion of the URL that comes after the hostname) using the secret.
     *
     * It does it by computing an small HMAC for the linkupID (48 bits) and appending
     * it to the endpoint before encrypting (both using the provided secret).
     *
     * To validate an endpoint, it decrypts it and verifies the hmac, and only then it
     * checks with the pre-existing peer source.
     *
     * This way, only folks knowing the secret can join the peer group.
     */
    const HMAC_NIBBLES = 12;
    class SecretBasedPeerSource {
        constructor(peers, secret) {
            this.peers = peers;
            this.secret = secret;
        }
        static maskEndpoint(endpoint, secret) {
            const addr = LinkupAddress.fromURL(endpoint);
            let hmac = new HMAC().hmacSHA256hex(addr.linkupId, secret).slice(-HMAC_NIBBLES);
            let key = new JSHashesSHA().sha256hex(secret);
            let nonce = new JSHashesSHA().sha256hex(key).slice(-24);
            let linkupId = new ChaCha20Universal().encryptHex(addr.linkupId + hmac, key, nonce);
            return new LinkupAddress(addr.serverURL, linkupId).url();
        }
        static unmaskEndpoint(endpoint, secret) {
            const addr = LinkupAddress.fromURL(endpoint);
            let result = undefined;
            try {
                let key = new JSHashesSHA().sha256hex(secret);
                let nonce = new JSHashesSHA().sha256hex(key).slice(-24);
                let clear = new ChaCha20Universal().decryptHex(addr.linkupId, key, nonce);
                let hmac = clear.slice(-HMAC_NIBBLES);
                let linkupId = clear.slice(0, -HMAC_NIBBLES);
                if (hmac === new HMAC().hmacSHA256hex(linkupId, secret).slice(-HMAC_NIBBLES)) {
                    result = linkupId;
                }
            }
            catch (e) {
            }
            return result;
        }
        async getPeers(count) {
            let result = [];
            for (const peer of await this.peers.getPeers(count)) {
                const newEndpoint = SecretBasedPeerSource.maskEndpoint(peer.endpoint, this.secret);
                const newPeer = {
                    endpoint: newEndpoint,
                    identityHash: peer.identityHash
                };
                if (peer.identity !== undefined) {
                    newPeer.identity = peer.identity;
                }
                result.push(newPeer);
            }
            return result;
        }
        async getPeerForEndpoint(endpoint) {
            let result = undefined;
            const unmasked = SecretBasedPeerSource.unmaskEndpoint(endpoint, this.secret);
            if (unmasked !== undefined) {
                result = await this.peers.getPeerForEndpoint(unmasked);
            }
            return result;
        }
    }

    class IdentityPeer {
        constructor(linkupServer, identityHash, identity) {
            this.linkupServer = linkupServer;
            this.identityHash = identityHash;
            this.identity = identity;
        }
        static fromIdentity(id, linkupServer = LinkupManager.defaultLinkupServer) {
            let ip = new IdentityPeer(linkupServer, id.hash(), id);
            return ip;
        }
        async asPeer() {
            return this.asPeerIfReady();
        }
        asPeerIfReady() {
            if (this.linkupServer === undefined || this.identityHash === undefined) {
                throw new Error('Missing peer information.');
            }
            return { endpoint: new LinkupAddress(this.linkupServer, Hashing.toHex(this.identityHash)).url(), identityHash: this.identityHash, identity: this.identity };
        }
        async initFromEndpoint(ep, store) {
            const address = LinkupAddress.fromURL(ep);
            this.linkupServer = address.serverURL;
            this.identityHash = Hashing.fromHex(address.linkupId);
            if (store !== undefined) {
                this.identity = await store.loadRef(new HashReference(this.identityHash, Identity.className));
            }
        }
        static getEndpointParser(store) {
            return async (ep) => {
                const ip = new IdentityPeer();
                await ip.initFromEndpoint(ep, store);
                return ip.asPeer();
            };
        }
    }

    exports.SyncMode = void 0;
    (function (SyncMode) {
        SyncMode["single"] = "single";
        SyncMode["full"] = "full";
        SyncMode["recursive"] = "recursive"; // sync the object, and any mutable object referenced by it or its mutation ops.
    })(exports.SyncMode || (exports.SyncMode = {}));
    class Mesh {
        // configuration
        constructor(networkProxy) {
            this.pod = new AgentPod();
            this.network = new NetworkAgent(new LinkupManager(), networkProxy);
            this.pod.registerAgent(this.network);
            this.secured = new SecureNetworkAgent();
            this.pod.registerAgent(this.secured);
            this.usage = new MultiMap();
            this.usageTokens = new Map();
            this.gossipIdsPerPeerGroup = new MultiMap();
            this.syncAgents = new Map();
            this.rootObjects = new Map();
            this.rootObjectStores = new Map();
            this.gossipIdsPerObject = new MultiMap();
            this.allNewOpCallbacks = new Map();
            this.allRootAncestors = new Map();
            this.allDependencyClosures = new Map();
        }
        // PeerGroups: join, leave
        joinPeerGroup(pg, config, usageToken) {
            let token = this.registerUsage({ type: 'peer-group', peerGroupId: pg.id }, usageToken);
            let agent = this.pod.getAgent(PeerGroupAgent.agentIdForPeerGroup(pg.id));
            if (agent === undefined) {
                agent = new PeerGroupAgent(pg.id, pg.localPeer, pg.peerSource, config);
                this.pod.registerAgent(agent);
            }
            return token;
        }
        leavePeerGroup(token) {
            const usageInfo = this.deregisterUsage(token, 'peer-group');
            if (usageInfo !== undefined) {
                const usageKey = Mesh.createUsageKey(usageInfo);
                if (this.usage.get(usageKey).size === 0) {
                    const agentId = PeerGroupAgent.agentIdForPeerGroup(usageInfo.peerGroupId);
                    let agent = this.pod.getAgent(agentId);
                    if (agent !== undefined) {
                        this.pod.deregisterAgent(agent);
                    }
                }
            }
        }
        // Object synchronization
        syncObjectWithPeerGroup(peerGroupId, obj, mode = exports.SyncMode.full, gossipId, usageToken) {
            let peerGroup = this.pod.getAgent(PeerGroupAgent.agentIdForPeerGroup(peerGroupId));
            if (peerGroup === undefined) {
                throw new Error("Cannot sync object with mesh " + peerGroupId + ", need to join it first.");
            }
            if (gossipId === undefined) {
                gossipId = peerGroupId;
            }
            let gossip = this.pod.getAgent(StateGossipAgent.agentIdForGossip(gossipId));
            if (gossip === undefined) {
                gossip = new StateGossipAgent(gossipId, peerGroup);
                this.pod.registerAgent(gossip);
            }
            else if (gossip.getPeerControl().peerGroupId !== peerGroupId) {
                throw new Error('The gossip id ' + gossipId + ' is already in use buy peer group ' + gossip.getPeerControl().peerGroupId);
            }
            this.addRootSync(gossip, obj, mode);
            this.gossipIdsPerPeerGroup.add(peerGroupId, gossipId);
            return this.registerUsage({ type: 'object-sync', objHash: obj.getLastHash(), peerGroupId: peerGroupId, gossipId: gossipId }, usageToken);
        }
        syncManyObjectsWithPeerGroup(peerGroupId, objs, mode = exports.SyncMode.full, gossipId, usageTokens) {
            const tokens = new Map();
            for (const obj of objs) {
                const usageToken = this.syncObjectWithPeerGroup(peerGroupId, obj, mode, gossipId, usageTokens === null || usageTokens === void 0 ? void 0 : usageTokens.get(obj.getLastHash()));
                tokens.set(obj.getLastHash(), usageToken);
            }
            return tokens;
        }
        stopSyncObjectWithPeerGroup(usageToken) {
            const usageInfo = this.deregisterUsage(usageToken, 'object-sync');
            if (usageInfo !== undefined) {
                const usageKey = Mesh.createUsageKey(usageInfo);
                if (this.usage.get(usageKey).size === 0) {
                    const peerGroupId = usageInfo.peerGroupId;
                    const hash = usageInfo.objHash;
                    const gossipId = usageInfo.gossipId;
                    let gossip = this.pod.getAgent(StateGossipAgent.agentIdForGossip(gossipId));
                    if (gossip !== undefined) {
                        this.removeRootSync(gossip, hash);
                        let roots = this.rootObjects.get(gossipId);
                        if (roots === undefined || roots.size === 0) {
                            this.pod.deregisterAgent(gossip);
                            this.gossipIdsPerPeerGroup.delete(peerGroupId, gossipId);
                        }
                    }
                }
            }
        }
        stopSyncManyObjectsWithPeerGroup(tokens) {
            for (const token of tokens) {
                this.stopSyncObjectWithPeerGroup(token);
            }
        }
        // Object discovery
        startObjectBroadcast(object, linkupServers, replyEndpoints, broadcastedSuffixBits, usageToken) {
            if (broadcastedSuffixBits === undefined) {
                broadcastedSuffixBits = ObjectBroadcastAgent.defaultBroadcastedSuffixBits;
            }
            const agentId = ObjectBroadcastAgent.agentIdForHash(object.hash(), broadcastedSuffixBits);
            let broadcastAgent = this.pod.getAgent(agentId);
            if (broadcastAgent === undefined) {
                broadcastAgent = new ObjectBroadcastAgent(object, broadcastedSuffixBits);
                this.pod.registerAgent(broadcastAgent);
            }
            broadcastAgent.listenOn(linkupServers, replyEndpoints);
            return this.registerUsage({ type: 'object-broadcast', objHash: object.getLastHash(), broadcastedSuffixBits: broadcastedSuffixBits }, usageToken);
        }
        stopObjectBroadcast(token) {
            const usageInfo = this.deregisterUsage(token, 'object-broadcast');
            if (usageInfo !== undefined) {
                const usageKey = Mesh.createUsageKey(usageInfo);
                if (this.usage.get(usageKey).size === 0) {
                    const hash = usageInfo.objHash;
                    const broadcastedSuffixBits = usageInfo.broadcastedSuffixBits;
                    const agentId = ObjectBroadcastAgent.agentIdForHash(hash, broadcastedSuffixBits);
                    let broadcastAgent = this.pod.getAgent(agentId);
                    broadcastAgent === null || broadcastAgent === void 0 ? void 0 : broadcastAgent.shutdown();
                }
            }
        }
        findObjectByHash(hash, linkupServers, replyEndpoint, count = 1, maxAge = 30, strictEndpoints = false) {
            const suffix = Hashing.toHex(hash);
            return this.findObjectByHashSuffix(suffix, linkupServers, replyEndpoint, count, maxAge, strictEndpoints);
        }
        findObjectByHashSuffix(hashSuffix, linkupServers, replyEndpoint, count = 1, maxAge = 30, strictEndpoints = false) {
            const discoveryAgent = this.getDiscoveryAgentFor(hashSuffix);
            discoveryAgent.query(linkupServers, replyEndpoint, count);
            let params = {};
            params.maxAge = maxAge;
            if (strictEndpoints) {
                params.linkupServers = linkupServers;
                params.localEndpoints = [replyEndpoint];
            }
            return discoveryAgent.getReplyStream(params);
        }
        findObjectByHashRetry(hash, linkupServers, replyEndpoint, count = 1) {
            const suffix = Hashing.toHex(hash);
            this.findObjectByHashSuffixRetry(suffix, linkupServers, replyEndpoint, count);
        }
        findObjectByHashSuffixRetry(hashSuffix, linkupServers, replyEndpoint, count = 1) {
            const discoveryAgent = this.getDiscoveryAgentFor(hashSuffix);
            discoveryAgent.query(linkupServers, replyEndpoint, count);
        }
        getDiscoveryAgentFor(hashSuffix) {
            const agentId = ObjectDiscoveryAgent.agentIdForHexHashSuffix(hashSuffix);
            let discoveryAgent = this.pod.getAgent(agentId);
            if (discoveryAgent !== undefined && discoveryAgent.wasShutdown) {
                this.pod.deregisterAgent(discoveryAgent);
                discoveryAgent = undefined;
            }
            if (discoveryAgent === undefined) {
                discoveryAgent = new ObjectDiscoveryAgent(hashSuffix);
                this.pod.registerAgent(discoveryAgent);
            }
            return discoveryAgent;
        }
        addRootSync(gossip, obj, mode) {
            var _a;
            const gossipId = gossip.gossipId;
            let roots = this.rootObjects.get(gossipId);
            if (roots === undefined) {
                roots = new Map();
                this.rootObjects.set(gossipId, roots);
            }
            let rootStores = this.rootObjectStores.get(gossipId);
            if (rootStores === undefined) {
                rootStores = new Map();
                this.rootObjectStores.set(gossipId, rootStores);
            }
            let hash = obj.hash();
            let oldMode = roots.get(hash);
            if (oldMode === undefined) {
                roots.set(hash, mode);
                rootStores.set(hash, (_a = obj.getResources()) === null || _a === void 0 ? void 0 : _a.store);
                if (mode === exports.SyncMode.single) {
                    if (obj instanceof MutableObject) {
                        this.addSingleObjectSync(gossip, hash, obj);
                    }
                    else {
                        throw new Error('Asked to sync object in single mode, but it is not mutable, so there is nothing to do.');
                    }
                }
                else {
                    this.addFullObjectSync(gossip, obj, hash, mode);
                }
            }
            else if (oldMode !== mode) {
                throw new Error('The object ' + hash + ' was already being gossiped on ' + gossipId + ', but with a different mode. Gossiping with more than one mode is not supported.');
            }
        }
        removeRootSync(gossip, objHash) {
            let roots = this.rootObjects.get(gossip.gossipId);
            let rootStores = this.rootObjectStores.get(gossip.gossipId);
            if (roots !== undefined) {
                let oldMode = roots.get(objHash);
                if (oldMode !== undefined) {
                    roots.delete(objHash);
                    if (oldMode === exports.SyncMode.single) {
                        let modes = this.getAllModesForObject(gossip, objHash);
                        if (modes.size === 0) {
                            this.removeSingleObjectSync(gossip, objHash);
                        }
                    }
                    else {
                        const store = rootStores === null || rootStores === void 0 ? void 0 : rootStores.get(objHash);
                        this.removeFullObjectSync(gossip, objHash, objHash, oldMode, store);
                    }
                }
            }
        }
        // get all the modes this objHash is being synced within all gossip ids
        // that share their peer group with the provided one.
        getAllModesForObject(gossip, objHash) {
            var _a;
            let modes = new Set();
            if (gossip !== undefined) {
                let peerGroupId = gossip.peerGroupAgent.peerGroupId;
                let matchGossipIds = this.gossipIdsPerPeerGroup.get(peerGroupId);
                if (matchGossipIds !== undefined) {
                    for (const matchGossipId of matchGossipIds) {
                        let roots = this.rootObjects.get(matchGossipId);
                        let mode = roots === null || roots === void 0 ? void 0 : roots.get(objHash);
                        if (mode !== undefined) {
                            modes.add(mode);
                        }
                        let rootAncestors = (_a = this.allRootAncestors.get(matchGossipId)) === null || _a === void 0 ? void 0 : _a.get(objHash);
                        if (rootAncestors !== undefined) {
                            for (const rootHash of rootAncestors) {
                                let rootMode = roots === null || roots === void 0 ? void 0 : roots.get(rootHash);
                                if (rootMode !== undefined) {
                                    modes.add(rootMode);
                                }
                            }
                        }
                    }
                }
                return modes;
            }
            return modes;
        }
        addFullObjectSync(gossip, obj, root, mode) {
            const gossipId = gossip.gossipId;
            let hash = obj.hash();
            let dependencies = this.allDependencyClosures.get(gossipId);
            if (dependencies === undefined) {
                dependencies = new MultiMap();
                this.allDependencyClosures.set(gossipId, dependencies);
            }
            if (!dependencies.get(root).has(hash)) {
                let rootAncestors = this.allRootAncestors.get(gossipId);
                if (rootAncestors === undefined) {
                    rootAncestors = new MultiMap();
                    this.allRootAncestors.set(gossipId, rootAncestors);
                }
                let targets = new Map();
                if (mode === exports.SyncMode.single) {
                    if (obj instanceof MutableObject) {
                        targets.set(hash, obj);
                    }
                }
                else {
                    // (mode === SyncMode.subobjects || mode === SyncMode.mutations)
                    let context = obj.toContext();
                    for (let [hash, dep] of context.objects.entries()) {
                        if (dep instanceof MutableObject) {
                            targets.set(hash, dep);
                        }
                    }
                }
                for (const [thash, target] of targets.entries()) {
                    this.addSingleObjectSync(gossip, thash, target);
                    dependencies.add(root, thash);
                    rootAncestors.add(thash, root);
                    if (mode === exports.SyncMode.recursive) {
                        this.watchForNewOps(gossip, target);
                        this.trackOps(gossip, target, root);
                    }
                }
            }
        }
        removeFullObjectSync(gossip, mutHash, oldRootHash, oldMode, store) {
            var _a;
            let depClosures = this.allDependencyClosures.get(gossip.gossipId);
            let depClosure = depClosures === null || depClosures === void 0 ? void 0 : depClosures.get(mutHash);
            if (depClosure !== undefined) {
                depClosures === null || depClosures === void 0 ? void 0 : depClosures.deleteKey(mutHash);
                for (const depHash of depClosure) {
                    (_a = this.allRootAncestors.get(gossip.gossipId)) === null || _a === void 0 ? void 0 : _a.delete(depHash, oldRootHash);
                }
                for (const depHash of depClosure) {
                    const modes = this.getAllModesForObject(gossip, depHash);
                    if (modes.size === 0) {
                        this.removeSingleObjectSync(gossip, depHash);
                    }
                    if (oldMode === exports.SyncMode.recursive && !modes.has(exports.SyncMode.recursive)) {
                        this.unwatchForNewOps(gossip, depHash, store);
                    }
                }
            }
        }
        addSingleObjectSync(gossip, mutHash, mut) {
            const peerGroup = gossip.peerGroupAgent;
            const peerGroupId = peerGroup.peerGroupId;
            let peerGroupSyncAgents = this.syncAgents.get(peerGroupId);
            if (peerGroupSyncAgents === undefined) {
                peerGroupSyncAgents = new Map();
                this.syncAgents.set(peerGroupId, peerGroupSyncAgents);
            }
            let sync = peerGroupSyncAgents.get(mutHash);
            if (sync === undefined) {
                sync = mut.createSyncAgent(gossip.peerGroupAgent);
                peerGroupSyncAgents.set(mutHash, sync);
                gossip.trackAgentState(sync.getAgentId());
                this.pod.registerAgent(sync);
            }
        }
        removeSingleObjectSync(gossip, mutHash) {
            if (gossip !== undefined) {
                const peerGroup = gossip.peerGroupAgent;
                const peerGroupId = peerGroup.peerGroupId;
                let peerGroupSyncAgents = this.syncAgents.get(peerGroupId);
                let sync = peerGroupSyncAgents === null || peerGroupSyncAgents === void 0 ? void 0 : peerGroupSyncAgents.get(mutHash);
                if (sync !== undefined) {
                    gossip.untrackAgentState(sync.getAgentId());
                    this.pod.deregisterAgent(sync);
                    peerGroupSyncAgents === null || peerGroupSyncAgents === void 0 ? void 0 : peerGroupSyncAgents.delete(mutHash);
                }
            }
        }
        // recursive tracking of subobjects for state gossip & sync
        // Fetch existing ops on the databse and check if there are any mutable
        // references to track.
        async trackOps(gossip, mut, root) {
            let validOpClasses = mut.getAcceptedMutationOpClasses();
            let refs = await mut.getStore().loadByReference('targetObject', mut.hash());
            for (let obj of refs.objects) {
                if (validOpClasses.indexOf(obj.getClassName()) >= 0) {
                    this.addFullObjectSync(gossip, mut, root, exports.SyncMode.recursive);
                }
            }
        }
        watchForNewOps(gossip, mut) {
            let newOpCallbacks = this.allNewOpCallbacks.get(gossip.gossipId);
            if (newOpCallbacks === undefined) {
                newOpCallbacks = new Map();
                this.allNewOpCallbacks.set(gossip.gossipId, newOpCallbacks);
            }
            let hash = mut.hash();
            if (!newOpCallbacks.has(hash)) {
                let callback = async (opHash) => {
                    var _a, _b;
                    let op = await mut.getStore().load(opHash);
                    if (op !== undefined &&
                        mut.getAcceptedMutationOpClasses().indexOf(op.getClassName()) >= 0) {
                        let mutOp = op;
                        const roots = (_a = this.allRootAncestors.get(gossip.gossipId)) === null || _a === void 0 ? void 0 : _a.get(mutOp.getTargetObject().hash());
                        if (roots !== undefined) {
                            for (const rootHash of roots) {
                                if (((_b = this.rootObjects.get(gossip.gossipId)) === null || _b === void 0 ? void 0 : _b.get(rootHash)) === exports.SyncMode.recursive) {
                                    this.addFullObjectSync(gossip, op, rootHash, exports.SyncMode.recursive);
                                }
                            }
                        }
                    }
                };
                newOpCallbacks.set(hash, callback);
                mut.getStore().watchReferences('targetObject', mut.hash(), callback);
            }
        }
        unwatchForNewOps(gossip, mutHash, store) {
            let newOpCallbacks = this.allNewOpCallbacks.get(gossip.gossipId);
            const callback = newOpCallbacks === null || newOpCallbacks === void 0 ? void 0 : newOpCallbacks.get(mutHash);
            if (callback !== undefined) {
                store.removeReferencesWatch('targetObject', mutHash, callback);
                newOpCallbacks === null || newOpCallbacks === void 0 ? void 0 : newOpCallbacks.delete(mutHash);
            }
        }
        registerUsage(usageInfo, usageToken) {
            const token = usageToken || Mesh.createUsageToken();
            this.usageTokens.set(token, usageInfo);
            const usageKey = Mesh.createUsageKey(usageInfo);
            this.usage.add(usageKey, token);
            return token;
        }
        deregisterUsage(token, expectedType) {
            const usageInfo = this.usageTokens.get(token);
            if (usageInfo !== undefined) {
                if (usageInfo.type !== expectedType) {
                    throw new Error('Refusing to deregister usage token ' + token + ': it is being used as for ' + expectedType + ', but originally was for ' + usageInfo.type);
                }
                const usageKey = Mesh.createUsageKey(usageInfo);
                this.usage.delete(usageKey, token);
                this.usageTokens.delete(token);
                return usageInfo;
            }
            else {
                return undefined;
            }
        }
        static createUsageToken() {
            return new BrowserRNG().randomHexString(128);
        }
        static createUsageKey(usageInfo) {
            if (usageInfo.type === 'peer-group') {
                return usageInfo.type + '-' + usageInfo.peerGroupId.replace(/[-]/g, '--');
            }
            else if (usageInfo.type === 'object-sync') {
                return usageInfo.type + '-' + usageInfo.peerGroupId.replace(/[-]/g, '--') + '-' + usageInfo.gossipId.replace(/[-]/g, '--');
            }
            else {
                return usageInfo.type + '-' + usageInfo.objHash + '-' + usageInfo.broadcastedSuffixBits;
            }
        }
    }

    class MeshHost {
        constructor(mesh, streamedReplyCb, peerSourceReqCb) {
            this.mesh = mesh;
            this.streamedReplyCb = streamedReplyCb;
            this.peerSourceReqCb = peerSourceReqCb;
            this.pendingPeersRequests = new Map();
            this.pendingPeerForEndpointRequests = new Map();
            this.stores = new Map();
        }
        static isCommand(msg) {
            const type = msg === null || msg === void 0 ? void 0 : msg.type;
            return (type === 'join-peer-group' ||
                type === 'check-peer-group-usage' ||
                type === 'leave-peer-group' ||
                type === 'sync-objects-with-peer-group' ||
                type === 'stop-sync-objects-with-peer-group' ||
                type === 'start-object-broadcast' ||
                type === 'stop-object-broadcast' ||
                type === 'find-object-by-hash' ||
                type === 'find-object-by-hash-suffix' ||
                type === 'object-discovery-reply' ||
                type === 'object-discovery-end' ||
                type === 'forward-get-peers-reply' ||
                type === 'forward-get-peer-for-endpoint-reply');
        }
        static isStreamedReply(msg) {
            const type = msg === null || msg === void 0 ? void 0 : msg.type;
            return (type === 'object-discovery-reply' ||
                type === 'object-discovery-end');
        }
        static isPeerSourceRequest(msg) {
            const type = msg === null || msg === void 0 ? void 0 : msg.type;
            return (type === 'get-peers' || type === 'get-peer-for-endpoint');
        }
        execute(command) {
            //let error: string | undefined;
            var _a, _b;
            if (command.type === 'join-peer-group') {
                const join = command;
                let peerSource = new PeerSourceProxy(this, join.peerGroupId);
                const identity = (join.localPeerIdentity === undefined ? undefined : HashedObject.fromLiteralContext(join.localPeerIdentity));
                if (identity !== undefined && join.localPeerIdentityKeyPair !== undefined) {
                    identity._keyPair = HashedObject.fromLiteralContext(join.localPeerIdentityKeyPair);
                }
                let localPeer = {
                    endpoint: join.localPeerEndpoint,
                    identityHash: join.localPeerIdentityHash,
                    identity: identity
                };
                this.mesh.joinPeerGroup({ id: join.peerGroupId, localPeer: localPeer, peerSource: peerSource }, join.config, join.usageToken);
            }
            else if (command.type === 'leave-peer-group') {
                const leave = command;
                this.mesh.leavePeerGroup(leave.usageToken);
            }
            else if (command.type === 'sync-objects-with-peer-group') {
                const syncObjs = command;
                let objs = [];
                let tokens = undefined;
                if (syncObjs.usageTokens !== undefined) {
                    tokens = new Map();
                }
                let context = new Context();
                context.fromLiteralContext(syncObjs.objContext);
                for (const hash of syncObjs.objContext.rootHashes) {
                    const obj = HashedObject.fromContext(context, hash);
                    objs.push(obj);
                    if (tokens !== undefined) {
                        tokens.set(hash, syncObjs.usageTokens[hash]);
                    }
                }
                for (const [hash, obj] of context.objects.entries()) {
                    if (syncObjs.stores[hash] !== undefined) {
                        const backendName = syncObjs.stores[hash]['backendName'];
                        const dbName = syncObjs.stores[hash]['dbName'];
                        if (!this.stores.has(backendName)) {
                            this.stores.set(backendName, new Map());
                        }
                        let db = (_a = this.stores.get(backendName)) === null || _a === void 0 ? void 0 : _a.get(dbName);
                        if (db === undefined) {
                            db = Store.load(backendName, dbName);
                            if (db !== undefined) {
                                (_b = this.stores.get(backendName)) === null || _b === void 0 ? void 0 : _b.set(dbName, db);
                            }
                        }
                        if (db !== undefined) {
                            obj.setStore(db);
                        }
                        else {
                            console.log('WARNING: missing store for ' + hash);
                        }
                    }
                }
                this.mesh.syncManyObjectsWithPeerGroup(syncObjs.peerGroupId, objs.values(), syncObjs.mode, syncObjs.gossipId, tokens);
            }
            else if (command.type === 'stop-sync-objects-with-peer-group') {
                const stopSyncObjs = command;
                this.mesh.stopSyncManyObjectsWithPeerGroup(stopSyncObjs.usageTokens.values());
            }
            else if (command.type === 'start-object-broadcast') {
                const startBcast = command;
                let obj = HashedObject.fromLiteralContext(startBcast.objContext);
                this.mesh.startObjectBroadcast(obj, startBcast.linkupServers, startBcast.replyEndpoints, startBcast.broadcastedSuffixBits, startBcast.usageToken);
            }
            else if (command.type === 'stop-object-broadcast') {
                const stopBcast = command;
                this.mesh.stopObjectBroadcast(stopBcast.usageToken);
            }
            else if (command.type === 'find-object-by-hash' ||
                command.type === 'find-object-by-hash-suffix') {
                const find = command;
                if (!find.retry) {
                    const streamId = command.streamId;
                    let replyStream;
                    if (command.type === 'find-object-by-hash') {
                        replyStream = this.mesh.findObjectByHash(find.hash, find.linkupServers, find.replyEndpoint, find.count, find.maxAge, find.strictEndpoints);
                    }
                    else {
                        replyStream = this.mesh.findObjectByHashSuffix(find.hashSuffix, find.linkupServers, find.replyEndpoint, find.count, find.maxAge, find.strictEndpoints);
                    }
                    const tt = setTimeout(async () => {
                        try {
                            while (!replyStream.atEnd()) {
                                const discov = await replyStream.next();
                                let reply = {
                                    type: 'object-discovery-reply',
                                    streamId: streamId,
                                    source: discov.source,
                                    destination: discov.destination,
                                    hash: discov.hash,
                                    objContext: discov.object.toLiteralContext(),
                                    timestamp: discov.timestamp
                                };
                                this.streamedReplyCb(reply);
                            }
                        }
                        finally {
                            let replyEnd = {
                                type: 'object-discovery-end',
                                streamId: streamId
                            };
                            this.streamedReplyCb(replyEnd);
                            clearTimeout(tt);
                        }
                    }, 0);
                }
                else {
                    if (command.type === 'find-object-by-hash') {
                        this.mesh.findObjectByHashRetry(find.hash, find.linkupServers, find.replyEndpoint, find.count);
                    }
                    else {
                        this.mesh.findObjectByHashSuffixRetry(find.hashSuffix, find.linkupServers, find.replyEndpoint, find.count);
                    }
                }
            }
            else if (command.type === 'forward-get-peers-reply') {
                const reply = command;
                let ex = this.pendingPeersRequests.get(reply.requestId);
                if (ex !== undefined) {
                    if (reply.error) {
                        ex.reject('Received rejection through remoting');
                    }
                    else {
                        ex.resolve(reply.peers);
                    }
                }
            }
            else if (command.type === 'forward-get-peer-for-endpoint-reply') {
                const reply = command;
                let ex = this.pendingPeerForEndpointRequests.get(reply.requestId);
                if (ex !== undefined) {
                    if (reply.error) {
                        ex.reject('Received rejection through remoting');
                    }
                    else {
                        ex.resolve(reply.peerInfo);
                    }
                }
            }
        }
        registerPeersRequest(requestId, executor) {
            this.pendingPeersRequests.set(requestId, executor);
        }
        registerPeerForEndpointRequest(requestId, executor) {
            this.pendingPeerForEndpointRequests.set(requestId, executor);
        }
    }
    class PeerSourceProxy {
        constructor(host, peerGroupId) {
            this.host = host;
            this.peerGroupId = peerGroupId;
        }
        getPeers(count) {
            let requestId = new BrowserRNG().randomHexString(128);
            let result = new Promise((resolve, reject) => {
                this.host.registerPeersRequest(requestId, { resolve: resolve, reject: reject });
            });
            this.host.peerSourceReqCb({
                type: 'get-peers',
                peerGroupId: this.peerGroupId,
                count: count,
                requestId: requestId
            });
            return result;
        }
        getPeerForEndpoint(endpoint) {
            let requestId = new BrowserRNG().randomHexString(128);
            let result = new Promise((resolve, reject) => {
                this.host.registerPeerForEndpointRequest(requestId, { resolve: resolve, reject: reject });
            });
            this.host.peerSourceReqCb({
                type: 'get-peer-for-endpoint',
                peerGroupId: this.peerGroupId,
                endpoint: endpoint,
                requestId: requestId
            });
            return result;
        }
    }

    class MeshProxy {
        constructor(meshCommandFwdFn, linkupCommandFwdFn, webRTCConnEventIngestFn) {
            this.commandForwardingFn = meshCommandFwdFn;
            this.discoveryStreamSources = new Map();
            if (linkupCommandFwdFn !== undefined) {
                this.linkup = new LinkupManagerProxy(linkupCommandFwdFn);
            }
            if (webRTCConnEventIngestFn !== undefined) {
                this.webRTCConnsHost = new WebRTCConnectionsHost(webRTCConnEventIngestFn, this.linkup); // ugly
            }
            this.commandStreamedReplyIngestFn = (reply) => {
                var _a, _b;
                if (reply.type === 'object-discovery-reply') {
                    const literalReply = reply;
                    const objReply = {
                        source: literalReply.source,
                        destination: literalReply.destination,
                        hash: literalReply.hash,
                        object: HashedObject.fromLiteralContext(literalReply.objContext),
                        timestamp: literalReply.timestamp
                    };
                    (_a = this.discoveryStreamSources.get(literalReply.streamId)) === null || _a === void 0 ? void 0 : _a.ingest(objReply);
                }
                else if (reply.type === 'object-discovery-end') {
                    const endReply = reply;
                    (_b = this.discoveryStreamSources.get(endReply.streamId)) === null || _b === void 0 ? void 0 : _b.end();
                    this.discoveryStreamSources.delete(endReply.streamId);
                }
            };
            this.peerSources = new Map();
            this.peerSourceRequestIngestFn = (req) => {
                if (req.type === 'get-peers') {
                    const source = this.peerSources.get(req.peerGroupId);
                    if (source !== undefined) {
                        source.getPeers(req.count).then((value) => {
                            this.commandForwardingFn({
                                type: 'forward-get-peers-reply',
                                requestId: req.requestId,
                                peers: value,
                                error: false
                            });
                        }, (_reason) => {
                            this.commandForwardingFn({
                                type: 'forward-get-peers-reply',
                                requestId: req.requestId,
                                peers: [],
                                error: true
                            });
                        });
                    }
                }
                else if (req.type === 'get-peer-for-endpoint') {
                    const source = this.peerSources.get(req.peerGroupId);
                    if (source !== undefined) {
                        source.getPeerForEndpoint(req.endpoint).then((value) => {
                            this.commandForwardingFn({
                                type: 'forward-get-peer-for-endpoint-reply',
                                requestId: req.requestId,
                                peerInfo: value,
                                error: false
                            });
                        }, (_reason) => {
                            this.commandForwardingFn({
                                type: 'forward-get-peer-for-endpoint-reply',
                                requestId: req.requestId,
                                peerInfo: undefined,
                                error: true
                            });
                        });
                    }
                }
            };
        }
        getCommandStreamedReplyIngestFn() {
            return this.commandStreamedReplyIngestFn;
        }
        joinPeerGroup(pg, config, usageToken) {
            var _a;
            if (!this.peerSources.has(pg.id)) {
                this.peerSources.set(pg.id, pg.peerSource);
            }
            const token = usageToken || Mesh.createUsageToken();
            const cmd = {
                type: 'join-peer-group',
                peerGroupId: pg.id,
                localPeerEndpoint: pg.localPeer.endpoint,
                localPeerIdentityHash: pg.localPeer.identityHash,
                localPeerIdentity: pg.localPeer.identity === undefined ? undefined : pg.localPeer.identity.toLiteralContext(),
                localPeerIdentityKeyPair: ((_a = pg.localPeer.identity) === null || _a === void 0 ? void 0 : _a._keyPair) === undefined ? undefined : pg.localPeer.identity._keyPair.toLiteralContext(),
                config: config,
                usageToken: token
            };
            this.commandForwardingFn(cmd);
            return token;
        }
        leavePeerGroup(usageToken) {
            const cmd = {
                type: 'leave-peer-group',
                usageToken: usageToken
            };
            this.commandForwardingFn(cmd);
        }
        syncObjectWithPeerGroup(peerGroupId, obj, mode = exports.SyncMode.full, gossipId, usageToken) {
            const ctx = obj.toContext();
            let stores = {};
            for (const [hash, o] of ctx.objects.entries()) {
                const store = o.getStore();
                if (store !== undefined) {
                    stores[hash] = { backendName: store.getBackendName(), dbName: store.getName() };
                }
            }
            let tokens = {};
            const token = usageToken || Mesh.createUsageToken();
            tokens[ctx.rootHashes[0]] = token;
            const cmd = {
                type: 'sync-objects-with-peer-group',
                peerGroupId: peerGroupId,
                objContext: obj.toLiteralContext(),
                stores: stores,
                mode: mode,
                gossipId: gossipId,
                usageTokens: tokens
            };
            this.commandForwardingFn(cmd);
            return token;
        }
        syncManyObjectsWithPeerGroup(peerGroupId, objs, mode = exports.SyncMode.full, gossipId, usageTokens) {
            const objContext = new Context();
            let tokens = {};
            let resultTokens = new Map();
            for (const obj of objs) {
                objContext.merge(obj.toContext());
                const token = (usageTokens === null || usageTokens === void 0 ? void 0 : usageTokens.get(obj.getLastHash())) || Mesh.createUsageToken();
                tokens[obj.getLastHash()] = token;
                resultTokens.set(obj.getLastHash(), token);
            }
            let stores = {};
            for (const [hash, o] of objContext.objects.entries()) {
                const store = o.getStore();
                if (store !== undefined) {
                    stores[hash] = { backendName: store.getBackendName(), dbName: store.getName() };
                }
            }
            const cmd = {
                type: 'sync-objects-with-peer-group',
                peerGroupId: peerGroupId,
                objContext: objContext.toLiteralContext(),
                stores: stores,
                mode: mode,
                gossipId: gossipId,
                usageTokens: tokens
            };
            this.commandForwardingFn(cmd);
            return resultTokens;
        }
        stopSyncObjectWithPeerGroup(usageToken) {
            const cmd = {
                type: 'stop-sync-objects-with-peer-group',
                usageTokens: [usageToken]
            };
            this.commandForwardingFn(cmd);
        }
        stopSyncManyObjectsWithPeerGroup(usageTokens) {
            const cmd = {
                type: 'stop-sync-objects-with-peer-group',
                usageTokens: Array.from(usageTokens)
            };
            this.commandForwardingFn(cmd);
        }
        startObjectBroadcast(object, linkupServers, replyEndpoints, broadcastedSuffixBits, usageToken) {
            if (usageToken === undefined) {
                usageToken = Mesh.createUsageToken();
            }
            const cmd = {
                type: 'start-object-broadcast',
                objContext: object.toLiteralContext(),
                linkupServers: linkupServers,
                replyEndpoints: replyEndpoints,
                broadcastedSuffixBits: broadcastedSuffixBits,
                usageToken: usageToken
            };
            this.commandForwardingFn(cmd);
            return usageToken;
        }
        stopObjectBroadcast(usageToken) {
            const cmd = {
                type: 'stop-object-broadcast',
                usageToken: usageToken
            };
            this.commandForwardingFn(cmd);
        }
        findObjectByHash(hash, linkupServers, replyEndpoint, count = 1, maxAge = 30, strictEndpoints = false) {
            const streamId = new BrowserRNG().randomHexString(64);
            const src = new BufferingAsyncStreamSource();
            this.discoveryStreamSources.set(streamId, src);
            const cmd = {
                type: 'find-object-by-hash',
                hash: hash,
                linkupServers: linkupServers,
                replyEndpoint: replyEndpoint,
                count: count,
                maxAge: maxAge,
                strictEndpoints: strictEndpoints,
                retry: false,
                streamId: streamId
            };
            this.commandForwardingFn(cmd);
            return new BufferedAsyncStream(src);
        }
        findObjectByHashSuffix(hashSuffix, linkupServers, replyEndpoint, count = 1, maxAge = 30, strictEndpoints = false) {
            const streamId = new BrowserRNG().randomHexString(64);
            const src = new BufferingAsyncStreamSource();
            this.discoveryStreamSources.set(streamId, src);
            const cmd = {
                type: 'find-object-by-hash-suffix',
                hashSuffix: hashSuffix,
                linkupServers: linkupServers,
                replyEndpoint: replyEndpoint,
                count: count,
                maxAge: maxAge,
                strictEndpoints: strictEndpoints,
                retry: false,
                streamId: streamId
            };
            this.commandForwardingFn(cmd);
            return new BufferedAsyncStream(src);
        }
        findObjectByHashRetry(hash, linkupServers, replyEndpoint, count = 1) {
            const cmd = {
                type: 'find-object-by-hash',
                hash: hash,
                linkupServers: linkupServers,
                replyEndpoint: replyEndpoint,
                count: count,
                retry: true,
            };
            this.commandForwardingFn(cmd);
        }
        findObjectByHashSuffixRetry(hashSuffix, linkupServers, replyEndpoint, count = 1) {
            const cmd = {
                type: 'find-object-by-hash-suffix',
                hashSuffix: hashSuffix,
                linkupServers: linkupServers,
                replyEndpoint: replyEndpoint,
                count: count,
                retry: true,
            };
            this.commandForwardingFn(cmd);
        }
    }

    class PeerGroup {
        getResources() {
            return this.resources;
        }
        async init(resources) {
            this.resources = resources;
        }
        async getPeerGroupInfo() {
            return {
                id: this.getPeerGroupId(),
                localPeer: await this.getLocalPeer(),
                peerSource: await this.getPeerSource()
            };
        }
    }

    class PeerNode {
        constructor(resources) {
            this.resources = resources;
            this.peerGroupTokens = new Map();
            this.syncTokens = new Map();
            this.broadcastTokens = new Map();
            this.syncPerPeerGroup = new MultiMap();
        }
        async broadcast(obj, linkupServers, localEndpoints) {
            if (linkupServers === undefined) {
                linkupServers = this.resources.config.linkupServers;
            }
            if (localEndpoints === undefined) {
                localEndpoints = this.resources.getPeersForDiscovery().map((pi) => pi.endpoint);
            }
            const token = this.resources.mesh.startObjectBroadcast(obj, linkupServers, localEndpoints);
            this.broadcastTokens.set(obj.getLastHash(), token);
        }
        async stopBroadcast(obj) {
            const token = this.broadcastTokens.get(obj.hash());
            if (token !== undefined) {
                this.resources.mesh.stopObjectBroadcast(token);
                this.broadcastTokens.delete(obj.getLastHash());
            }
        }
        async sync(obj, mode = exports.SyncMode.full, peerGroup, gossipId) {
            if (peerGroup === undefined) {
                peerGroup = await this.discoveryPeerGroupInfo(obj);
            }
            const peerGroupKey = PeerNode.generateKey([peerGroup.id]);
            let peerGroupToken = this.peerGroupTokens.get(peerGroupKey);
            if (peerGroupToken === undefined) {
                peerGroupToken = this.resources.mesh.joinPeerGroup(peerGroup);
                this.peerGroupTokens.set(peerGroupKey, peerGroupToken);
            }
            const syncKey = PeerNode.generateKey([obj.hash(), peerGroup.id, gossipId]);
            let syncToken = this.syncTokens.get(syncKey);
            if (syncToken === undefined) {
                syncToken = this.resources.mesh.syncObjectWithPeerGroup(peerGroup.id, obj, mode, gossipId);
                this.syncTokens.set(syncKey, syncToken);
                this.syncPerPeerGroup.add(peerGroupToken, syncToken);
            }
        }
        async stopSync(obj, peerGroupId, gossipId) {
            if (peerGroupId === undefined) {
                peerGroupId = PeerNode.discoveryPeerGroupInfoId(obj);
            }
            const syncKey = PeerNode.generateKey([obj.hash(), peerGroupId, gossipId]);
            const syncToken = this.syncTokens.get(syncKey);
            if (syncToken !== undefined) {
                this.resources.mesh.stopSyncObjectWithPeerGroup(syncToken);
                this.syncTokens.delete(syncKey);
                const peerGroupKey = PeerNode.generateKey([peerGroupId]);
                const peerGroupToken = this.peerGroupTokens.get(peerGroupKey);
                if (peerGroupToken !== undefined) {
                    this.syncPerPeerGroup.delete(peerGroupToken, syncToken);
                    if (this.syncPerPeerGroup.get(peerGroupToken).size === 0) {
                        this.resources.mesh.leavePeerGroup(peerGroupToken);
                        this.peerGroupTokens.delete(peerGroupKey);
                    }
                }
            }
        }
        async discoveryPeerGroupInfo(obj) {
            let localPeer = this.resources.getPeersForDiscovery()[0];
            let peerSource = new ObjectDiscoveryPeerSource(this.resources.mesh, obj, this.resources.config.linkupServers, localPeer.endpoint, this.resources.getEndointParserForDiscovery());
            return {
                id: PeerNode.discoveryPeerGroupInfoId(obj),
                localPeer: localPeer,
                peerSource: peerSource
            };
        }
        static discoveryPeerGroupInfoId(obj) {
            return 'sync-for-' + obj.hash();
        }
        static generateKey(parts) {
            let result = '';
            for (const part of parts) {
                if (part !== undefined) {
                    if (result.length > 0) {
                        result = result + '-';
                    }
                    result = result + part.replace(/[-]/g, '--');
                }
            }
            return result;
        }
    }

    /* eslint-disable-next-line no-restricted-globals */
    //const worker: DedicatedWorkerGlobalScope | undefined = self || undefined as any;
    class WebWorkerMeshHost {
        constructor() {
            this.worker = self;
            this.linkupEventIngestFn = (ev) => {
                WebWorkerMeshHost.logger.trace('Sending linkup event to main thread: ' + (ev === null || ev === void 0 ? void 0 : ev.type));
                WebWorkerMeshHost.logger.trace(ev);
                try {
                    this.worker.postMessage(ev);
                }
                catch (e) {
                    WebWorkerMeshHost.logger.warning('Could not send linkup event to main thread:');
                    WebWorkerMeshHost.logger.warning(ev);
                    WebWorkerMeshHost.logger.warning('Error was: ' + e);
                }
            };
            this.webRTCCommandFn = (cmd) => {
                WebWorkerMeshHost.logger.trace('Sending webrtc command to main thread: ' + (cmd === null || cmd === void 0 ? void 0 : cmd.type));
                WebWorkerMeshHost.logger.trace(cmd);
                try {
                    this.worker.postMessage(cmd);
                }
                catch (e) {
                    WebWorkerMeshHost.logger.warning('Could not send webrtc command to main thread:');
                    WebWorkerMeshHost.logger.warning(cmd);
                    WebWorkerMeshHost.logger.warning('Error was: ' + e);
                }
            };
            const proxyConfig = {
                linkupEventIngestFn: this.linkupEventIngestFn,
                webRTCCommandFn: this.webRTCCommandFn
            };
            this.mesh = new Mesh(proxyConfig);
            this.commandStreamedReplyIngestFn = (reply) => {
                WebWorkerMeshHost.logger.trace('Sending command streamed reply to main thread: ' + (reply === null || reply === void 0 ? void 0 : reply.type));
                WebWorkerMeshHost.logger.trace(reply);
                try {
                    this.worker.postMessage(reply);
                }
                catch (e) {
                    WebWorkerMeshHost.logger.warning('Could not send command streamed reply to main thread:');
                    WebWorkerMeshHost.logger.warning(reply);
                    WebWorkerMeshHost.logger.warning('Error was: ' + e);
                }
            };
            this.peerSourceRequestIngestFn = (req) => {
                WebWorkerMeshHost.logger.trace('Sending peer source request to main thread: ' + (req === null || req === void 0 ? void 0 : req.type));
                WebWorkerMeshHost.logger.trace(req);
                try {
                    this.worker.postMessage(req);
                }
                catch (e) {
                    WebWorkerMeshHost.logger.warning('Could not send peer source request to main thread:');
                    WebWorkerMeshHost.logger.warning(req);
                    WebWorkerMeshHost.logger.warning('Error was: ' + e);
                }
            };
            this.host = new MeshHost(this.mesh, this.commandStreamedReplyIngestFn, this.peerSourceRequestIngestFn);
            this.worker.onerror = (ev) => {
                console.log('ERROR RECEIVING PROXYIED MESSAGE FROM MAIN THREAD:');
                console.log(ev);
            };
            this.worker.onmessage = (msg) => {
                var _a;
                const data = msg === null || msg === void 0 ? void 0 : msg.data;
                WebWorkerMeshHost.logger.debug('Received from main: ' + (data === null || data === void 0 ? void 0 : data.type));
                WebWorkerMeshHost.logger.debug(msg);
                if (data.type === 'mesh-worker-ready-query') {
                    this.worker.postMessage({ type: 'mesh-worker-ready' });
                }
                if (MeshHost.isCommand(data)) {
                    WebWorkerMeshHost.logger.debug('Executing mesh command');
                    this.host.execute(data);
                }
                if (LinkupManagerHost.isCommand(data)) {
                    WebWorkerMeshHost.logger.debug('Executing linkup command');
                    (_a = this.mesh.network.linkupManagerHost) === null || _a === void 0 ? void 0 : _a.execute(data);
                }
                if (WebRTCConnectionsHost.isEvent(data)) {
                    WebWorkerMeshHost.logger.debug('Ingesting webrtc event');
                    if (this.mesh.network.webRTCConnEventIngestFn !== undefined) {
                        this.mesh.network.webRTCConnEventIngestFn(data);
                        WebWorkerMeshHost.logger.debug('Ingested ok');
                    }
                }
            };
            this.worker.postMessage({ type: 'mesh-worker-ready' });
        }
    }
    WebWorkerMeshHost.logger = new Logger();

    //import WebWorker from 'worker-loader!./mesh.worker';
    class WebWorkerMeshProxy {
        constructor(worker) {
            this.hostReady = false;
            this.ready = new Promise((resolve, reject) => {
                this.readyCallback = resolve;
                this.timeoutCallback = reject;
                if (this.hostReady) {
                    resolve();
                }
            });
            this.meshCommandFwdFn = (cmd) => {
                WebWorkerMeshProxy.meshLogger.trace('Sending mesh command to worker: ' + (cmd === null || cmd === void 0 ? void 0 : cmd.type), cmd);
                try {
                    this.worker.postMessage(cmd);
                }
                catch (e) {
                    WebWorkerMeshProxy.meshLogger.warning('Could not send mesh command to worker:', cmd);
                    WebWorkerMeshProxy.meshLogger.warning(cmd);
                    WebWorkerMeshProxy.meshLogger.warning('Error was: ', e);
                    throw e;
                }
            };
            this.linkupCommandFwdFn = (cmd) => {
                WebWorkerMeshProxy.linkupLogger.trace('Sending linkup command to worker: ' + (cmd === null || cmd === void 0 ? void 0 : cmd.type), cmd);
                try {
                    this.worker.postMessage(cmd);
                }
                catch (e) {
                    WebWorkerMeshProxy.linkupLogger.warning('Could not send linkup command to worker:', cmd);
                    WebWorkerMeshProxy.linkupLogger.warning(cmd);
                    WebWorkerMeshProxy.linkupLogger.warning('Error was: ', e);
                    throw e;
                }
            };
            this.webRTCConnEventIngestFn = (ev) => {
                WebWorkerMeshProxy.webRTCLogger.trace('Sending webrtc event to worker: ' + (ev === null || ev === void 0 ? void 0 : ev.type), ev);
                try {
                    this.worker.postMessage(ev);
                }
                catch (e) {
                    WebWorkerMeshProxy.webRTCLogger.warning('Could not send webrtc event to worker:', ev);
                    WebWorkerMeshProxy.webRTCLogger.warning('Error was: ', e);
                    throw e;
                }
            };
            this.worker = worker;
            this.worker.onerror = (ev) => {
                console.log('ERROR RECEIVING PROXYIED MESSAGE FROM WEB WORKER:');
                console.log(ev);
            };
            this.worker.onmessage = (ev) => {
                var _a, _b;
                let data = ev.data;
                WebWorkerMeshProxy.meshLogger.debug('Receiving from worker: ' + (data === null || data === void 0 ? void 0 : data.type), ev);
                if (ev.data.type === 'mesh-worker-ready') {
                    if (!this.hostReady) {
                        this.hostReady = true;
                        if (this.readyCallback !== undefined) {
                            this.readyCallback();
                        }
                    }
                }
                if (LinkupManagerHost.isEvent(data)) {
                    WebWorkerMeshProxy.linkupLogger.debug('Ingesting linkup event:', data);
                    (_a = this.proxy.linkup) === null || _a === void 0 ? void 0 : _a.linkupManagerEventIngestFn(data);
                }
                if (WebRTCConnectionsHost.isCommand(data)) {
                    WebWorkerMeshProxy.webRTCLogger.debug('Executing webrtc command:', data);
                    if (this.proxy.webRTCConnsHost === undefined) {
                        WebWorkerMeshProxy.webRTCLogger.warning('webRTCConnsHost is undefined, message will be lost (!)');
                    }
                    try {
                        (_b = this.proxy.webRTCConnsHost) === null || _b === void 0 ? void 0 : _b.execute(data);
                    }
                    catch (e) {
                        WebWorkerMeshProxy.webRTCLogger.error('Error trying to execute webrtc command:', e);
                    }
                }
                if (MeshHost.isStreamedReply(data)) {
                    WebWorkerMeshProxy.meshLogger.debug('Ingesting streamed reply:', data);
                    this.proxy.commandStreamedReplyIngestFn(data);
                }
                if (MeshHost.isPeerSourceRequest(data)) {
                    WebWorkerMeshProxy.meshLogger.debug('Ingesting peer source request:', data);
                    this.proxy.peerSourceRequestIngestFn(data);
                }
            };
            this.proxy = new MeshProxy(this.meshCommandFwdFn, this.linkupCommandFwdFn, this.webRTCConnEventIngestFn);
            this.worker.postMessage({ type: 'mesh-worker-ready-query' });
        }
        getMesh() {
            return this.proxy;
        }
    }
    WebWorkerMeshProxy.meshLogger = new Logger(WebWorkerMeshProxy.name);
    WebWorkerMeshProxy.linkupLogger = new Logger(WebWorkerMeshProxy.name);
    WebWorkerMeshProxy.webRTCLogger = new Logger(WebWorkerMeshProxy.name);

    class SharedNamespace {
        constructor(spaceId, localPeer, config, resources) {
            this.spaceId = spaceId;
            this.localPeer = localPeer;
            if ((resources === null || resources === void 0 ? void 0 : resources.store) !== undefined) {
                this.store = resources.store;
            }
            else {
                this.store = new Store(new IdbBackend('group-shared-space-' + spaceId + '-' + localPeer.identityHash));
            }
            if ((resources === null || resources === void 0 ? void 0 : resources.mesh) !== undefined) {
                this.mesh = resources.mesh;
            }
            else {
                this.mesh = new Mesh();
            }
            if ((config === null || config === void 0 ? void 0 : config.syncDependencies) !== undefined) {
                this.syncDependencies = config.syncDependencies;
            }
            else {
                this.syncDependencies = true;
            }
            if ((config === null || config === void 0 ? void 0 : config.peerGroupAgentConfig) !== undefined) {
                this.peerGroupAgentConfig = config === null || config === void 0 ? void 0 : config.peerGroupAgentConfig;
            }
            else {
                this.peerGroupAgentConfig = {}; // empty config (defaults)
            }
            this.objects = new Map();
            this.definedKeys = new Map();
            this.started = false;
        }
        connect() {
            if (this.peerSource === undefined) {
                throw new Error("Cannot connect before setting a peerSource");
            }
            this.mesh.joinPeerGroup({ id: this.spaceId, localPeer: this.localPeer, peerSource: this.peerSource }, this.peerGroupAgentConfig);
        }
        setPeerSource(peerSource) {
            if (this.started) {
                throw new Error("Can't change peer source after space has started.");
            }
            this.peerSource = peerSource;
        }
        getPeerSource() {
            return this.peerSource;
        }
        getMesh() {
            return this.mesh;
        }
        getStore() {
            return this.store;
        }
        async attach(key, mut) {
            mut.setId(HashedObject.generateIdForPath(this.spaceId, key));
            this.definedKeys.set(key, mut);
            await this.store.save(mut);
            this.addObject(mut);
        }
        get(key) {
            return this.definedKeys.get(key);
        }
        addObject(mut) {
            let hash = mut.hash();
            if (!this.objects.has(hash)) {
                this.objects.set(mut.hash(), mut);
                this.mesh.syncObjectWithPeerGroup(this.spaceId, mut, exports.SyncMode.recursive);
            }
        }
    }

    class SpaceInfo extends HashedObject {
        constructor(entryPoint) {
            super();
            if (entryPoint !== undefined) {
                this.entryPoint = entryPoint;
                this.hashSuffixes = SpaceInfo.createHashSuffixes(this.entryPoint);
            }
        }
        getClassName() {
            return SpaceInfo.className;
        }
        init() {
        }
        async validate(references) {
            if (this.entryPoint === undefined || this.hashSuffixes === undefined) {
                return false;
            }
            const hashSuffixes = SpaceInfo.createHashSuffixes(this.entryPoint);
            if (this.hashSuffixes.length !== hashSuffixes.length) {
                return false;
            }
            for (let i = 0; i < hashSuffixes.length; i++) {
                if (this.hashSuffixes[i] !== hashSuffixes[i]) {
                    return false;
                }
            }
            return true;
        }
        static createHashSuffixes(entryPoint) {
            const hash = entryPoint.hash();
            const hashSuffixes = new Array();
            for (const bitLength of SpaceInfo.bitLengths) {
                hashSuffixes.push(new HashedLiteral(ObjectBroadcastAgent.hexSuffixFromHash(hash, bitLength)));
            }
            return hashSuffixes;
        }
    }
    SpaceInfo.className = 'hhs/v0/SpaceInfo';
    SpaceInfo.bitLengths = [11 * 4, 12 * 5, 12 * 4, 12 * 3];
    HashedObject.registerClass(SpaceInfo.className, SpaceInfo);

    class Space {
        constructor(init, resources) {
            this.resources = resources;
            if (init.entryPoint !== undefined) {
                this.entryPoint = this.saveSpaceInfo(init.entryPoint).then(() => {
                    return Promise.resolve(init.entryPoint);
                });
            }
            else if (init.hash !== undefined) {
                this.entryPoint = this.resources.store.load(init.hash).then((obj) => {
                    if (obj !== undefined) {
                        return obj;
                    }
                    else {
                        if (resources.config.peersForDiscovery === undefined) {
                            throw new Error('Trying to open space for missing object ' + init.hash + ', but config.peersForDiscovery is undefined.');
                        }
                        const linkupServers = resources.config.linkupServers;
                        const discoveryEndpoint = resources.config.peersForDiscovery[0].endpoint;
                        const discovery = this.resources.mesh.findObjectByHash(init.hash, linkupServers, discoveryEndpoint);
                        return this.processDiscoveryReply(discovery);
                    }
                });
            }
            else if (init.wordCode !== undefined) {
                let wordCoders;
                if (init.wordCodeLang !== undefined) {
                    if (WordCode.lang.has(init.wordCodeLang)) {
                        wordCoders = [WordCode.lang.get(init.wordCodeLang)];
                    }
                    else {
                        throw new Error('Unknown language "' + init.wordCodeLang + '" received for decoding wordCode ' + init.wordCode.join('-') + '.');
                    }
                }
                else {
                    wordCoders = WordCode.all;
                }
                let suffix;
                let lastError;
                for (const wordCoder of wordCoders) {
                    try {
                        suffix = wordCoder.decode(init.wordCode);
                        break;
                    }
                    catch (e) {
                        lastError = e;
                    }
                }
                if (suffix === undefined) {
                    throw new Error('Could not decode wordCode ' + init.wordCode.join(' ') + ', last error: ' + lastError);
                }
                this.entryPoint = this.lookupOrDiscover(suffix);
            }
            else {
                throw new Error('Created new space, but no initialization was provided (entry object nor hash no word code).');
            }
        }
        static fromEntryPoint(obj, resources) {
            return new Space({ entryPoint: obj }, resources);
        }
        static fromHash(hash, resources) {
            return new Space({ hash: hash }, resources);
        }
        static fromWordCode(words, resources) {
            return new Space({ wordCode: words }, resources);
        }
        async lookupOrDiscover(suffix) {
            const results = await this.resources.store.loadByReference('hashSuffixes', new HashedLiteral(suffix).hash());
            for (const obj of results.objects) {
                if (obj instanceof SpaceInfo && obj.getClassName() === SpaceInfo.className) {
                    if (ObjectBroadcastAgent.hexSuffixFromHash(obj.getLastHash(), suffix.length * 4)) {
                        return Promise.resolve(obj.entryPoint);
                    }
                }
            }
            if (this.resources.config.peersForDiscovery === undefined) {
                throw new Error('Trying to open space for missing object with suffix ' + suffix + ', but config.peersForDiscovery is undefined.');
            }
            const linkupServers = this.resources.config.linkupServers;
            const discoveryEndpoint = this.resources.config.peersForDiscovery[0].endpoint;
            const discovery = this.resources.mesh.findObjectByHashSuffix(suffix, linkupServers, discoveryEndpoint);
            return this.processDiscoveryReply(discovery);
        }
        processDiscoveryReply(discoveryStream) {
            this.entryPoint.then((entryPoint) => { this.saveSpaceInfo(entryPoint); });
            return new Promise((resolve, reject) => {
                discoveryStream.next(30000).then((reply) => {
                    resolve(reply.object);
                }).catch((reason) => {
                    reject(reason);
                });
            });
        }
        async saveSpaceInfo(entryPoint) {
            const spaceInfo = new SpaceInfo(entryPoint);
            await this.resources.store.save(spaceInfo);
        }
        async getEntryPoint() {
            return this.entryPoint;
        }
        async getHash() {
            let entry = await this.entryPoint;
            return entry.hash();
        }
        async getWordCoding(words = 3, lang = 'en') {
            return Space.getWordCodingFor(await this.entryPoint, words, lang);
        }
        startBroadcast() {
            if (this.resources.config.peersForDiscovery === undefined) {
                throw new Error('Trying to start space broadcast but config.peersForDiscovery is undefined.');
            }
            const linkupServers = this.resources.config.linkupServers;
            const discoveryEndpoint = this.resources.config.peersForDiscovery[0].endpoint;
            this.entryPoint.then((ep) => {
                this.resources.mesh.startObjectBroadcast(ep, linkupServers, [discoveryEndpoint]);
            });
        }
        stopBroadcast() {
            this.entryPoint.then((ep) => {
                this.resources.mesh.stopObjectBroadcast(ep.hash());
            });
        }
        getResources() {
            return this.resources;
        }
        static getWordCodingFor(entryPoint, words = 3, lang = 'en') {
            const hash = entryPoint.hash();
            return Space.getWordCodingForHash(hash, words, lang);
        }
        static getWordCodingForHash(hash, words = 3, lang = 'en') {
            let coder = WordCode.lang.get(lang);
            if (coder === undefined) {
                throw new Error('Could not find word coder for language ' + lang + '.');
            }
            const nibbles = coder.bitsPerWord * words / 4;
            const suffix = Hashing.toHex(hash).slice(-nibbles);
            return coder.encode(suffix);
        }
    }

    class Resources {
        constructor(init) {
            var _a;
            const linkupServers = ((_a = init === null || init === void 0 ? void 0 : init.config) === null || _a === void 0 ? void 0 : _a.linkupServers) !== undefined && init.config.linkupServers.length > 0 ?
                init.config.linkupServers
                :
                    [LinkupManager.defaultLinkupServer];
            this.config = {
                linkupServers: linkupServers,
                id: init.config.id
            };
            if (init.store === undefined) {
                this.store = new Store(new MemoryBackend('auto-generated store ' + new BrowserRNG().randomHexString(64)));
            }
            else {
                this.store = init === null || init === void 0 ? void 0 : init.store;
            }
            if (init.mesh === undefined) {
                this.mesh = new Mesh();
            }
            else {
                this.mesh = init.mesh;
            }
            if (init.config.peersForDiscovery !== undefined &&
                init.config.endpointParserForDiscovery !== undefined) {
                this.config.peersForDiscovery = init.config.peersForDiscovery;
                this.config.endpointParserForDiscovery = init.config.endpointParserForDiscovery;
            }
            else {
                this.config.peersForDiscovery = [(new IdentityPeer(linkupServers[0], this.config.id.hash(), this.config.id)).asPeerIfReady()];
                this.config.endpointParserForDiscovery = IdentityPeer.getEndpointParser(this.store);
            }
            this.aliasing = new Map();
        }
        getId() {
            if (this.config.id === undefined) {
                throw new Error('A default identity was requested, but none was provided in the resources object.');
            }
            return this.config.id;
        }
        getPeersForDiscovery() {
            if (this.config.peersForDiscovery === undefined) {
                throw new Error('A list of peers for discovery was requested, but none was provided in the resources object.');
            }
            return this.config.peersForDiscovery;
        }
        getEndointParserForDiscovery() {
            if (this.config.endpointParserForDiscovery === undefined) {
                throw new Error('An endpoint parser for discovery was requested, but none was provided in the resources object.');
            }
            return this.config.endpointParserForDiscovery;
        }
        static async create(init) {
            var _a, _b, _c, _d;
            let localId;
            if (((_a = init === null || init === void 0 ? void 0 : init.config) === null || _a === void 0 ? void 0 : _a.id) !== undefined) {
                localId = init === null || init === void 0 ? void 0 : init.config.id;
            }
            else {
                let key = await RSAKeyPair.generate(1024);
                localId = Identity.fromKeyPair({ name: 'auto-generated id ' + new BrowserRNG().randomHexString(64) }, key);
            }
            const config = {
                linkupServers: (_b = init === null || init === void 0 ? void 0 : init.config) === null || _b === void 0 ? void 0 : _b.linkupServers,
                id: localId,
                peersForDiscovery: (_c = init === null || init === void 0 ? void 0 : init.config) === null || _c === void 0 ? void 0 : _c.peersForDiscovery,
                endpointParserForDiscovery: (_d = init === null || init === void 0 ? void 0 : init.config) === null || _d === void 0 ? void 0 : _d.endpointParserForDiscovery
            };
            return new Resources({ store: init === null || init === void 0 ? void 0 : init.store, mesh: init === null || init === void 0 ? void 0 : init.mesh, config: config, aliasing: init === null || init === void 0 ? void 0 : init.aliasing });
        }
    }

    exports.AbstractCapabilitySet = AbstractCapabilitySet;
    exports.AbstractFeatureSet = AbstractFeatureSet;
    exports.AgentPod = AgentPod;
    exports.BFSHistoryWalk = BFSHistoryWalk;
    exports.CascadedInvalidateOp = CascadedInvalidateOp;
    exports.ChaCha20Impl = ChaCha20Universal;
    exports.ConstantPeerSource = ConstantPeerSource;
    exports.Context = Context;
    exports.DisableFeatureAfterOp = DisableFeatureAfterOp;
    exports.EmptyPeerSource = EmptyPeerSource;
    exports.EnableFeatureOp = EnableFeatureOp;
    exports.FullHistoryWalk = FullHistoryWalk;
    exports.GrantCapabilityOp = GrantCapabilityOp;
    exports.HMACImpl = HMAC;
    exports.HashBasedPeerSource = HashBasedPeerSource;
    exports.HashReference = HashReference;
    exports.HashedLiteral = HashedLiteral;
    exports.HashedObject = HashedObject;
    exports.HashedSet = HashedSet;
    exports.Hashing = Hashing;
    exports.HeaderBasedState = HeaderBasedState;
    exports.HeaderBasedSyncAgent = HeaderBasedSyncAgent;
    exports.HistoryDelta = HistoryDelta;
    exports.HistoryProvider = HistoryProvider;
    exports.HistorySynchronizer = HistorySynchronizer;
    exports.HistoryWalk = HistoryWalk;
    exports.IdbBackend = IdbBackend;
    exports.Identity = Identity;
    exports.IdentityPeer = IdentityPeer;
    exports.InvalidateAfterOp = InvalidateAfterOp;
    exports.JoinPeerSources = JoinPeerSources;
    exports.LinkupAddress = LinkupAddress;
    exports.LinkupManager = LinkupManager;
    exports.LinkupManagerHost = LinkupManagerHost;
    exports.LinkupManagerProxy = LinkupManagerProxy;
    exports.LiteralUtils = LiteralUtils;
    exports.MemoryBackend = MemoryBackend;
    exports.Mesh = Mesh;
    exports.MeshHost = MeshHost;
    exports.MeshProxy = MeshProxy;
    exports.MutableObject = MutableObject;
    exports.MutableReference = MutableReference;
    exports.MutableSet = MutableSet;
    exports.MutationOp = MutationOp;
    exports.Namespace = Namespace;
    exports.NetworkAgent = NetworkAgent;
    exports.ObjectBroadcastAgent = ObjectBroadcastAgent;
    exports.ObjectDiscoveryAgent = ObjectDiscoveryAgent;
    exports.ObjectDiscoveryPeerSource = ObjectDiscoveryPeerSource;
    exports.OpHeader = OpHeader;
    exports.PeerGroup = PeerGroup;
    exports.PeerGroupAgent = PeerGroupAgent;
    exports.PeerNode = PeerNode;
    exports.PeeringAgentBase = PeeringAgentBase;
    exports.ProviderLimits = ProviderLimits;
    exports.RMDImpl = JSHashesRMD;
    exports.RNGImpl = BrowserRNG;
    exports.RSADefaults = RSADefaults;
    exports.RSAKeyPair = RSAKeyPair;
    exports.RSAPublicKey = RSAPublicKey;
    exports.Resources = Resources;
    exports.ReversibleSet = ReversibleSet;
    exports.RevokeCapabilityAfterOp = RevokeCapabilityAfterOp;
    exports.SHAImpl = JSHashesSHA;
    exports.SecretBasedPeerSource = SecretBasedPeerSource;
    exports.SecureNetworkAgent = SecureNetworkAgent;
    exports.Serialization = Serialization;
    exports.SharedNamespace = SharedNamespace;
    exports.Shuffle = Shuffle;
    exports.SignallingServerConnection = SignallingServerConnection;
    exports.Space = Space;
    exports.StateGossipAgent = StateGossipAgent;
    exports.Store = Store;
    exports.TerminalOpsState = TerminalOpsState;
    exports.TerminalOpsSyncAgent = TerminalOpsSyncAgent;
    exports.UseCapabilityOp = UseCapabilityOp;
    exports.UseFeatureOp = UseFeatureOp;
    exports.WebCryptoConfig = WebCryptoConfig;
    exports.WebCryptoRSA = WebCryptoRSA;
    exports.WebCryptoRSASigKP = WebCryptoRSASigKP;
    exports.WebRTCConnection = WebRTCConnection;
    exports.WebRTCConnectionProxy = WebRTCConnectionProxy;
    exports.WebRTCConnectionsHost = WebRTCConnectionsHost;
    exports.WebSocketConnection = WebSocketConnection;
    exports.WebSocketListener = WebSocketListener;
    exports.WebWorkerMeshHost = WebWorkerMeshHost;
    exports.WebWorkerMeshProxy = WebWorkerMeshProxy;
    exports.WordCode = WordCode;
    exports.WorkerSafeIdbBackend = WorkerSafeIdbBackend;

    Object.defineProperty(exports, '__esModule', { value: true });

    return exports;

})({});
