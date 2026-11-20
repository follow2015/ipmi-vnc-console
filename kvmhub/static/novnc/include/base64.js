


var Base64 = {
    toBase64Table : 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='.split(''),
    base64Pad     : '=',

    encode: function (data) {
        "use strict";
        var result = '';
        var toBase64Table = Base64.toBase64Table;
        var length = data.length;
        var lengthpad = (length % 3);

        for (var i = 0; i < (length - 2); i += 3) {
            result += toBase64Table[data[i] >> 2];
            result += toBase64Table[((data[i] & 0x03) << 4) + (data[i + 1] >> 4)];
            result += toBase64Table[((data[i + 1] & 0x0f) << 2) + (data[i + 2] >> 6)];
            result += toBase64Table[data[i + 2] & 0x3f];
        }

        var j = 0;
        if (lengthpad === 2) {
            j = length - lengthpad;
            result += toBase64Table[data[j] >> 2];
            result += toBase64Table[((data[j] & 0x03) << 4) + (data[j + 1] >> 4)];
            result += toBase64Table[(data[j + 1] & 0x0f) << 2];
            result += toBase64Table[64];
        } else if (lengthpad === 1) {
            j = length - lengthpad;
            result += toBase64Table[data[j] >> 2];
            result += toBase64Table[(data[j] & 0x03) << 4];
            result += toBase64Table[64];
            result += toBase64Table[64];
        }

        return result;
    },

    toBinaryTable : [
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,-1,
        -1,-1,-1,-1, -1,-1,-1,-1, -1,-1,-1,62, -1,-1,-1,63,
        52,53,54,55, 56,57,58,59, 60,61,-1,-1, -1, 0,-1,-1,
        -1, 0, 1, 2,  3, 4, 5, 6,  7, 8, 9,10, 11,12,13,14,
        15,16,17,18, 19,20,21,22, 23,24,25,-1, -1,-1,-1,-1,
        -1,26,27,28, 29,30,31,32, 33,34,35,36, 37,38,39,40,
        41,42,43,44, 45,46,47,48, 49,50,51,-1, -1,-1,-1,-1
    ],

    decode: function (data, offset) {
        "use strict";
        offset = typeof(offset) !== 'undefined' ? offset : 0;
        var toBinaryTable = Base64.toBinaryTable;
        var base64Pad = Base64.base64Pad;
        var result, result_length;
        var leftbits = 0; // number of bits decoded, but yet to be appended
        var leftdata = 0; // bits decoded, but yet to be appended
        var data_length = data.indexOf('=') - offset;

        if (data_length < 0) { data_length = data.length - offset; }

        result_length = (data_length >> 2) * 3 + Math.floor((data_length % 4) / 1.5);
        result = new Array(result_length);

        for (var idx = 0, i = offset; i < data.length; i++) {
            var c = toBinaryTable[data.charCodeAt(i) & 0x7f];
            var padding = (data.charAt(i) === base64Pad);
            if (c === -1) {
                console.error("Illegal character code " + data.charCodeAt(i) + " at position " + i);
                continue;
            }
          
            leftdata = (leftdata << 6) | c;
            leftbits += 6;

            if (leftbits >= 8) {
                leftbits -= 8;
                if (!padding) {
                    result[idx++] = (leftdata >> leftbits) & 0xff;
                }
                leftdata &= (1 << leftbits) - 1;
            }
        }

        if (leftbits) {
            err = new Error('Corrupted base64 string');
            err.name = 'Base64-Error';
            throw err;
        }

        return result;
    }
}; /* End of Base64 namespace */
