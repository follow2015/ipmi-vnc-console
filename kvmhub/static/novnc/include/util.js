

var Util = {};



var addFunc = function (cl, name, func) {
    if (!cl.prototype[name]) {
        Object.defineProperty(cl.prototype, name, { enumerable: false, value: func });
    }
};

addFunc(Array, 'push8', function (num) {
    "use strict";
    this.push(num & 0xFF);
});

addFunc(Array, 'push16', function (num) {
    "use strict";
    this.push((num >> 8) & 0xFF,
              num & 0xFF);
});

addFunc(Array, 'push32', function (num) {
    "use strict";
    this.push((num >> 24) & 0xFF,
              (num >> 16) & 0xFF,
              (num >>  8) & 0xFF,
              num & 0xFF);
});

addFunc(Array, 'map', function (fun /*, thisp*/) {
    "use strict";
    var len = this.length;
    if (typeof fun != "function") {
        throw new TypeError();
    }

    var res = new Array(len);
    var thisp = arguments[1];
    for (var i = 0; i < len; i++) {
        if (i in this) {
            res[i] = fun.call(thisp, this[i], i, this);
        }
    }

    return res;
});

addFunc(Array, 'indexOf', function (elt /*, from*/) {
    "use strict";
    var len = this.length >>> 0;

    var from = Number(arguments[1]) || 0;
    from = (from < 0) ? Math.ceil(from) : Math.floor(from);
    if (from < 0) {
        from += len;
    }

    for (; from < len; from++) {
        if (from in this &&
                this[from] === elt) {
            return from;
        }
    }
    return -1;
});

if (!Object.keys) {
    Object.keys = (function () {
        'use strict';
        var hasOwnProperty = Object.prototype.hasOwnProperty,
            hasDontEnumBug = !({toString: null}).propertyIsEnumerable('toString'),
            dontEnums = [
                'toString',
                'toLocaleString',
                'valueOf',
                'hasOwnProperty',
                'isPrototypeOf',
                'propertyIsEnumerable',
                'constructor'
            ],
            dontEnumsLength = dontEnums.length;

        return function (obj) {
            if (typeof obj !== 'object' && (typeof obj !== 'function' || obj === null)) {
                throw new TypeError('Object.keys called on non-object');
            }

            var result = [], prop, i;

            for (prop in obj) {
                if (hasOwnProperty.call(obj, prop)) {
                    result.push(prop);
                }
            }

            if (hasDontEnumBug) {
                for (i = 0; i < dontEnumsLength; i++) {
                    if (hasOwnProperty.call(obj, dontEnums[i])) {
                        result.push(dontEnums[i]);
                    }
                }
            }
            return result;
        };
    })();
}

addFunc(Function, 'bind', function (oThis) {
    if (typeof this !== "function") {
        throw new TypeError("Function.prototype.bind - " +
                            "what is trying to be bound is not callable");
    }

    var aArgs = Array.prototype.slice.call(arguments, 1),
            fToBind = this,
            fNOP = function () {},
            fBound = function () {
                return fToBind.apply(this instanceof fNOP && oThis ? this
                                                                   : oThis,
                                     aArgs.concat(Array.prototype.slice.call(arguments)));
            };

    fNOP.prototype = this.prototype;
    fBound.prototype = new fNOP();

    return fBound;
});


window.requestAnimFrame = (function () {
    "use strict";
    return  window.requestAnimationFrame       ||
            window.webkitRequestAnimationFrame ||
            window.mozRequestAnimationFrame    ||
            window.oRequestAnimationFrame      ||
            window.msRequestAnimationFrame     ||
            function (callback) {
                window.setTimeout(callback, 1000 / 60);
            };
})();



Util._log_level = 'warn';
Util.init_logging = function (level) {
    "use strict";
    if (typeof level === 'undefined') {
        level = Util._log_level;
    } else {
        Util._log_level = level;
    }
    if (typeof window.console === "undefined") {
        if (typeof window.opera !== "undefined") {
            window.console = {
                'log'  : window.opera.postError,
                'warn' : window.opera.postError,
                'error': window.opera.postError
            };
        } else {
            window.console = {
                'log'  : function (m) {},
                'warn' : function (m) {},
                'error': function (m) {}
            };
        }
    }
    
    Util.Debug = Util.Info = Util.Warn = Util.Error = function (msg) {};
    switch (level) {
        case 'debug':
            Util.Debug = function (msg) { console.log(msg); };
        case 'info':
            Util.Info  = function (msg) { console.log(msg); };
        case 'warn':
            Util.Warn  = function (msg) { console.log(msg); };
        case 'error':
            Util.Error = function (msg) { console.log(msg); };
        case 'none':
            break;
        default:
            throw new Error("invalid logging type '" + level + "'");
    }
};
Util.get_logging = function () {
    return Util._log_level;
};
Util.init_logging();

Util.make_property = function (proto, name, mode, type) {
    "use strict";

    var getter;
    if (type === 'arr') {
        getter = function (idx) {
            if (typeof idx !== 'undefined') {
                return this['_' + name][idx];
            } else {
                return this['_' + name];
            }
        };
    } else {
        getter = function () {
            return this['_' + name];
        };
    }

    var make_setter = function (process_val) {
        if (process_val) {
            return function (val, idx) {
                if (typeof idx !== 'undefined') {
                    this['_' + name][idx] = process_val(val);
                } else {
                    this['_' + name] = process_val(val);
                }
            };
        } else {
            return function (val, idx) {
                if (typeof idx !== 'undefined') {
                    this['_' + name][idx] = val;
                } else {
                    this['_' + name] = val;
                }
            };
        }
    };

    var setter;
    if (type === 'bool') {
        setter = make_setter(function (val) {
            if (!val || (val in {'0': 1, 'no': 1, 'false': 1})) {
                return false;
            } else {
                return true;
            }
        });
    } else if (type === 'int') {
        setter = make_setter(function (val) { return parseInt(val, 10); });
    } else if (type === 'float') {
        setter = make_setter(parseFloat);
    } else if (type === 'str') {
        setter = make_setter(String);
    } else if (type === 'func') {
        setter = make_setter(function (val) {
            if (!val) {
                return function () {};
            } else {
                return val;
            }
        });
    } else if (type === 'arr' || type === 'dom' || type == 'raw') {
        setter = make_setter();
    } else {
        throw new Error('Unknown property type ' + type);  // some sanity checking
    }

    if (typeof proto['get_' + name] === 'undefined') {
        proto['get_' + name] = getter;
    }

    if (typeof proto['set_' + name] === 'undefined') {
        if (mode === 'rw') {
            proto['set_' + name] = setter;
        } else if (mode === 'wo') {
            proto['set_' + name] = function (val, idx) {
                if (typeof this['_' + name] !== 'undefined') {
                    throw new Error(name + " can only be set once");
                }
                setter.call(this, val, idx);
            };
        }
    }

    proto['_raw_set_' + name] = function (val, idx) {
        setter.call(this, val, idx);
    };
};

Util.make_properties = function (constructor, arr) {
    "use strict";
    for (var i = 0; i < arr.length; i++) {
        Util.make_property(constructor.prototype, arr[i][0], arr[i][1], arr[i][2]);
    }
};

Util.set_defaults = function (obj, conf, defaults) {
    var defaults_keys = Object.keys(defaults);
    var conf_keys = Object.keys(conf);
    var keys_obj = {};
    var i;
    for (i = 0; i < defaults_keys.length; i++) { keys_obj[defaults_keys[i]] = 1; }
    for (i = 0; i < conf_keys.length; i++) { keys_obj[conf_keys[i]] = 1; }
    var keys = Object.keys(keys_obj);

    for (i = 0; i < keys.length; i++) {
        var setter = obj['_raw_set_' + keys[i]];
        if (!setter) {
          Util.Warn('Invalid property ' + keys[i]);
          continue;
        }

        if (keys[i] in conf) {
            setter.call(obj, conf[keys[i]]);
        } else {
            setter.call(obj, defaults[keys[i]]);
        }
    }
};

Util.decodeUTF8 = function (utf8string) {
    "use strict";
    return decodeURIComponent(escape(utf8string));
};





Util.get_include_uri = function () {
    return (typeof INCLUDE_URI !== "undefined") ? INCLUDE_URI : "../novnc/include/";
};
Util._loading_scripts = [];
Util._pending_scripts = [];
Util.load_scripts = function (files) {
    "use strict";
    var head = document.getElementsByTagName('head')[0], script,
        ls = Util._loading_scripts, ps = Util._pending_scripts;

    var loadFunc = function (e) {
        while (ls.length > 0 && (ls[0].readyState === 'loaded' ||
                                 ls[0].readyState === 'complete')) {
            var s = ls.shift();
            head.appendChild(s);
        }
        if (!this.readyState ||
            (Util.Engine.presto && this.readyState === 'loaded') ||
            this.readyState === 'complete') {
            if (ps.indexOf(this) >= 0) {
                this.onload = this.onreadystatechange = null;
                ps.splice(ps.indexOf(this), 1);

                if (ps.length === 0 && window.onscriptsload) {
                    window.onscriptsload();
                }
            }
        }
    };

    for (var f = 0; f < files.length; f++) {
        script = document.createElement('script');
        script.type = 'text/javascript';
        script.src = Util.get_include_uri() + files[f];
        script.onload = script.onreadystatechange = loadFunc;
        if (Util.Engine.trident) {
            ls.push(script);
        } else {
            script.async = false;
            head.appendChild(script);
        }
        ps.push(script);
    }
};


Util.getPosition = (function () {
    "use strict";
    function getStyle(obj, styleProp) {
        var y;
        if (obj.currentStyle) {
            y = obj.currentStyle[styleProp];
        } else if (window.getComputedStyle)
            y = window.getComputedStyle(obj, null)[styleProp];
        return y;
    }

    function scrollDist() {
        var myScrollTop = 0, myScrollLeft = 0;
        var html = document.getElementsByTagName('html')[0];

        if (html.scrollTop && document.documentElement.scrollTop) {
            myScrollTop = html.scrollTop;
        } else if (html.scrollTop || document.documentElement.scrollTop) {
            myScrollTop = html.scrollTop + document.documentElement.scrollTop;
        } else if (document.body.scrollTop) {
            myScrollTop = document.body.scrollTop;
        } else {
            myScrollTop = 0;
        }

        if (html.scrollLeft && document.documentElement.scrollLeft) {
            myScrollLeft = html.scrollLeft;
        } else if (html.scrollLeft || document.documentElement.scrollLeft) {
            myScrollLeft = html.scrollLeft + document.documentElement.scrollLeft;
        } else if (document.body.scrollLeft) {
            myScrollLeft = document.body.scrollLeft;
        } else {
            myScrollLeft = 0;
        }

        return [myScrollLeft, myScrollTop];
    }

    return function (obj) {
        var curleft = 0, curtop = 0, scr = obj, fixed = false;
        while ((scr = scr.parentNode) && scr != document.body) {
            curleft -= scr.scrollLeft || 0;
            curtop -= scr.scrollTop || 0;
            if (getStyle(scr, "position") == "fixed") {
                fixed = true;
            }
        }
        if (fixed && !window.opera) {
            var scrDist = scrollDist();
            curleft += scrDist[0];
            curtop += scrDist[1];
        }

        do {
            curleft += obj.offsetLeft;
            curtop += obj.offsetTop;
        } while ((obj = obj.offsetParent));

        return {'x': curleft, 'y': curtop};
};
})();


Util.getEventPosition = function (e, obj, scale) {
    "use strict";
    var evt, docX, docY, pos;
    evt = (e ? e : window.event);
    evt = (evt.changedTouches ? evt.changedTouches[0] : evt.touches ? evt.touches[0] : evt);
    if (evt.pageX || evt.pageY) {
        docX = evt.pageX;
        docY = evt.pageY;
    } else if (evt.clientX || evt.clientY) {
        docX = evt.clientX + document.body.scrollLeft +
            document.documentElement.scrollLeft;
        docY = evt.clientY + document.body.scrollTop +
            document.documentElement.scrollTop;
    }
    pos = Util.getPosition(obj);
    if (typeof scale === "undefined") {
        scale = 1;
    }
    var realx = docX - pos.x;
    var realy = docY - pos.y;
    var x = Math.max(Math.min(realx, obj.width - 1), 0);
    var y = Math.max(Math.min(realy, obj.height - 1), 0);
    return {'x': x / scale, 'y': y / scale, 'realx': realx / scale, 'realy': realy / scale};
};


Util.addEvent = function (obj, evType, fn) {
    "use strict";
    if (obj.attachEvent) {
        var r = obj.attachEvent("on" + evType, fn);
        return r;
    } else if (obj.addEventListener) {
        obj.addEventListener(evType, fn, false);
        return true;
    } else {
        throw new Error("Handler could not be attached");
    }
};

Util.removeEvent = function (obj, evType, fn) {
    "use strict";
    if (obj.detachEvent) {
        var r = obj.detachEvent("on" + evType, fn);
        return r;
    } else if (obj.removeEventListener) {
        obj.removeEventListener(evType, fn, false);
        return true;
    } else {
        throw new Error("Handler could not be removed");
    }
};

Util.stopEvent = function (e) {
    "use strict";
    if (e.stopPropagation) { e.stopPropagation(); }
    else                   { e.cancelBubble = true; }

    if (e.preventDefault)  { e.preventDefault(); }
    else                   { e.returnValue = false; }
};

Util._cursor_uris_supported = null;

Util.browserSupportsCursorURIs = function () {
    if (Util._cursor_uris_supported === null) {
        try {
            var target = document.createElement('canvas');
            target.style.cursor = 'url("data:image/x-icon;base64,AAACAAEACAgAAAIAAgA4AQAAFgAAACgAAAAIAAAAEAAAAAEAIAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAD/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////AAAAAAAAAAAAAAAAAAAAAA==") 2 2, default';

            if (target.style.cursor) {
                Util.Info("Data URI scheme cursor supported");
                Util._cursor_uris_supported = true;
            } else {
                Util.Warn("Data URI scheme cursor not supported");
                Util._cursor_uris_supported = false;
            }
        } catch (exc) {
            Util.Error("Data URI scheme cursor test exception: " + exc);
            Util._cursor_uris_supported = false;
        }
    }

    return Util._cursor_uris_supported;
};

Util.Features = {xpath: !!(document.evaluate), air: !!(window.runtime), query: !!(document.querySelector)};

(function () {
    "use strict";
    var detectPresto = function () {
        return !!window.opera;
    };

    var detectTrident = function () {
        if (!window.ActiveXObject) {
            return false;
        } else {
            if (window.XMLHttpRequest) {
                return (document.querySelectorAll) ? 6 : 5;
            } else {
                return 4;
            }
        }
    };

    var detectInitialWebkit = function () {
        try {
            if (navigator.taintEnabled) {
                return false;
            } else {
                if (Util.Features.xpath) {
                    return (Util.Features.query) ? 525 : 420;
                } else {
                    return 419;
                }
            }
        } catch (e) {
            return false;
        }
    };

    var detectActualWebkit = function (initial_ver) {
        var re = /WebKit\/([0-9\.]*) /;
        var str_ver = (navigator.userAgent.match(re) || ['', initial_ver])[1];
        return parseFloat(str_ver, 10);
    };

    var detectGecko = function () {
        if (!document.getBoxObjectFor && window.mozInnerScreenX == null) {
            return false;
        } else {
            return (document.getElementsByClassName) ? 19 : 18;
        }
    };

    var detectIE = function () {
        var ua = window.navigator.userAgent;

        var msie = ua.indexOf('MSIE ');
        if (msie > 0) {
            return parseInt(ua.substring(msie + 5, ua.indexOf('.', msie)), 10);
        }

        var trident = ua.indexOf('Trident/');
        if (trident > 0) {
            var rv = ua.indexOf('rv:');
            return parseInt(ua.substring(rv + 3, ua.indexOf('.', rv)), 10);
        }

        var edge = ua.indexOf('Edge/');
        if (edge > 0) {
           return parseInt(ua.substring(edge + 5, ua.indexOf('.', edge)), 10);
        }
        return false;
    };

    Util.Engine = {
        'presto': detectPresto(),
        'trident': detectTrident(),
        'webkit': detectInitialWebkit(),
        'gecko': detectGecko(),
        'IE': detectIE(),
    };

    if (Util.Engine.webkit) {
        Util.Engine.webkit = detectActualWebkit(Util.Engine.webkit);
    }
})();

Util.Flash = (function () {
    "use strict";
    var v, version;
    try {
        v = navigator.plugins['Shockwave Flash'].description;
    } catch (err1) {
        try {
            v = new ActiveXObject('ShockwaveFlash.ShockwaveFlash').GetVariable('$version');
        } catch (err2) {
            v = '0 r0';
        }
    }
    version = v.match(/\d+/g);
    return {version: parseInt(version[0] || 0 + '.' + version[1], 10) || 0, build: parseInt(version[2], 10) || 0};
}());

window.performance = window.performance || {};
performance.now = (function() {
  return performance.now       ||
         performance.mozNow    ||
         performance.msNow     ||
         performance.oNow      ||
         performance.webkitNow ||
         function() { return new Date().getTime(); };
})();
