var kbdUtil = (function() {
    "use strict";

    function substituteCodepoint(cp) {
        var substitutions = {
            0x218 : 0x15e,
            0x219 : 0x15f,
            0x21a : 0x162,
            0x21b : 0x163
        };

        var sub = substitutions[cp];
        return sub ? sub : cp;
    }

    function isMac() {
        return navigator && !!(/mac/i).exec(navigator.platform);
    }
    function isWindows() {
        return navigator && !!(/win/i).exec(navigator.platform);
    }
    function isLinux() {
        return navigator && !!(/linux/i).exec(navigator.platform);
    }

    function hasShortcutModifier(charModifier, currentModifiers) {
        var mods = {};
        for (var key in currentModifiers) {
            if (parseInt(key) !== XK_Shift_L) {
                mods[key] = currentModifiers[key];
            }
        }

        var sum = 0;
        for (var k in currentModifiers) {
            if (mods[k]) {
                ++sum;
            }
        }
        if (hasCharModifier(charModifier, mods)) {
            return sum > charModifier.length;
        }
        else {
            return sum > 0;
        }
    }

    function hasCharModifier(charModifier, currentModifiers) {
        if (charModifier.length === 0) { return false; }

        for (var i = 0; i < charModifier.length; ++i) {
            if (!currentModifiers[charModifier[i]]) {
                return false;
            }
        }
        return true;
    }

    function ModifierSync(charModifier) {
        if (!charModifier) {
            if (isMac()) {
                charModifier = [XK_Alt_L];
            }
            else if (isWindows()) {
                charModifier = [XK_Alt_L, XK_Control_L];
            }
            else if (isLinux()) {
                charModifier = [XK_ISO_Level3_Shift];
            }
            else {
                charModifier = [];
            }
        }

        var state = {};
        state[XK_Control_L] = false;
        state[XK_Alt_L] = false;
        state[XK_ISO_Level3_Shift] = false;
        state[XK_Shift_L] = false;
        state[XK_Meta_L] = false;

        function sync(evt, keysym) {
            var result = [];
            function syncKey(keysym) {
                return {keysym: keysyms.lookup(keysym), type: state[keysym] ? 'keydown' : 'keyup'};
            }

            if (evt.ctrlKey !== undefined &&
                evt.ctrlKey !== state[XK_Control_L] && keysym !== XK_Control_L) {
                state[XK_Control_L] = evt.ctrlKey;
                result.push(syncKey(XK_Control_L));
            }
            if (evt.altKey !== undefined &&
                evt.altKey !== state[XK_Alt_L] && keysym !== XK_Alt_L) {
                state[XK_Alt_L] = evt.altKey;
                result.push(syncKey(XK_Alt_L));
            }
            if (evt.altGraphKey !== undefined &&
                evt.altGraphKey !== state[XK_ISO_Level3_Shift] && keysym !== XK_ISO_Level3_Shift) {
                state[XK_ISO_Level3_Shift] = evt.altGraphKey;
                result.push(syncKey(XK_ISO_Level3_Shift));
            }
            if (evt.shiftKey !== undefined &&
                evt.shiftKey !== state[XK_Shift_L] && keysym !== XK_Shift_L) {
                state[XK_Shift_L] = evt.shiftKey;
                result.push(syncKey(XK_Shift_L));
            }
            if (evt.metaKey !== undefined &&
                evt.metaKey !== state[XK_Meta_L] && keysym !== XK_Meta_L) {
                state[XK_Meta_L] = evt.metaKey;
                result.push(syncKey(XK_Meta_L));
            }
            return result;
        }
        function syncKeyEvent(evt, down) {
            var obj = getKeysym(evt);
            var keysym = obj ? obj.keysym : null;

            if (keysym !== null && state[keysym] !== undefined) {
                state[keysym] = down;
            }
            return sync(evt, keysym);
        }

        return {
            keydown: function(evt) { return syncKeyEvent(evt, true);},
            keyup: function(evt) { return syncKeyEvent(evt, false);},
            syncAny: function(evt) { return sync(evt);},

            hasShortcutModifier: function() { return hasShortcutModifier(charModifier, state); },
            activeCharModifier: function() { return hasCharModifier(charModifier, state) ? charModifier : null; }
        };
    }

    function getKey(evt){
        if ('keyCode' in evt && 'key' in evt) {
            return evt.key + ':' + evt.keyCode;
        }
        else if ('keyCode' in evt) {
            return evt.keyCode;
        }
        else {
            return evt.key;
        }
    }

    function getKeysym(evt){
        var codepoint;
        if (evt.char && evt.char.length === 1) {
            codepoint = evt.char.charCodeAt();
        }
        else if (evt.charCode) {
            codepoint = evt.charCode;
        }
        else if (evt.keyCode && evt.type === 'keypress') {
            codepoint = evt.keyCode;
        }
        if (codepoint) {
            var res = keysyms.fromUnicode(substituteCodepoint(codepoint));
            if (res) {
                return res;
            }
        }
        if (evt.keyCode) {
            return keysyms.lookup(keysymFromKeyCode(evt.keyCode, evt.shiftKey));
        }
        if (evt.which) {
            return keysyms.lookup(keysymFromKeyCode(evt.which, evt.shiftKey));
        }
        return null;
    }

    function keysymFromKeyCode(keycode, shiftPressed) {
        if (typeof(keycode) !== 'number') {
            return null;
        }
        if (keycode >= 0x30 && keycode <= 0x39) {
            return keycode; // digit
        }
        if (keycode >= 0x41 && keycode <= 0x5a) {
            return shiftPressed ? keycode : keycode + 32; // A-Z
        }
        if (keycode >= 0x60 && keycode <= 0x69) {
            return XK_KP_0 + (keycode - 0x60); // numpad 0-9
        }

        switch(keycode) {
            case 0x20: return XK_space;
            case 0x6a: return XK_KP_Multiply;
            case 0x6b: return XK_KP_Add;
            case 0x6c: return XK_KP_Separator;
            case 0x6d: return XK_KP_Subtract;
            case 0x6e: return XK_KP_Decimal;
            case 0x6f: return XK_KP_Divide;
            case 0xbb: return XK_plus;
            case 0xbc: return XK_comma;
            case 0xbd: return XK_minus;
            case 0xbe: return XK_period;
        }

        return nonCharacterKey({keyCode: keycode});
    }

    function nonCharacterKey(evt) {
        if (!evt.keyCode) { return null; }
        var keycode = evt.keyCode;

        if (keycode >= 0x70 && keycode <= 0x87) {
            return XK_F1 + keycode - 0x70; // F1-F24
        }
        switch (keycode) {

            case 8 : return XK_BackSpace;
            case 13 : return XK_Return;

            case 9 : return XK_Tab;

            case 27 : return XK_Escape;
            case 46 : return XK_Delete;

            case 36 : return XK_Home;
            case 35 : return XK_End;
            case 33 : return XK_Page_Up;
            case 34 : return XK_Page_Down;
            case 45 : return XK_Insert;

            case 37 : return XK_Left;
            case 38 : return XK_Up;
            case 39 : return XK_Right;
            case 40 : return XK_Down;

            case 16 : return XK_Shift_L;
            case 17 : return XK_Control_L;
            case 18 : return XK_Alt_L; // also: Option-key on Mac

            case 224 : return XK_Meta_L;
            case 225 : return XK_ISO_Level3_Shift; // AltGr
            case 91 : return XK_Super_L; // also: Windows-key
            case 92 : return XK_Super_R; // also: Windows-key
            case 93 : return XK_Menu; // also: Windows-Menu, Command on Mac
            case 20 : return XK_Caps_Lock;
            default: return null;
        }
    }
    return {
        hasShortcutModifier : hasShortcutModifier,
        hasCharModifier : hasCharModifier,
        ModifierSync : ModifierSync,
        getKey : getKey,
        getKeysym : getKeysym,
        keysymFromKeyCode : keysymFromKeyCode,
        nonCharacterKey : nonCharacterKey,
        substituteCodepoint : substituteCodepoint
    };
})();

function KeyEventDecoder(modifierState, next) {
    "use strict";
    function sendAll(evts) {
        for (var i = 0; i < evts.length; ++i) {
            next(evts[i]);
        }
    }
    function process(evt, type) {
        var result = {type: type};
        var keyId = kbdUtil.getKey(evt);
        if (keyId) {
            result.keyId = keyId;
        }

        var keysym = kbdUtil.getKeysym(evt);

        var hasModifier = modifierState.hasShortcutModifier() || !!modifierState.activeCharModifier();
        if (keysym && (type !== 'keydown' || kbdUtil.nonCharacterKey(evt) || hasModifier)) {
            result.keysym = keysym;
        }

        var isShift = evt.keyCode === 0x10 || evt.key === 'Shift';

        var suppress = !isShift && (type !== 'keydown' || modifierState.hasShortcutModifier() || !!kbdUtil.nonCharacterKey(evt));

        var stall = type === 'keydown' && modifierState.activeCharModifier() && !kbdUtil.nonCharacterKey(evt);

        var active = modifierState.activeCharModifier();

        if (active && keysym) {
            var isCharModifier = false;
            for (var i  = 0; i < active.length; ++i) {
                if (active[i] === keysym.keysym) {
                    isCharModifier = true;
                }
            }
            if (type === 'keypress' && !isCharModifier) {
                result.escape = modifierState.activeCharModifier();
            }
        }

        if (stall) {
            next({type: 'stall'});
        }
        next(result);

        return suppress;
    }

    return {
        keydown: function(evt) {
            sendAll(modifierState.keydown(evt));
            return process(evt, 'keydown');
        },
        keypress: function(evt) {
            return process(evt, 'keypress');
        },
        keyup: function(evt) {
            sendAll(modifierState.keyup(evt));
            return process(evt, 'keyup');
        },
        syncModifiers: function(evt) {
            sendAll(modifierState.syncAny(evt));
        },
        releaseAll: function() { next({type: 'releaseall'}); }
    };
}

function VerifyCharModifier(next) {
    "use strict";
    var queue = [];
    var timer = null;
    function process() {
        if (timer) {
            return;
        }

        var delayProcess = function () {
            clearTimeout(timer);
            timer = null;
            process();
        };

        while (queue.length !== 0) {
            var cur = queue[0];
            queue = queue.splice(1);
            switch (cur.type) {
            case 'stall':
                timer = setTimeout(delayProcess, 5);
                return;
            case 'keydown':
                if (queue.length !== 0 && queue[0].type === 'keypress') {
                    if (queue[0].escape && (!cur.keysym || cur.keysym.keysym !== queue[0].keysym.keysym)) {
                        cur.escape = queue[0].escape;
                    }
                    cur.keysym = queue[0].keysym;
                    queue = queue.splice(1);
                }
                break;
            }

            if (cur.type !== 'stall') {
                next(cur);
            }
        }
    }
    return function(evt) {
        queue.push(evt);
        process();
    };
}

function TrackKeyState(next) {
    "use strict";
    var state = [];

    return function (evt) {
        var last = state.length !== 0 ? state[state.length-1] : null;

        switch (evt.type) {
        case 'keydown':
            if (!last || !evt.keyId || last.keyId !== evt.keyId) {
                last = {keyId: evt.keyId, keysyms: {}};
                state.push(last);
            }
            if (evt.keysym) {
                last.keysyms[evt.keysym.keysym] = evt.keysym;
                last.ignoreKeyPress = true;
                next(evt);
            }
            break;
        case 'keypress':
            if (!last) {
                last = {keyId: evt.keyId, keysyms: {}};
                state.push(last);
            }
            if (!evt.keysym) {
                console.log('keypress with no keysym:', evt);
            }

            if (evt.keysym && !last.ignoreKeyPress) {
                last.keysyms[evt.keysym.keysym] = evt.keysym;
                evt.type = 'keydown';
                next(evt);
            }
            break;
        case 'keyup':
            if (state.length === 0) {
                return;
            }
            var idx = null;
            for (var i = 0; i !== state.length; ++i) {
                if (state[i].keyId === evt.keyId) {
                    idx = i;
                    break;
                }
            }
            if (idx === null) {
                idx = state.length - 1;
            }

            var item = state.splice(idx, 1)[0];
            var clone = (function(){
                function Clone(){}
                return function (obj) { Clone.prototype=obj; return new Clone(); };
            }());
            for (var key in item.keysyms) {
                var out = clone(evt);
                out.keysym = item.keysyms[key];
                next(out);
            }
            break;
        case 'releaseall':
            for (var i = 0; i < state.length; ++i) {
                for (var key in state[i].keysyms) {
                    var keysym = state[i].keysyms[key];
                    next({keyId: 0, keysym: keysym, type: 'keyup'});
                }
            }
            state = [];
        }
    };
}

function EscapeModifiers(next) {
    "use strict";
    return function(evt) {
        if (evt.type !== 'keydown' || evt.escape === undefined) {
            next(evt);
            return;
        }
        for (var i = 0; i < evt.escape.length; ++i) {
            next({type: 'keyup', keyId: 0, keysym: keysyms.lookup(evt.escape[i])});
        }
        next(evt);
        for (var i = 0; i < evt.escape.length; ++i) {
            next({type: 'keydown', keyId: 0, keysym: keysyms.lookup(evt.escape[i])});
        }
    };
}
