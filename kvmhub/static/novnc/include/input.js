

var Keyboard, Mouse;

(function () {
    "use strict";


    Keyboard = function (defaults) {
        this._keyDownList = [];         // List of depressed keys

        Util.set_defaults(this, defaults, {
            'target': document,
            'focused': true
        });

        this._handler = new KeyEventDecoder(kbdUtil.ModifierSync(),
            VerifyCharModifier( /* jshint newcap: false */
                TrackKeyState(
                    EscapeModifiers(this._handleRfbEvent.bind(this))
                )
            )
        ); /* jshint newcap: true */

        this._eventHandlers = {
            'keyup': this._handleKeyUp.bind(this),
            'keydown': this._handleKeyDown.bind(this),
            'keypress': this._handleKeyPress.bind(this),
            'blur': this._allKeysUp.bind(this)
        };
    };

    Keyboard.prototype = {

        _handleRfbEvent: function (e) {
            if (this._onKeyPress) {
                Util.Debug("onKeyPress " + (e.type == 'keydown' ? "down" : "up") +
                           ", keysym: " + e.keysym.keysym + "(" + e.keysym.keyname + ")");
                this._onKeyPress(e.keysym.keysym, e.type == 'keydown');
            }
        },

        _handleKeyDown: function (e) {
            if (!this._focused) { return true; }

            if (this._handler.keydown(e)) {
                Util.stopEvent(e);
                return false;
            } else {
                return true;
            }
        },

        _handleKeyPress: function (e) {
            if (!this._focused) { return true; }

            if (this._handler.keypress(e)) {
                Util.stopEvent(e);
                return false;
            } else {
                return true;
            }
        },

        _handleKeyUp: function (e) {
            if (!this._focused) { return true; }

            if (this._handler.keyup(e)) {
                Util.stopEvent(e);
                return false;
            } else {
                return true;
            }
        },

        _allKeysUp: function () {
            Util.Debug(">> Keyboard.allKeysUp");
            this._handler.releaseAll();
            Util.Debug("<< Keyboard.allKeysUp");
        },


        grab: function () {
            var c = this._target;

            Util.addEvent(c, 'keydown', this._eventHandlers.keydown);
            Util.addEvent(c, 'keyup', this._eventHandlers.keyup);
            Util.addEvent(c, 'keypress', this._eventHandlers.keypress);

            Util.addEvent(window, 'blur', this._eventHandlers.blur);

        },

        ungrab: function () {
            var c = this._target;

            Util.removeEvent(c, 'keydown', this._eventHandlers.keydown);
            Util.removeEvent(c, 'keyup', this._eventHandlers.keyup);
            Util.removeEvent(c, 'keypress', this._eventHandlers.keypress);
            Util.removeEvent(window, 'blur', this._eventHandlers.blur);

            this._allKeysUp();

        },

        sync: function (e) {
            this._handler.syncModifiers(e);
        }
    };

    Util.make_properties(Keyboard, [
        ['target',     'wo', 'dom'],  // DOM element that captures keyboard input
        ['focused',    'rw', 'bool'], // Capture and send key events

        ['onKeyPress', 'rw', 'func'] // Handler for key press/release
    ]);


    Mouse = function (defaults) {
        this._mouseCaptured  = false;

        this._doubleClickTimer = null;
        this._lastTouchPos = null;

        Util.set_defaults(this, defaults, {
            'target': document,
            'focused': true,
            'scale': 1.0,
            'touchButton': 1
        });

        this._eventHandlers = {
            'mousedown': this._handleMouseDown.bind(this),
            'mouseup': this._handleMouseUp.bind(this),
            'mousemove': this._handleMouseMove.bind(this),
            'mousewheel': this._handleMouseWheel.bind(this),
            'mousedisable': this._handleMouseDisable.bind(this)
        };
    };

    Mouse.prototype = {
        _captureMouse: function () {
            if (this._target.setCapture) {
                this._target.setCapture();
            }

            this._mouseCaptured = true;
        },

        _releaseMouse: function () {
            if (this._target.releaseCapture) {
                this._target.releaseCapture();
            }
            this._mouseCaptured = false;
        },

        _resetDoubleClickTimer: function () {
            this._doubleClickTimer = null;
        },

        _handleMouseButton: function (e, down) {
            if (!this._focused) { return true; }

            if (this._notify) {
                this._notify(e);
            }

            var evt = (e ? e : window.event);
            var pos = Util.getEventPosition(e, this._target, this._scale);

            var bmask;
            if (e.touches || e.changedTouches) {

                if (down == 1) {
                    if (this._doubleClickTimer === null) {
                        this._lastTouchPos = pos;
                    } else {
                        clearTimeout(this._doubleClickTimer);


                        var xs = this._lastTouchPos.x - pos.x;
                        var ys = this._lastTouchPos.y - pos.y;
                        var d = Math.sqrt((xs * xs) + (ys * ys));

                        if (d < 20 * window.devicePixelRatio) {
                            pos = this._lastTouchPos;
                        }
                    }
                    this._doubleClickTimer = setTimeout(this._resetDoubleClickTimer.bind(this), 500);
                }
                bmask = this._touchButton;
            } else if (evt.which) {
                bmask = 1 << evt.button;
            } else {
                bmask = (evt.button & 0x1) +      // Left
                        (evt.button & 0x2) * 2 +  // Right
                        (evt.button & 0x4) / 2;   // Middle
            }

            if (this._onMouseButton) {
                Util.Debug("onMouseButton " + (down ? "down" : "up") +
                           ", x: " + pos.x + ", y: " + pos.y + ", bmask: " + bmask);
                this._onMouseButton(pos.x, pos.y, down, bmask);
            }
            Util.stopEvent(e);
            return false;
        },

        _handleMouseDown: function (e) {
            this._captureMouse();
            this._handleMouseButton(e, 1);
        },

        _handleMouseUp: function (e) {
            if (!this._mouseCaptured) { return; }

            this._handleMouseButton(e, 0);
            this._releaseMouse();
        },

        _handleMouseWheel: function (e) {
            if (!this._focused) { return true; }

            if (this._notify) {
                this._notify(e);
            }

            var evt = (e ? e : window.event);
            var pos = Util.getEventPosition(e, this._target, this._scale);
            var wheelData = evt.detail ? evt.detail * -1 : evt.wheelDelta / 40;
            var bmask;
            if (wheelData > 0) {
                bmask = 1 << 3;
            } else {
                bmask = 1 << 4;
            }

            if (this._onMouseButton) {
                this._onMouseButton(pos.x, pos.y, 1, bmask);
                this._onMouseButton(pos.x, pos.y, 0, bmask);
            }
            Util.stopEvent(e);
            return false;
        },

        _handleMouseMove: function (e) {
            if (! this._focused) { return true; }

            if (this._notify) {
                this._notify(e);
            }

            var evt = (e ? e : window.event);
            var pos = Util.getEventPosition(e, this._target, this._scale);
            if (this._onMouseMove) {
                this._onMouseMove(pos.x, pos.y);
            }
            Util.stopEvent(e);
            return false;
        },

        _handleMouseDisable: function (e) {
            if (!this._focused) { return true; }

            var evt = (e ? e : window.event);
            var pos = Util.getEventPosition(e, this._target, this._scale);

            if (evt.target.id == this._target.id)  // filter non-canvas pos
            {
            if ((pos.realx >= 0) && (pos.realy >= 0) &&
                (pos.realx < this._target.offsetWidth) &&
                (pos.realy < this._target.offsetHeight)) {
                Util.stopEvent(e);
                return false;
            }

            }

            return true;
        },


        grab: function () {
            var c = this._target;

            if ('ontouchstart' in document.documentElement) {
                Util.addEvent(c, 'touchstart', this._eventHandlers.mousedown);
                Util.addEvent(window, 'touchend', this._eventHandlers.mouseup);
                Util.addEvent(c, 'touchend', this._eventHandlers.mouseup);
                Util.addEvent(c, 'touchmove', this._eventHandlers.mousemove);
            } else {
                Util.addEvent(c, 'mousedown', this._eventHandlers.mousedown);
                Util.addEvent(window, 'mouseup', this._eventHandlers.mouseup);
                Util.addEvent(c, 'mouseup', this._eventHandlers.mouseup);
                Util.addEvent(c, 'mousemove', this._eventHandlers.mousemove);
                Util.addEvent(c, (Util.Engine.gecko) ? 'DOMMouseScroll' : 'mousewheel',
                              this._eventHandlers.mousewheel);
            }

            Util.addEvent(document, 'click', this._eventHandlers.mousedisable);
            Util.addEvent(document.body, 'contextmenu', this._eventHandlers.mousedisable);
        },

        ungrab: function () {
            var c = this._target;

            if ('ontouchstart' in document.documentElement) {
                Util.removeEvent(c, 'touchstart', this._eventHandlers.mousedown);
                Util.removeEvent(window, 'touchend', this._eventHandlers.mouseup);
                Util.removeEvent(c, 'touchend', this._eventHandlers.mouseup);
                Util.removeEvent(c, 'touchmove', this._eventHandlers.mousemove);
            } else {
                Util.removeEvent(c, 'mousedown', this._eventHandlers.mousedown);
                Util.removeEvent(window, 'mouseup', this._eventHandlers.mouseup);
                Util.removeEvent(c, 'mouseup', this._eventHandlers.mouseup);
                Util.removeEvent(c, 'mousemove', this._eventHandlers.mousemove);
                Util.removeEvent(c, (Util.Engine.gecko) ? 'DOMMouseScroll' : 'mousewheel',
                                 this._eventHandlers.mousewheel);
            }

            Util.removeEvent(document, 'click', this._eventHandlers.mousedisable);
            Util.removeEvent(document.body, 'contextmenu', this._eventHandlers.mousedisable);

        }
    };

    Util.make_properties(Mouse, [
        ['target',         'ro', 'dom'],   // DOM element that captures mouse input
        ['notify',         'ro', 'func'],  // Function to call to notify whenever a mouse event is received
        ['focused',        'rw', 'bool'],  // Capture and send mouse clicks/movement
        ['scale',          'rw', 'float'], // Viewport scale factor 0.0 - 1.0

        ['onMouseButton',  'rw', 'func'],  // Handler for mouse button click/release
        ['onMouseMove',    'rw', 'func'],  // Handler for mouse movement
        ['touchButton',    'rw', 'int']    // Button mask (1, 2, 4) for touch devices (0 means ignore clicks)
    ]);
})();
