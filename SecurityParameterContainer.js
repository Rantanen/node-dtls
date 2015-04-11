
"use strict";

var SecurityParameters = require( './SecurityParameters' );

var SecurityParameterContainer = function() {
    this.pending = new SecurityParameters();
    this.current = {};
    this.current[0] = new SecurityParameters();
};

SecurityParameterContainer.prototype.getCurrent = function( epoch ) {
    return this.current[ epoch ];
};

module.exports = SecurityParameterContainer;
