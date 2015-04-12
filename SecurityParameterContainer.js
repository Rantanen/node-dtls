
"use strict";

var SecurityParameters = require( './SecurityParameters' );

var SecurityParameterContainer = function() {
    this.parameters = {};
    this.parameters[0] = new SecurityParameters();
    this.pending = this.parameters[1] = new SecurityParameters();

    this.current = 0;
};

SecurityParameterContainer.prototype.getCurrent = function( epoch ) {
    return this.parameters[ epoch ];
};

SecurityParameterContainer.prototype.change = function( epoch ) {
    this.current++;
    this.pending.init();
    this.pending = this.parameters[ this.current + 1 ] = new SecurityParameters();
};

module.exports = SecurityParameterContainer;
