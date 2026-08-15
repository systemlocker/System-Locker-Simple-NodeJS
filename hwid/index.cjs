'use strict';

const core = require('./core.cjs');
const platform = require('./collect.cjs');

module.exports = {
  ...core,
  collect: platform.collect,
  deviceHwid: platform.deviceHwid,
};
