Anonymous Filter for ZNC
===================================

This module filter commands to ensure your anonymity.
(Based on IRCFilter.java from I2PTunnel from I2P project.)

Build
-----------------------------------

Build it with

    $ znc-buildmod anonfilter.cpp

Install
-----------------------------------

Place compiled anonfilter.so in your ZNC modules folder.

Usage
-----------------------------------

Load plugin and it should just works.

Arguments
-----------------------------------

Pass `i2pdcc` to allow DCC with I2P addresses.

