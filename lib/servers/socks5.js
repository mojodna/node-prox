var net = require('net');
var Binary = require('binary');
var Put = require('put');

module.exports = function (cb) {
    return net.createServer(function (stream) {
        session(stream, cb);
    });
};

function session (stream, cb) {
    // silence warnings
    stream.setMaxListeners(0);

    Binary.stream(stream)
        .word8('ver')
        .word8('nmethods')
        .buffer('methods', 'nmethods')
        .tap(function (vars) {
            var methods = [].slice.call(vars.methods)
                .reduce(function (acc,m) { acc[m] = true; return acc }, {});
            // username + password only
            //var method = methods[2] ? 0x02 : 0xff;
            var method = methods[0] ? 0x00 : 0xff;
            
            Put().word8(5).word8(method).write(stream);
        })
        .loop(function (end) {
            stream.on('end', end);
            
            var vars = this
            .word8('ver')
            .word8('cmd')
            .word8('rsv')
            .word8('dst.atyp')
            .tap(function (vars) {
                var atyp = vars.dst.atyp;
                if (atyp === 0x01) { // ipv4
                    this
                        .buffer('addr.buf', 4)
                        .tap(function (vars) {
                            vars.dst.addr = [].slice
                                .call(vars.addr.buf).join('.');
                        })
                    ;
                }
                else if (atyp === 0x03) { // domain name
                    this
                        .word8('addr.size')
                        .buffer('addr.buf', 'addr.size')
                        .tap(function (vars) {
                            vars.dst.addr = vars.addr.buf.toString();
                        })
                    ;
                }
                else if (atyp === 0x04) { // ipv6
                    this
                        .word32be('addr.a')
                        .word32be('addr.b')
                        .word32be('addr.c')
                        .word32be('addr.d')
                        .tap(function (vars) {
                            vars.dst.addr = 'abcd'.split('')
                                .map(function (x) {
                                    return vars.addr[x].toString(16);
                                })
                            ;
                        })
                    ;
                }
            })
            .word16bu('dst.port')
            .vars;

            // console.log(vars);
            // TODO better verification of pieces
            if (vars.ver === 0x05 &&
                vars.cmd === 0x01 &&
                vars.rsv === 0x00) {
                var dst = vars.dst;
                // TODO emit connect event (or bind or associate)
                // TODO include atyp
                cb({
                    host : dst.addr,
                    port : dst.port,
                }, stream);
            }
            else if (vars.ver === 0x05 && vars.rsv === 0x00) {
                var cmd = vars.cmd;
                var dst = vars.dst;

                if (cmd === 0x01) {
                    console.log("CONNECT %s:%s", dst.addr, dst.port);
                }
                else if (cmd === 0x02) {
                    console.log("BIND %s:%s", dst.addr, dst.port);
                }
                else if (cmd === 0x03) {
                    console.log("UDP ASSOCIATE %s:%s", dst.addr, dst.port);
                }
            }
        })
    ;
};
