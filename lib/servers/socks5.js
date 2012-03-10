var net = require('net');
var Binary = require('binary');
var Put = require('put');

module.exports = function() {
    return net.createServer()
        .on('connection', function(socket) {
            session(socket, this);
        });
};

function session (stream, server) {
    var vars = Binary.stream(stream)
        // authentication method negotiation
        .word8('ver')
        .word8('nmethods')
        .buffer('methods', 'nmethods')
        .tap(function (vars) {
            var methods = [].slice.call(vars.methods)
                .reduce(function (acc,m) { acc[m] = true; return acc }, {});

            // pick a method and tell the client what we're using

            // methods[0] => no authentication required
            var method = methods[0] ? 0x00 : 0xff;

            // methods[2] => username/password
            //var method = methods[2] ? 0x02 : 0xff;


            // notify the client of the selected method
            Put()
                .word8(0x05) // ver
                .word8(method) // chosen method
                .write(stream);
        })

        // relay request
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
        .tap(function(vars) {
            // verify preamble
            if (vars.ver === 0x05 &&
                vars.rsv === 0x00) {
                var dst = vars.dst;

                switch(vars.cmd) {
                    case 0x01:
                        console.log("CONNECT %s:%s", dst.addr, dst.port);

                        // TODO respond with not supported if
                        // server.listeners(event).length == 0

                        server.emit('connect', {
                            host: dst.addr,
                            port: dst.port,
                            atyp: dst.atyp
                        }, stream);

                        break;

                    case 0x02:
                        console.log("BIND %s:%s", dst.addr, dst.port);

                        // TODO respond with not supported if
                        // server.listeners(event).length == 0

                        server.emit('bind', {
                            host: dst.addr,
                            port: dst.port,
                            atyp: dst.atyp
                        }, stream);

                        break;

                    case 0x03:
                        console.log("UDP ASSOCIATE %s:%s", dst.addr, dst.port);

                        // TODO respond with not supported if
                        // server.listeners(event).length == 0

                        server.emit('associate', {
                            host: dst.addr,
                            port: dst.port,
                            atyp: dst.atyp
                        }, stream);

                        break;

                    default:
                        console.warn("Invalid CMD: " + vars.cmd);
                }
            }
        });
};
