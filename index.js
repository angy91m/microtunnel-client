"use strict";
const superSphincs = require( 'supersphincs' ),
    kyber = require( 'kyber-crystals' ),
    symCryptor = require( 'symcryptor' ),
    { encode: cbEncode, decode: cbDecode } = require( 'cbor-x' );
if ( process.argv[1] === __filename && process.argv[2] === 'cred-generate' ) {
    Promise.all( [
        superSphincs.keyPair(),
        symCryptor.rndBytes( 24 )
    ] )
    .then( res => {
        const cred = {
            publicKey: Buffer.from( res[0].publicKey ).toString( 'base64' ),
            privateKey: Buffer.from( res[0].privateKey ).toString( 'base64' ),
            agent: res[1].toString( 'base64' )
        }
        console.log( JSON.stringify( cred, null, 4 ) );
    } )
    .catch( console.error )
    .finally( process.exit );
} else {
    const create = ( options = {} ) => {
        const defaultOptions = {
            api: '/microtunnel',
            timeout: 5000,
            servErrorWait: 5,                       // In minutes
            appCredFile: process.env.APP_CRED,
            authServersFile: process.env.AUTH_SRVS,
            ...options
        };
        const { api, timeout, appCredFile, authServersFile, servErrorWait } = defaultOptions;
        const 
            appCred = require( appCredFile ),
            authServers = require( authServersFile ),
            HttpAgent = require( 'agentkeepalive' ),
            { HttpsAgent } = HttpAgent,
            client = require( 'axios' ).create( {
                timeout,
                httpAgent: new HttpAgent(),
                httpsAgent: new HttpsAgent(),
                maxRedirects: 0,
                responseType: 'arraybuffer',
                headers: {
                    "User-Agent": appCred.agent,
                    "Connection": 'keep-alive'
                }
            } ),
            postOptions = {
                headers: {
                    'Content-Type': 'application/octet-stream'
                }
            }
        ;
        class AuthClientSex {
            constructor( name, srvs ) {
                this.name = name;
                if ( srvs.constructor !== Array ) srvs = [srvs];
                this.servers = srvs.map( ( s, i ) => ( {
                    name,
                    agent: s.agent,
                    signature: Buffer.from( s.publicKey, 'base64' ),
                    url: s.url,
                    active: false,
                    key: undefined,
                    shaKey: undefined,
                    connecting: false,
                    index: i,
                    lastError: undefined,
                    delete() {
                        this.active = false;
                        this.key = undefined;
                        this.shaKey = undefined;
                    },
                    async connect() {
                        try {
                            this.connecting = true;
                            let body;
                            const rndStr = await symCryptor.rndBytes( 64 );
                            try {
                                body = new Uint8Array( ( await client.post( this.url + api +'/auth1', rndStr, postOptions ) ).data );
                            } catch ( err ) {
                                throw new Error( 'Internal server error with server ' + this.name );
                            }
                            if (
                                body.length !== 31490
                            ) throw new Error( 'Internal server error with server ' + this.name );
                            const very = await superSphincs.verifyDetached( body.slice( 1568, -64 ), rndStr, this.signature, this.agent );
                            if ( !very ) throw new Error( 'Internal server error with server ' + this.name );
                            const pubKey = body.slice( 0, 1568 );
                            const strToSign = body.slice( -64 );
                            const { cyphertext, secret } = await kyber.encrypt( pubKey );
                            this.key = secret;
                            this.shaKey = await symCryptor.rndBytes( 32 );
                            const signed = await superSphincs.signDetached( strToSign, Buffer.from( appCred.privateKey, 'base64' ), this.shaKey );
                            const pst = Buffer.concat( [
                                cyphertext,
                                await symCryptor.encrypt( this.shaKey, this.key ),
                                await symCryptor.encrypt( signed, this.key, this.shaKey, appCred.agent )
                            ] );
                            body = ( await client.post( this.url + api + '/auth2', pst, postOptions ) ).data;
                            if ( body.length !== 84 ) throw new Error( 'Internal server error with server ' + this.name );
                            const confirmation = await symCryptor.decrypt( body, this.key, this.shaKey, this.agent );
                            if ( confirmation.toString() === 'true' ) {
                                this.active = true;
                            }
                        } catch {
                            throw new Error( 'Internal server error with server ' + this.name );
                        } finally {
                            this.connecting = false;
                        }
                    }
                } ) );
                this.robin = 0;
            }
        }
    
        class AuthClientSessions extends Array {
            constructor( authServers ) {
                const servs = [];
                for ( const srv in authServers ) {
                    servs.push( new AuthClientSex( srv, authServers[srv] ) );
                }
                super( ...servs );
            }
            get( str ) {
                if ( !str || typeof str !== 'string' ) return false;
                const found = this.find( el => el.name === str );
                if ( !found ) return false;
                let srv, firstIndex;
                while ( !srv ) {
                    const server = found.servers[found.robin];
                    if ( found.servers.length - 1 === found.robin ) {
                        found.robin = 0;
                    } else {
                        found.robin = found.robin + 1;
                    }
                    if ( typeof firstIndex === 'undefined' ) {
                        firstIndex = server.index;
                    } else if ( firstIndex === server.index ) {
                        throw new Error( 'Internal server error with server ' + str );
                    }
                    if ( server.lastError ) {
                        if ( Date.now() > ( server.lastError + ( servErrorWait * 60000 ) ) ) {
                            server.lastError = undefined;
                            srv = server;
                        }
                    } else {
                        srv = server;
                    }
                }
                return srv;
            }
        }
    
        const sessions = new AuthClientSessions( authServers );
    
        const getSrvConnection = async ( serverName ) => {
            let srv, firstIndex;
            while( !srv ) {
                const server = sessions.get( serverName );
                if ( typeof firstIndex === 'undefined' ) {
                    firstIndex = server.index;
                } else if ( firstIndex === server.index ) {
                    throw new Error( 'Internal server error with server ' + serverName );
                }
                if ( server.connecting ) {
                    await new Promise( r => setTimeout( r, 1000 ) );
                    if ( server.active ) srv = server;
                } else {
                    if ( !server.active ) {
                        try {
                            await server.connect();
                            srv = server;
                        } catch {
                            server.lastError = Date.now();
                            continue;
                        }
                    } else {
                        srv = server;
                    }
                }
            }
            return srv;
        };

        const srvReq = {
            async get( serverName, serverPath = '/' ) {
                let srv = await getSrvConnection( serverName ); 
                serverPath = serverPath || '/';
                let body;
                try {
                    body = ( await client.get( srv.url + api + serverPath ) ).data;
                } catch {
                    try {
                        srv.delete();
                        srv = await getSrvConnection( serverName );
                        body = ( await client.get( srv.url + api + serverPath ) ).data;
                    } catch ( err ) {
                        throw err;
                    }
                }
                try {
                    return cbDecode( await symCryptor.decrypt( body, srv.key, srv.shaKey, srv.agent ) );
                } catch {
                    throw new Error( 'Internal server error with server ' + serverName );
                }
            },
            async post( serverName, serverPath = '/', obj ) {
                let srv = await getSrvConnection( serverName );
                serverPath = serverPath || '/';
                let body
                try {
                    body = ( await client.post(
                        srv.url + api + serverPath,
                        await symCryptor.encrypt( cbEncode( obj ), srv.key, srv.shaKey, appCred.agent ),
                        postOptions
                    ) ).data;
                } catch {
                    try {
                        srv.delete();
                        srv = await getSrvConnection( serverName );
                        body = ( await client.post(
                            srv.url + api + serverPath,
                            await symCryptor.encrypt( cbEncode( obj ), srv.key, srv.shaKey, appCred.agent ),
                            postOptions
                        ) ).data;
                    } catch ( err ) {
                        throw err;
                    }
                }
                try {
                    return cbDecode( await symCryptor.decrypt( body, srv.key, srv.shaKey, srv.agent ) );
                } catch {
                    throw new Error( 'Internal server error with server ' + serverName );
                }
            },
            symCryptor,
            authServers
        };
        return srvReq;
    };
    
    
    module.exports = create;
}