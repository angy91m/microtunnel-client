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
            appCredFile: process.env.APP_CRED,
            authServersFile: process.env.AUTH_SRVS,
            ...options
        };
        const { api, timeout, appCredFile, authServersFile } = defaultOptions;
        const 
            appCred = require( './' + appCredFile ),
            authServers = require( './' + authServersFile ),
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
            constructor( name, url, agent, signature ) {
                this.name = name;
                this.url = url;
                this.agent = agent;
                this.signature = signature;
                this.active = false;
                this.key = undefined;
                this.shaKey = undefined;
                this.connecting = false;
            }
            delete() {
                this.active = false;
                this.key = undefined;
                this.shaKey = undefined;
            }
            extract() {
                const obj = {
                    name: this.name,
                    url: this.url,
                    agent: this.agent,
                    signature: this.signature,
                    active: this.active,
                    key: this.key,
                    shaKey: this.shaKey
                };
                return obj;
            }
            reset() {
                this.delete();
            }
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
        }
    
        class AuthClientSessions extends Array {
            constructor( authServers ) {
                const servs = [];
                for ( const srv in authServers ) {
                    servs.push( new AuthClientSex( srv, authServers[srv].url, authServers[srv].agent, Buffer.from( authServers[srv].publicKey, 'base64' ) ) );
                }
                super( ...servs );
            }
            get( str ) {
                if ( !str || typeof str !== 'string' ) return false;
                const found = this.find( el => el.name === str );
                if ( found ) return found;
                return false;
            }
            extract( str ) {
                const found = this.get( str );
                if ( !found ) return found;
                return found.extract();
            }
            reset( str ) {
                const found = this.get( str );
                if ( !found ) return found;
                return found.reset();
            }
        }
    
        const sessions = new AuthClientSessions( authServers );
    
        const srvReq = {
            async get( serverName, serverPath = '/' ) {
                const srv = sessions.get( serverName );
                while ( srv.connecting ) await new Promise( r => setTimeout( r, 1000 ) );
                if ( !srv.active ) {
                    try {
                        await srv.connect();
                    } catch {
                        await new Promise( r => setTimeout( r, 2000 ) );
                        await srv.connect();
                    }
                }
                let body;
                try {
                    body = ( await client.get( srv.url + api + serverPath ) ).data;
                } catch {
                    try {
                        srv.delete();
                        while ( srv.connecting ) await new Promise( r => setTimeout( r, 1000 ) );
                        try {
                            await srv.connect();
                        } catch {
                            await new Promise( r => setTimeout( r, 2000 ) );
                            await srv.connect();
                        }
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
                const srv = sessions.get( serverName );
                while ( srv.connecting ) await new Promise( r => setTimeout( r, 1000 ) );
                if ( !srv.active ) {
                    try {
                        await srv.connect();
                    } catch {
                        await new Promise( r => setTimeout( r, 2000 ) );
                        await srv.connect();
                    }
                }
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
                        while ( srv.connecting ) await new Promise( r => setTimeout( r, 1000 ) );
                        try {
                            await srv.connect();
                        } catch {
                            await new Promise( r => setTimeout( r, 2000 ) );
                            await srv.connect();
                        }
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
            symCryptor
        };
        return srvReq;
    };
    
    
    module.exports = create;
}