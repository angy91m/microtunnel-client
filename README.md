# microtunnel-client

**microtunnel-client** is an [axios](https://www.npmjs.com/package/axios) based library to enable post-quantum protected communication between apps (it must be used with microtunnel-server). You can send any JSON-serializable data. It also uses [supersphincs](https://www.npmjs.com/package/supersphincs) for app authentication, [kyber-crystals](https://www.npmjs.com/package/kyber-crystals) for asymmetric encryption and [symcryptor](https://www.npmjs.com/package/symcryptor) for symmetric encryption.

## Installation

```bash
npm i microtunnel-client
```

## Usage

First, you have to create app credentials and save them in a json file. Enter in module path typing `cd path-to-your-project/node-modules/microtunnel-client` and then run `npm run -s cred-generate > ../../appCred.json` to save the credentials in your project root.

```javascript
// appCred.json
{
    // Supersphincs keys base-64 encoded
    "publicKey": "rPyoqSZrNNUVpjKdhGLDD4sjXd8lgIgnRBY2NP5n8PDDLSvoLoD5n4GjaxbAfSDjagBjN8zztUQTNG1EKO9IgpgTLkfkTkhWqdgkC/K3EQLh6AMCZ8snlnles2QrbHAy",
    "privateKey": "FKQ243eKoZ1zAdfXfGkzjcONsFwXbb2YliwoFSMFjNSs/KipJms01RWmMp2EYsMPiyNd3yWAiCdEFjY0/mfw8MkQY9Orp5MsbUAf54jM1iUhvEhaUJceqTG92ibMdu914IaJsN5+3hKHhAZ1o+dtspIY09zuZKNe48hEjlLwjg3DLSvoLoD5n4GjaxbAfSDjagBjN8zztUQTNG1EKO9IgpgTLkfkTkhWqdgkC/K3EQLh6AMCZ8snlnles2QrbHAy",

    // Random bytes base-64 encoded for ID
    "agent": "vwoA1JzkT6d7SXjIBoZ2egYlSn6Ajzge"
}
```

Then you have to create a JSON file containing servers info. In this example we have two apps named `backEnd` and `sessions`:

```javascript
// authServers.json
{
    "backEnd": {
        "url": "http://127.0.0.1:3000",
        "publicKey": "X67kzs9zrKfbayvF5SIsulZzfUYHeTm6BoFTD/BWiryIcOWcaR8d6M4LpaOylCi4DqY59ABNt1nNnfFZjG4akE4hcKaMyx5ar9Uds2Op687uecLGWb0n6W+voSDKzMS8",
        "agent": "285gWsTqj3Gza+3AxJn1qrWzAvf/Lf5i"
    },
    "sessions": [
        {
            "url": "http://192.168.0.3:3000",
            "publicKey": "rPyoqSZrNNUVpjKdhGLDD4sjXd8lgIgnRBY2NP5n8PDDLSvoLoD5n4GjaxbAfSDjagBjN8zztUQTNG1EKO9IgpgTLkfkTkhWqdgkC/K3EQLh6AMCZ8snlnles2QrbHAy",
            "agent": "vwoA1JzkT6d7SXjIBoZ2egYlSn6Ajzge"
        },
        {
            "url": "http://192.168.0.4:3000",
            "publicKey": "UFOrl4Rtp/4sLvwsHG9bTBGQ9vf95L8WQJRvueRHKbOs+Hf2vRlVw/ZIF18vf1EV+q2voXYBAwE/uhPlH2IiAkFDC8p4vEr/4xQMl45U6Y8wfgJwjGNnUorD8z/AAyR2",
            "agent": "zzgU2bYvR0mRREkDz+sqAMOGNDBX7XrW"
        }
    ]
}
```

Then you can use it in your code:

```javascript
const authReq = require( 'microtunnel-client' )( { appCredFile: './appCred.json', authServersFile: './authServers.json' } );
( async () => {
    try {
        let resp = await authReq.get( 'backEnd', '/page/2' );
        console.log( resp );
        resp = await authReq.post( 'sessions', '/another-route', { data: 'mydata' } );
        console.log( resp );
    } catch ( err ) {
        console.log( err );
    }
} )();
```

## Configuration

### `require( 'microtunnel-client' )( options )`

#### `options`

* `api` Optional - Root path for microtunnel (note: must be the same for servers) - Default `'/microtunnel'`
* `timeout` Optional - Axios timeout for each request
* `appCredFile` Optional - Relative path of the credentials file - Default: enviroment var `APP_CRED`
* `authServersFile` Optional - Relative path of the autherized clients file - Default: enviroment var `AUTH_SRVS`
* `customCa` Optional - Replace default Mozilla wellknowed CA with your custom CA as result of `fs.readFileSync( './ca.cert' )`

## Methods

### `authReq.get`
```javascript
authReq.get( serverName: String, serverPath: String )
```

#### Parameters
* `serverName` Required - The name of the server as written in authServers.json
* `serverPath` Required - The path of the server you want to fetch

#### Return
Decrypted JSON parsed data from server when `Promise` resolved else throw an `Error`

### `authReq.post`
```javascript
authReq.post( serverName: String, serverPath: String, obj )
```

#### Parameters
* `serverName` Required - The name of the server as written in authServers.json
* `serverPath` Required - The path of the server you want to fetch
* `obj` Required - The data you want to send. It must be JSON serializable

#### Return
Decrypted JSON parsed data from server when `Promise` resolved else throw an `Error`