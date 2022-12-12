export = create;
declare function create(options?: {}): {
    get(serverName: any, serverPath?: string): Promise<any>;
    post(serverName: any, serverPath: string, obj: any): Promise<any>;
    symCryptor: typeof symCryptor;
};
import symCryptor = require("symcryptor");
