#run with npm 

const nodeRSA = require('node-rsa');
const fetch = require('node-fetch');
const publicKey = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbM2br48JS2JJy8Ajy0gy33Gu5RNAFgysUp4Mj9FqzXWg7AwdGaXc0vIAGG3vmyrP906qJpiEV1aW9GhsEGNQ9Mjmngfnu1VAKZjskVToqG1ktiXZJKSlVUfGTYj+r1lKDgd2iKt4azIzoeElk1gnLovn8zEaiCT7prHlzWWb7JgW3qp1e12e5WvSC5xX9P5iKOs6WM3qTSAX3e8qGeA9wtlHdQuDjSjWA0WlYQIFKgpoCBNZeldNxel79QgR7QKG6Oo/H4aImhDW9vXH00mGVy9QX11ngovVYPhCQWzsAo+v+Y2lAJUtFdjr2t9/mJisKxpYvpMeqVo2ZSydwBmb5'
const consumerId = 'f68f212e-b470-4be6-8958-76fd2c00c5d2'
const privateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkFqS1RECoVRV\
ZoHOsTn+Hw58HE7gSL9ziKEbCwBqaXcfd3mANXVGR/VePis9aMZfh8Zs0s4b3iQT\
QVE1JbkE0pieIkJwAoKBomTkWqsYgu2uvXv+H61Fo2e9t8/wSNEfZCOHYh5ICk39\
OV7K4E4ZbGE8X4fAysbkADRMn5hyI4rPR/hAU5V7nQdXeXrfm3gwRflm0jroPrHb\
EIBsAAGJtBdfi2NOzVoySCuO4orM4R/0YZ/+qwjXW/xz6R0LeuyqwxruNW1c7t27\
nPQSDkSorVGYjz6Mi0yCOdn8x7W49mI3++CidRjSffdVnLIDcxwLOTNbF34gkI2P\
Nc1Q/tqLAgMBAAECggEACYJebTrVXGwB4N9j6myO5dE676pcT9cncTSb0YtjrMcL\
5kDwQ6PVdgs5hwqnStnFlUezEh9tXmQTRyJj6GaVQFhMC+4EV6VtlsGogytV+wer\
apMEmoePbRe5LV93p38wz1boUDI5ewdN2bz3Z150aDjFsc//eAbIW/I/FamyFfst\
j+aSLxPe5HBFSKBZbS7nC6MV3Emfih1Da0jx9JAQUOkEg94TLvBBxv/9v2VBiqAz\
gXY2UzDtV8VZpHQMnul0elS+uPc+zF/pDZgvCIfK36rWOc/w1JLbl/bvqTifUsr3\
GrTrHNqgsMYvQ9KuY4kdyQBLYLamJHJ0LJH8Il/isQKBgQDQfJ9Zj15mK6/wwGZa\
/r1J1leuz+mhmgeFb1EoL48jDQM/kaoMjC4sva04q8NekOqp1oiCOIyt7fa8xlCq\
AvB1w7QuBT6em0nOwVNjHQURfPAtlKmlUUWBdMzpzV9c5lBiC8IXFpQROaMy6JSx\
RLP+HzDGwCFTKC2bupJkvDMDNwKBgQDJe8Qdbyr5o0sz6vMr6GUbtiFq2c7cuiR3\
eMybZ075HQWtAq9joiu73NPJiuPLUL2QSsIUG6Ma1LkjhDr0hNQcU38DtkdNxV8h\
v9UMzCIt8yOaECc05l1fjiGbHGFvYArYBatOwHi4Gc5/RNy3IBxzHNP1XgbTinpb\
/XlvkSe1TQKBgAowfQ1Af4mYywGGNbpuxsuMCT8G9FEsmP+BgELpiCJbaXQ650ez\
tjIDlyq04liF1qI0VPmgT+fUQIHbY2fbuurWhMDXCsdvqXzMYAnxCiVfqNFheaUV\
wsLf9X/bxLRioT0ZfAPq25O38Gz1hwbe57kcxyJ/k2FgDlKVHMCFniyjAoGBAKzb\
tDuUfohCImjeb9YBwYzuyujDCQix4ktlphTFoylyTsZKAXM3VNIN+N12fUyXbqr2\
mF9r/pksW9Iuxe22b8wFjnj+z1nXtXBdBkm+cKx/ZtHsfdaStRUf+ZD73lQRT/xZ\
kMk1s9wut8zUpY+uyvmvh+GA09Z1fdiiNKcVH74ZAoGAG0tQQJ9nwWeslzte0yk8\
QvphFHI8/VCOORgmayE+HWYJb5w2Wz8rBRIvIUTOtqp+S197h4QB8E5QSpiSlUNu\
Te2VwMKenvAAhpIbA98qlZtMhjuOrVKuUh4MMypNJrHi/1egalPHChe26G21rmTI\
a3OYNoZKX/8qXG940c+7K10="

const keyVer = '1'
const generateWalmartHeaders = () => {
    
    const hashList = {
        "WM_CONSUMER.ID": consumerId,
        "WM_CONSUMER.INTIMESTAMP": Date.now().toString(),
        "WM_SEC.KEY_VERSION": keyVer,
    };
    const sortedHashString = `${hashList["WM_CONSUMER.ID"]}\n${hashList["WM_CONSUMER.INTIMESTAMP"]}\n${hashList["WM_SEC.KEY_VERSION"]}\n`;
    const signature_enc=0;
    //const signer = new nodeRSA(privateKey,"pkcs1");
    const publicKeyBuffer = Buffer.from(publicKey, 'base64');
    const key = new nodeRSA();
    const signer = key.importKey(privateKey, 'public-der');
    try{
        //const signer = new nodeRSA(privateKey);
        const signature = signer.sign(sortedHashString);
        const signature_enc = signature.toString("base64");
    }
    catch(err){

        console.log("error catched");
    }
     //const signer = new nodeRSA(privateKey, "pkcs1");
     return {
        "WM_SEC.AUTH_SIGNATURE": signature_enc,
        "WM_CONSUMER.INTIMESTAMP": hashList["WM_CONSUMER.INTIMESTAMP"],
        "WM_CONSUMER.ID": hashList["WM_CONSUMER.ID"],
        "WM_SEC.KEY_VERSION": hashList["WM_SEC.KEY_VERSION"],
    
    };
}
(async () => {
    const options = {
        method: 'GET',
        headers: generateWalmartHeaders()
    }
    const response = await fetch('https://developer.api.walmart.com/api-proxy/service/affil/product/v2/search?query=ipod', options);
    const body = await response.text();
    console.log(body);
    return body;
})();
