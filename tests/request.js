
const http = require('http');


function testLogReport() {
    let param = {
        hostname: '127.0.0.1',
        port: 9607,
        path: '/cascade/v1.0/publicEntrance/publicEntranceInterfaceTransfer?asd=kasd&asdjsad=&jsdasd=',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
    };
    let req = http.request(param, (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
            body += chunk;
        });
        res.on('end', () => {
            console.log(body);
        });
    });
    req.on('error', (err) => {
        console.log(err);
    })

    let body = {
        "interfaceCode": "LXJFCWSBJK", 
        "body": {
            "category": "PIR",
            "workspaceId": "2025061100010400000638",
            "productId": "test_product",
            "productName": "test_product",
            "desc": "test_product",
            "serviceUrlUsable": true,
            "productType": "PIR",
            "serviceType": "隐匿查询",
            "publishTime": "1708125362323",
            "thirdPartyId": "000",
            "productInstId": "JG0200010400130700",
            "type": "api",
            "key": "blueelephant1232123121",
            "name": "blueelephant2",
            "operation": 'Hello World!askanfdkjsnfdqjfansfjakjkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;;;;;;;;;;;;;;;;;;;;;;;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwwwwwwwwwwwwwwoooooooooooooooooooooooooooooooooooooooooooooqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqddddddddddddddddddddddddddddddddddddddddddddddddddddddddddioooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiffffffffffffffffffffffffffffflllllllllllllllllllllllxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            "detail": {
              "apiMc": "PIR服务api",
              "apiLxMc": "外部系统接口",
              "sszz": "冰雪组织",
              "gxsj": "1708125362323",
              "cjr": "冰雪",
              "kzcl": "[{\"value\": \"10.32.28.10\",\"key\": \"refererWhitelist\",\"field\": \"refererWhitelist\",\"valueDesc\": \"10.32.28.10\",\"label\": \"Referer白名单\"}]",
              "apiPath": "http://10.32.23.11:8999/test/api",
              "apiUrl": "/test/api",
              "qqxy": "HTTPS",
              "qqfs": "POST",
              "fhlx": "JSON",
              "qqsl": "{}",
              "fhsl": "{}"
            }
          }
    };
    req.write(JSON.stringify(body));
    req.end();
}

function doserver() {

    let server = http.createServer((req, res) => {
        let body = ""
        req.on('data', (chunk) => {
            body += chunk;
        });
        req.on('end', () => {
            try {
                body = JSON.parse(body); 
            } catch(ex) {
                console.error(ex);
                body = {};
            }
			console.log('url:', req.url);
			console.log('body:', body);

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                data: 'Hello World!askanfdkjsnfdqjfansfjakjkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;;;;;;;;;;;;;;;;;;;;;;;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwwwwwwwwwwwwwwoooooooooooooooooooooooooooooooooooooooooooooqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqddddddddddddddddddddddddddddddddddddddddddddddddddddddddddioooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiffffffffffffffffffffffffffffflllllllllllllllllllllllxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            }));
        });
        req.on('error', (ex) => {
            console.log(ex)
        })
    });

    server.on("error", (err) => {
        console.log(err)
    })

    server.listen(9601, "127.0.0.1", () => {
        console.log("listen success")
    });
}
// doserver()

testLogReport();