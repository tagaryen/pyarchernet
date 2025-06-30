
const http = require('http');

function createServer() {

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
                data: 'Hello World! This is a long text\nkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;;;;;;;;;;;;;;;;;;;;;;;aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaawwwwwwwwwwwwwwwwwwwwwwwwwwwwwoooooooooooooooooooooooooooooooooooooooooooooqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqddddddddddddddddddddddddddddddddddddddddddddddddddddddddddioooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiffffffffffffffffffffffffffffflllllllllllllllllllllllxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            }));
        });
        req.on('error', (ex) => {
            console.log(ex)
        })
    });

    server.on("error", (err) => {
        console.log(err)
    })

    server.listen(8080, "127.0.0.1", () => {
        console.log("listen success")
    });
}

createServer()