// backend/index.js
const express = require('express');
const kyber = require('crystals-kyber');
const cors = require('cors');
const aes_gcm = require("./aes_gsm");
const { v4: uuidv4 } = require('uuid');
const { encrypt } = require('./aes_gsm');

const app = express();
app.use(cors());
app.use(express.json());

let keyPair = null;
let uuid = uuidv4();
let sharedSecret = null;

app.post('/start_proccess', async (req, res) => {
    keyPair = KeyGen512()
    let publicKeyBytes = keyPair[0]; //Public Key
    let privateKeyBytes = keyPair[1]; //Secret Key;

    try {
        const response = await fetch('http://localhost:8080/kyber/auth', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ pkClient: Buffer.from(publicKeyBytes).toString("base64"), clientId: uuid })
        })

        const data = await response.json()
        const ciphertext = data.ciphertext;
        let encapsulated = base64ToUint8Array(ciphertext);

        console.log("Ciphertext Recibido del Servidor => " + ciphertext)
        sharedSecret = kyber.Decrypt512(encapsulated, privateKeyBytes);

        let strSharedSecret = Buffer.from(sharedSecret).toString('base64');
        console.log("SharedSecret Descrypted En Cliente => " + strSharedSecret)
        res.json({ sharedSecret: strSharedSecret });

    } catch (err) {
        res.json({ sharedSecret: null });
        console.error('Error al iniciar el proceso Kyber:', err)
    }

});

app.post('/sendMessage', async (req, res) => {
    const { message } = req.body;

    let encryptado = aes_gcm.encrypt(message, sharedSecret);

    try {
        const response = await fetch('http://localhost:8080/kyber/message', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message: encryptado, clientId: uuid })
        })

        const data = await response.json()
        const responseMessage = data.responseMessage;

        res.json({ serverMessage: responseMessage });
    } catch (err) {
        res.json({ serverMessage: "Error al comunicarse con el servidor" });
        console.error('Error al iniciar el proceso Kyber:', err)
    }
});

// // Cualquier otra ruta debe devolver el index.html del React
app.use(express.static(__dirname + '/frontend'));

app.listen(4000, () => {
    console.log('Kyber server running on http://localhost:4000');
});

function base64ToUint8Array(base64, print = false) {
    let x = Buffer.from(base64, 'base64'); // Convierte Base64 a Buffer
    if (print) {
        console.log(x);
    }
    return new Uint8Array(x); // Convierte Buffer a Uint8Array
}