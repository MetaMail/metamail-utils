const simpleParser = require('mailparser').simpleParser;
const fsPromises = require('fs').promises;
const crypto = require('crypto'); 
const ethSigUtils = require('@metamask/eth-sig-util');

const concatAddress = (item) => item.name + " " + "<" + item.address + ">";

const metaPack = (from, to, cc, date, subject, text_hash, html_hash, attachments_hash, keys=null) => {
    let parts = [
        "From: " + concatAddress(from),
        "To: " + to.map(concatAddress).join(", "),
    ];
    if (cc.length >= 1) {
        parts.push( "Cc: " + cc.map(concatAddress).join(", "));
    }
    parts = parts.concat([
        "Date: " + date.toISOString(),
        "Subject: " + subject,
        "Content-Hash: " + text_hash + " " + html_hash,
        "Attachments-Hash: " + attachments_hash.join(" ")
    ]);
    if (keys) {
        parts.push("Keys: " + keys.join(" "))
    }
    return parts.join("\n");
}

const verifySign = async (eml_file) => {
    const data = await fsPromises.readFile(eml_file);
    let parsed = await simpleParser(data);

    let sign_header = parsed.headers.get('x-metamail');
    let sign_map = {};
    sign_header.split('; ').map(l => {
        let [key, val] = l.split('=');
        sign_map[key] = val;
    });

    const addr = sign_map.addr;
    const sig = sign_map.sig;
    const date = new Date(sign_map.date);
    if (!addr || !sig) {
        return false;
    }
    
    const from = parsed.from.value[0];
    const to = parsed.to.value;
    const cc = parsed.cc ? parsed.cc.value : [];
    const subject = parsed.subject;
    const text_hash = crypto.createHash("sha256").update(parsed.text).digest("hex");
    const html_hash = crypto.createHash("sha256").update(parsed.html).digest("hex");
    let attachments_hash = [];
    if (parsed.attachments) {
        parsed.attachments.map(attach => {
            const sha256 = crypto.createHash('sha256')
                            .update(attach.content)
                            .digest('hex').toLowerCase();
            attachments_hash.push(sha256);
        });
    }

    const sign_data = metaPack(from, to, cc, date, subject, text_hash, html_hash, attachments_hash);

    const recoveredAddr = ethSigUtils.recoverPersonalSignature({
        data: sign_data,
        signature: sig,
    });

    if (recoveredAddr !== addr) {
        return false;
    }

    return true
}


module.exports = { metaPack, verifySign }