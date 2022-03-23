const verifySign = require('../utils').verifySign

verifySign('./signed_mail.eml').then(succ => console.log("verify sign " + (succ ? "succ" : "failed")));