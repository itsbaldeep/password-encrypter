// Dependencies
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

// This function encrypts the password
async function generate(password) {
    const salt = await bcrypt.genSalt(10);
    return await bcrypt.hash(password, salt);
}

// Creating a strong random alphanumeric password
const length = 12;
const password = crypto.randomBytes(length).toString("hex");
console.log(`Password: ${password}`);

// Encrypting the password and then printing it
generate(password).then((hashed) => console.log(`Hashed password: ${hashed}`));
