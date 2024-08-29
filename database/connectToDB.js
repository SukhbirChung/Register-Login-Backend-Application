const mongoose = require('mongoose');
const db_url = process.env.REGISTERLOGIN_DB_URL;

module.exports.connectToDB = async (req, res) => {
    await mongoose.connect(db_url);
}