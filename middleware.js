const axios = require('axios');
const nodemailer_url = process.env.NODEMAILER;

module.exports.sendEmail = async (req, res) => {
    const url = `${nodemailer_url}/sendResetLink`;
    const dataToBeSent = {
        email: req.body.email,
        resetToken: req.resetToken
    }

    const options = {
        method: 'POST',
        url: url,
        data: dataToBeSent
    }

    await axios.request(options)
        .then((response) => {
            return res.status(200).send(response.data);
        })
        .catch((err) => {
            return res.status(500).send(err.response.data);
        });
}