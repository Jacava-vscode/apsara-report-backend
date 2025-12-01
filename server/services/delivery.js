const nodemailer = require('nodemailer');

// Simple SMTP transport using env variables SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.example.com',
  port: parseInt(process.env.SMTP_PORT || '587', 10),
  secure: false,
  auth: {
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || ''
  }
});

async function sendEmail({ to, subject, html, text }) {
  if (!transporter) {
    throw new Error('Email transport not configured');
  }
  const mailOptions = {
    from: process.env.SMTP_FROM || 'no-reply@example.com',
    to: Array.isArray(to) ? to.join(',') : to,
    subject,
    html,
    text
  };
  return transporter.sendMail(mailOptions);
}

module.exports = { sendEmail };
