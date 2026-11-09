require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { initDB } = require('./api/db');
const routes = require('./api/routes');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Statički fajlovi iz strukture projekta
app.use('/css', express.static(path.join(__dirname, 'css')));
app.use('/html', express.static(path.join(__dirname, 'html')));
app.get('/script1.js', (req, res) => res.sendFile(path.join(__dirname, 'script1.js')));
app.get('/favicon.svg', (req, res) => res.sendFile(path.join(__dirname, 'favicon.svg')));

// API rute
app.use('/api', routes);

// Početna stranica
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Pokretanje
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server pokrenut na http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('❌ Greška pri inicijalizaciji baze:', err);
  process.exit(1);
});