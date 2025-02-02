const mysql = require('mysql2');
 
// Configurer les détails de la base de données
const db = mysql.createConnection({
  host: 'yowl.cv4y86yiqy7u.eu-north-1.rds.amazonaws.com', // Ou l'adresse IP du serveur de la base de données
  port : 3306, 
  user: 'root',
  password: 'MUcJ5?7BUnJdt94Azu!d',
  database: 'yowl'
});
 
// Vérifier la connexion
db.connect((err) => {
  if (err) {
    console.error('Erreur de connexion à la base de données :', err);
  } else {
    console.log('Connecté à la base de données MySQL !');
  }
});
 
module.exports = db;