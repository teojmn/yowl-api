require('dotenv').config();
const express = require('express');
const db = require('./db.js');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware
app.use(express.json());
app.use(cors());
app.use('/uploads', express.static('uploads')); // Rendre les fichiers accessibles publiquement

//------------------------------------------
// Middleware pour vérifier le token JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1]; // Récupère le token après "Bearer"

  if (!token) return res.status(401).json({ error: 'Token manquant' });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: 'Token invalide' });

    console.log('decoded:', decoded); // Log decoded token
    req.user = decoded;
    next();
  });
};


//------------------------------------------
// Configuration de Multer pour l'upload de fichiers
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads');
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'video/mp4', 'video/mov'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Format de fichier non supporté'), false);
    }
  }
});

//------------------------------------------
// Lancer le serveur
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Serveur lancé sur \x1b[36m%s\x1b[0m`, `http://16.171.155.129:${PORT}`);
});

//------------------------------------------
// Route test 
app.get('/test', (req, res) => {
  res.send('Hello World!');
});


//------------------------------------------
// Route pour créer un utilisateur (register)
app.post('/register', (req, res) => {
  const { username, password, email } = req.body;

  if (!username || !password || !email) {
    return res.status(400).json({ error: 'Tous les champs sont requis.' });
  }

  db.query('SELECT * FROM USERS WHERE username = ?', [username], (err, results) => {
    if (err) return res.status(500).json({ error: 'Erreur interne.' });

    if (results.length > 0) return res.status(409).json({ error: 'Le username est déjà utilisé.' });

    db.query('SELECT * FROM USERS WHERE email = ?', [email], (err, results) => {
      if (err) return res.status(500).json({ error: 'Erreur interne.' });

      if (results.length > 0) return res.status(409).json({ error: 'L\'email est déjà utilisé.' });

      bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) return res.status(500).json({ error: 'Erreur interne.' });

        db.query('INSERT INTO USERS (username, password, email) VALUES (?, ?, ?)',
          [username, hashedPassword, email], (err, results) => {
            if (err) return res.status(500).json({ error: 'Erreur interne.' });

            res.status(201).json({ message: 'Utilisateur créé avec succès.', userId: results.insertId, username});
          });
      });
    });
  });
});

//------------------------------------------
// Route pour se connecter (login)
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.query('SELECT * FROM USERS WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).json({ error: 'Erreur interne' });

    if (results.length === 0) return res.status(404).json({ error: 'Utilisateur non trouvé' });

    const user = results[0];

    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) return res.status(500).json({ error: 'Erreur de vérification' });

      if (!isMatch) return res.status(401).json({ error: 'Mot de passe incorrect' });

      console.log('Creating token for user:', user); // Log user details

      const token = jwt.sign({ id: user.user_id, email: user.email, role: user.role }, JWT_SECRET);

      res.json({ token });
    });
  });
});


//------------------------------------------
// Route pour uploader une image ou vidéo
app.post('/upload', verifyToken, upload.single('file'), (req, res) => {
  const userId = req.user.id; // Récupération automatique via le token JWT

  // Vérifier si l'utilisateur existe dans la base de données
  db.query('SELECT user_id FROM USERS WHERE user_id = ?', [userId], (err, results) => {
    if (err) {
      console.error('Erreur lors de la recherche de l\'utilisateur :', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }
    if (results.length === 0) {
      console.error('Utilisateur non trouvé pour userId :', userId);
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    // Si l'utilisateur existe, on continue avec l'upload
    const filename = req.file.filename;
    const filetype = req.file.mimetype;
    const filepath = `/uploads/${filename}`;

    console.log('Données à insérer dans MEDIAS :', { userId, filename, filetype, filepath });

    // Insérer les données dans la table MEDIAS
    const insertMediaQuery = 'INSERT INTO MEDIAS (user_id, filename, filetype, filepath) VALUES (?, ?, ?, ?)';
    db.query(insertMediaQuery, [userId, filename, filetype, filepath], (err, result) => {
      if (err) {
        console.error('Erreur lors de l\'insertion du média :', err);
        return res.status(500).json({ error: 'Erreur lors de l\'insertion du média' });
      }

      console.log('Résultat de l\'insertion du média :', result);
      res.status(201).json({ message: 'Média uploadé avec succès', mediaId: result.insertId });
    });
  });
});

//------------------------------------------
// Route pour récupérer les médias d'un utilisateur
app.get('/media/:user_id', verifyToken, (req, res) => {
  const { user_id } = req.params;

  console.log('Requête pour récupérer les médias de l\'utilisateur avec user_id:', user_id);

  db.query('SELECT * FROM MEDIAS WHERE user_id = ?', [user_id], (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération des médias :', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }

    console.log('Résultats de la requête:', results);

    if (results.length === 0) return res.status(404).json({ error: 'Aucun média trouvé pour cet utilisateur' });

    res.status(200).json(results);
  });
});

//------------------------------------------
// Route pour récupérer un fichier média par son nom de fichier
app.get('/media/file/:filename', (req, res) => {
  const { filename } = req.params;
  const filepath = path.join(__dirname, 'uploads', filename);

  res.sendFile(filepath, (err) => {
    if (err) {
      res.status(404).json({ error: 'Fichier introuvable' });
    }
  });
});


// Route pour récupérer un fichier média par son id_media
app.get('/media/id/:id_media', (req, res) => {
  const { id_media } = req.params;

  // Rechercher le média dans la base de données
  db.query('SELECT * FROM MEDIAS WHERE id_media = ?', [id_media], (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération du média :', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Média non trouvé' });
    }

    const media = results[0];
    const filepath = path.join(__dirname, media.filepath);

    // Envoyer le fichier média
    res.sendFile(filepath, (err) => {
      if (err) {
        res.status(404).json({ error: 'Fichier introuvable' });
      }
    });
  });
});


//------------------------------------------
// Routes posts textuels

// Route pour récupérer tous les posts textuels
app.get('/posts-txt', (req, res) => {
  const page = parseInt(req.query.page, 10) || 1; // Page par défaut : 1
  const limit = parseInt(req.query.limit, 10) || 10; // Limite par défaut : 10 posts par requête
  const offset = (page - 1) * limit;

  const query = 'SELECT * FROM POST_TXT';
  const queryParams = [limit, offset];

  db.query(query, queryParams, (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération des posts:', err);
      return res.status(500).json({ error: 'Erreur lors de la récupération des posts' });
    }

    // Vérifie s'il reste encore des posts à charger
    const nextPage = results.length === limit ? page + 1 : null;

    res.json({ posts: results, nextPage });
  });
});

// Route pour récupérer un post textuel par son ID
app.get('/posts-txt/:id', (req, res) => {
  const postId = req.params.id;

  if (!postId) {
    return res.status(400).json({ error: 'ID du post requis' });
  }

  const query = 'SELECT * FROM POST_TXT WHERE post_txt_id = ?';
  db.query(query, [postId], (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération du post:', err);
      return res.status(500).json({ error: 'Erreur lors de la récupération du post' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Post non trouvé' });
    }

    res.json(results[0]);
  });
});

// Route pour créer un post textuel
app.post('/posts-txt', verifyToken, (req, res) => {
  const { text, description } = req.body;

  if (!text || !description) {
    return res.status(400).json({ error: 'Les champs text et description sont requis' });
  }

  const userId = req.user.id; // Récupérer l'ID de l'utilisateur à partir du token JWT
  console.log('userId:', userId); // Log userId

  const getUserQuery = 'SELECT username FROM USERS WHERE user_id = ?';
  db.query(getUserQuery, [userId], (err, userResults) => {
    if (err) {
      console.error('Erreur lors de la récupération du username:', err);
      return res.status(500).json({ error: 'Erreur lors de la récupération du username' });
    }

    console.log('userResults:', userResults); // Log userResults

    if (userResults.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    const username = userResults[0].username;

    const insertPostQuery = 'INSERT INTO POST_TXT (text, description, user_id, username, likes) VALUES (?, ?, ?, ?, 0)';
    db.query(insertPostQuery, [text, description, userId, username], (err, results) => {
      if (err) {
        console.error('Erreur lors de la création du post:', err);
        return res.status(500).json({ error: 'Erreur lors de la création du post' });
      }

      res.status(201).json({
        message: 'Post créé avec succès',
        postId: results.insertId,
      });
    });
  });
});

// Route pour ajouter un like à un post textuel
app.post('/posts-txt/:id/like', verifyToken, (req, res) => {
  const postId = req.params.id;
  const userId = req.user.id; // Récupérer l'ID de l'utilisateur à partir du token JWT

  // Vérifier si le post existe
  db.query('SELECT * FROM POST_TXT WHERE post_txt_id = ?', [postId], (err, results) => {
    if (err) {
      console.error('Erreur lors de la vérification du post:', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Post non trouvé' });
    }

    // Ajouter un like au post
    db.query('UPDATE POST_TXT SET likes = likes + 1 WHERE post_txt_id = ?', [postId], (err, results) => {
      if (err) {
        console.error('Erreur lors de l\'ajout du like:', err);
        return res.status(500).json({ error: 'Erreur interne' });
      }

      res.status(200).json({ message: 'Like ajouté avec succès' });
    });
  });
});


//------------------------------------------
// Routes posts medias

// Route pour créer un post media
app.post('/posts-media', verifyToken, upload.single('file'), (req, res) => {
  const { description } = req.body;

  if (!description) {
    return res.status(400).json({ error: 'Le champ description est requis' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'Un fichier est requis' });
  }

  const userId = req.user.id; // Récupération automatique via le token JWT
  console.log('userId:', userId);

  const getUserQuery = 'SELECT username FROM USERS WHERE user_id = ?';
  db.query(getUserQuery, [userId], (err, userResults) => {
    if (err) {
      console.error('Erreur lors de la récupération du username:', err);
      return res.status(500).json({ error: 'Erreur lors de la récupération du username' });
    }

    if (userResults.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    const username = userResults[0].username;

    const filename = req.file.filename;
    const filetype = req.file.mimetype;
    const filepath = `/uploads/${filename}`;

    console.log('Données à insérer dans MEDIAS :', { userId, filename, filetype, filepath });

    // Insérer le fichier dans la table MEDIAS
    db.query('INSERT INTO MEDIAS (user_id, filename, filetype, filepath) VALUES (?, ?, ?, ?)',
      [userId, filename, filetype, filepath], (err, mediaResult) => {
        if (err) {
          console.error('Erreur lors de l\'insertion du média:', err);
          return res.status(500).json({ error: 'Erreur lors de l\'upload' });
        }

        const id_media = mediaResult.insertId;

        // Insérer le post média dans POST_MEDIA
        db.query('INSERT INTO POST_MEDIA (id_media, description, username, user_id) VALUES (?, ?, ?, ?)',
          [id_media, description, username, userId], (err, postResult) => {
            if (err) {
              console.error('Erreur lors de la création du post média:', err);
              return res.status(500).json({ error: 'Erreur lors de la création du post' });
            }

            res.status(201).json({
              message: 'Post média créé avec succès',
              postMediaId: postResult.insertId,
            });
          });
      });
  });
});


//------------------------------------------
// Routes articles

// Route pour récupérer tous les articles
app.get('/articles', (req, res) => {
  const page = parseInt(req.query.page, 10) || 1; // Page par défaut : 1
  const limit = parseInt(req.query.limit, 10) || 10; // Limite par défaut : 10 articles par requête
  const offset = (page - 1) * limit;

  const query = 'SELECT * FROM ARTICLES';
  const queryParams = [limit, offset];

  db.query(query, queryParams, (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération des articles:', err);
      return res.status(500).json({ error: 'Erreur lors de la récupération des articles' });
    }

    // Vérifie s'il reste encore des articles à charger
    const nextPage = results.length === limit ? page + 1 : null;

    res.json({ articles: results, nextPage });
  });
});

// Route pour récupérer un article par son ID
app.get('/articles/:id', (req, res) => {
  const articleId = req.params.id;

  if (!articleId) {
    return res.status(400).json({ error: 'ID de l\'article requis' });
  }

  const query = 'SELECT * FROM ARTICLES WHERE id_article = ?';
  db.query(query, [articleId], (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération de l\'article:', err);
      return res.status(500).json({ error: 'Erreur lors de la récupération de l\'article' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Article non trouvé' });
    }

    res.json(results[0]);
  });
});

// Route pour créer un article
app.post('/articles', verifyToken, upload.single('file'), (req, res) => {
  const { titre, description, corps, sport, date } = req.body;

  if (!titre || !description || !corps || !sport || !date) {
    return res.status(400).json({ error: 'Les champs titre, description, corps, sport et date sont requis' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'Un fichier est requis' });
  }

  const userId = req.user.id; // Récupération automatique via le token JWT

  // Récupérer le username de l'utilisateur
  const getUserQuery = 'SELECT username FROM USERS WHERE user_id = ?';
  db.query(getUserQuery, [userId], (err, userResults) => {
    if (err) {
      console.error('Erreur lors de la récupération du username:', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }

    if (userResults.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    const username = userResults[0].username;
    const filename = req.file.filename;
    const filetype = req.file.mimetype;
    const filepath = `/uploads/${filename}`;

    console.log('Données à insérer dans MEDIAS :', { userId, filename, filetype, filepath });

    // Insérer le fichier dans la table MEDIAS
    db.query('INSERT INTO MEDIAS (user_id, filename, filetype, filepath) VALUES (?, ?, ?, ?)',
      [userId, filename, filetype, filepath], (err, mediaResult) => {
        if (err) {
          console.error('Erreur lors de l\'insertion du média:', err);
          return res.status(500).json({ error: 'Erreur lors de l\'upload du média' });
        }

        const id_media = mediaResult.insertId;

        // Insérer l'article dans ARTICLES
        db.query('INSERT INTO ARTICLES (titre, description, corps, sport, date, id_media, auteur) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [titre, description, corps, sport, date, id_media, username], (err, articleResult) => {
            if (err) {
              console.error('Erreur lors de la création de l\'article:', err);
              return res.status(500).json({ error: 'Erreur lors de la création de l\'article' });
            }

            res.status(201).json({
              message: 'Article et média créés avec succès',
              articleId: articleResult.insertId,
              mediaId: id_media
            });
          });
      });
  });
});


//------------------------------------------
// Routes events

// Route pour récupérer tous les events
app.get('/events', (req, res) => {
  const page = parseInt(req.query.page, 10) || 1; // Page par défaut : 1
  const limit = parseInt(req.query.limit, 10) || 10; // Limite par défaut : 10 events par requête
  const offset = (page - 1) * limit;

  const query = 'SELECT * FROM EVENTS';
  const queryParams = [limit, offset];

  db.query(query, queryParams, (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération des events:', err);
      return res.status(500).json({ error: 'Erreur lors de la récupération des events' });
    }

    // Vérifie s'il reste encore des events à charger
    const nextPage = results.length === limit ? page + 1 : null;

    res.json({ events: results, nextPage });
  });
});

// Route pour récupérer un event par son ID
app.get('/events/:id', (req, res) => {
  const eventId = req.params.id;

  if (!eventId) {
    return res.status(400).json({ error: 'ID de l\'event requis' });
  }

  const query = 'SELECT * FROM EVENTS WHERE id_event = ?';
  db.query(query, [eventId], (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération de l\'event:', err);
      return res.status(500).json({ error: 'Erreur lors de la récupération de l\'event' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Event non trouvé' });
    }

    res.json(results[0]);
  });
});

// Route pour créer un event 
app.post('/events', verifyToken, upload.single('file'), (req, res) => {
  const { name, date, lieu, sport, genre, nb_participants_max,  description } = req.body;

  if (!name || !date || !lieu || !sport || !genre || !nb_participants_max  || !description) {
    return res.status(400).json({ error: 'Les champs name, date, lieu, sport, genre, nb_participants_max et description sont requis' });
  }

  if (!req.file) {
    return res.status(400).json({ error: 'Un fichier est requis' });
  }

  const userId = req.user.id; // Récupération automatique via le token JWT

  // Récupérer le username de l'utilisateur
  const getUserQuery = 'SELECT username FROM USERS WHERE user_id = ?';
  db.query(getUserQuery, [userId], (err, userResults) => {
    if (err) {
      console.error('Erreur lors de la récupération du username:', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }

    if (userResults.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    const username = userResults[0].username;
    const filename = req.file.filename;
    const filetype = req.file.mimetype;
    const filepath = `/uploads/${filename}`;

    console.log('Données à insérer dans MEDIAS :', { userId, filename, filetype, filepath });

    // Insérer le fichier dans la table MEDIAS
    db.query('INSERT INTO MEDIAS (user_id, filename, filetype, filepath) VALUES (?, ?, ?, ?)',
      [userId, filename, filetype, filepath], (err, mediaResult) => {
        if (err) {
          console.error('Erreur lors de l\'insertion du média:', err);
          return res.status(500).json({ error: 'Erreur lors de l\'upload du média' });
        }

        const id_media = mediaResult.insertId;

    // Insérer l'event dans EVENTS
    db.query('INSERT INTO EVENTS (user_id, username, name, date, lieu, sport, genre, nb_participants_max, description, id_media) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [userId, username, name, date, lieu, sport, genre, nb_participants_max, description, id_media], (err, eventResult) => {
        if (err) {
          console.error('Erreur lors de la création de l\'event:', err);
          return res.status(500).json({ error: 'Erreur lors de la création de l\'event' });
        }

        res.status(201).json({
          message: 'Event et média créés avec succès',
          eventId: eventResult.insertId,
          mediaId: id_media
        });
      });
    });
  });
});

//Route pour modifier un event
app.put('/events/:id', verifyToken, (req, res) => {
  const eventId = req.params.id;
  const { name, date, lieu, sport, genre, nb_participants_max, description } = req.body;

  if (!name || !date || !lieu || !sport || !genre || !nb_participants_max || !description) {
    return res.status(400).json({ error: 'Les champs name, date, lieu, sport, genre, nb_participants_max et description sont requis' });
  }

  const userId = req.user.id; // Récupération automatique via le token JWT

  // Récupérer le username de l'utilisateur
  const getUserQuery = 'SELECT username FROM USERS WHERE user_id = ?';
  db.query(getUserQuery, [userId], (err, userResults) => {
    if (err) {
      console.error('Erreur lors de la récupération du username:', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }

    if (userResults.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    const username = userResults[0].username;

    // Insérer l'event dans EVENTS
    db.query('UPDATE EVENTS SET name = ?, date = ?, lieu = ?, sport = ?, genre = ?, nb_participants_max = ?, description = ? WHERE id_event = ? AND user_id = ?',
      [name, date, lieu, sport, genre, nb_participants_max, description, eventId, userId], (err, eventResult) => {
        if (err) {
          console.error('Erreur lors de la modification de l\'event:', err);
          return res.status(500).json({ error: 'Erreur lors de la modification de l\'event' });
        }

        res.status(200).json({
          message: 'Event modifié avec succès',
          eventId: eventId
        });
      });
    });
});

//Route pour supprimer un event
app.delete('/events/:id', verifyToken, (req, res) => {
  const eventId = req.params.id;

  const userId = req.user.id; // Récupération automatique via le token JWT

  // Supprimer l'event dans EVENTS
  db.query('DELETE FROM EVENTS WHERE id_event = ? AND user_id = ?',
    [eventId, userId], (err, eventResult) => {
      if (err) {
        console.error('Erreur lors de la suppression de l\'event:', err);
        return res.status(500).json({ error: 'Erreur lors de la suppression de l\'event' });
      }

      res.status(200).json({
        message: 'Event supprimé avec succès',
        eventId: eventId
      });
    });
});


// Route pour ajouter un participant à un événement
app.post('/events/:id/participants', verifyToken, (req, res) => {
  const eventId = req.params.id;
  const userId = req.user.id; // Récupération automatique de l'utilisateur connecté via le token JWT

  // Vérifier si l'événement existe
  db.query('SELECT * FROM EVENTS WHERE id_event = ?', [eventId], (err, eventResults) => {
    if (err) {
      console.error('Erreur lors de la récupération de l\'événement:', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }

    if (eventResults.length === 0) {
      return res.status(404).json({ error: 'Événement non trouvé' });
    }

    // Vérifier si l'utilisateur est déjà inscrit
    db.query('SELECT * FROM EVENT_PARTICIPANTS WHERE event_id = ? AND user_id = ?', [eventId, userId], (err, participantResults) => {
      if (err) {
        console.error('Erreur lors de la vérification du participant:', err);
        return res.status(500).json({ error: 'Erreur interne' });
      }

      if (participantResults.length > 0) {
        return res.status(400).json({ error: 'Utilisateur déjà inscrit à cet événement' });
      }

      // Vérifier le nombre maximal de participants
      const { nb_participants_max } = eventResults[0];

      db.query('SELECT COUNT(*) AS count FROM EVENT_PARTICIPANTS WHERE event_id = ?', [eventId], (err, countResults) => {
        if (err) {
          console.error('Erreur lors du comptage des participants:', err);
          return res.status(500).json({ error: 'Erreur interne' });
        }

        const currentParticipants = countResults[0].count;

        if (currentParticipants >= nb_participants_max) {
          return res.status(400).json({ error: 'Le nombre maximal de participants est atteint' });
        }

        // Ajouter l'utilisateur à l'événement
        db.query('INSERT INTO EVENT_PARTICIPANTS (event_id, user_id) VALUES (?, ?)', [eventId, userId], (err) => {
          if (err) {
            console.error('Erreur lors de l\'ajout du participant:', err);
            return res.status(500).json({ error: 'Erreur interne' });
          }

          res.status(201).json({ message: 'Utilisateur ajouté à l\'événement avec succès' });
        });
      });
    });
  });
});

// Route pour récupérer les participants d'un événement
app.get('/events/:id/participants', (req, res) => {
  const eventId = req.params.id;

  db.query(`
    SELECT u.user_id, u.username 
    FROM USERS u
    JOIN EVENT_PARTICIPANTS ep ON u.user_id = ep.user_id
    WHERE ep.event_id = ?
  `, [eventId], (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération des participants:', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }

    res.json({ participants: results });
  });
});


// Route pour supprimer un participant d'un événement
app.delete('/events/:id/participants', verifyToken, (req, res) => {
  const eventId = req.params.id;
  const userId = req.user.id;

  db.query('DELETE FROM EVENT_PARTICIPANTS WHERE event_id = ? AND user_id = ?', [eventId, userId], (err, result) => {
    if (err) {
      console.error('Erreur lors du retrait du participant:', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Participant non trouvé' });
    }

    res.json({ message: 'Utilisateur retiré de l\'événement avec succès' });
  });
});

// Route pour récupérer le nombre de participants d'un évènement et le nombre_max de participants
app.get('/events/:id/participants/count', (req, res) => {
  const eventId = req.params.id;

  db.query('SELECT COUNT(*) AS count FROM EVENT_PARTICIPANTS WHERE event_id = ?', [eventId], (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération du nombre de participants:', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }

    db.query('SELECT nb_participants_max FROM EVENTS WHERE id_event = ?', [eventId], (err, maxResults) => {
      if (err) {
        console.error('Erreur lors de la récupération du nombre maximal de participants:', err);
        return res.status(500).json({ error: 'Erreur interne' });
      }

      res.json({ participants: results[0].count, maxParticipants: maxResults[0].nb_participants_max });
    });
  });
});

//------------------------------------------
// Routes sports

// Route pour récupérer tous les sports (noms et id)
app.get('/sports', (req, res) => {
  const query = 'SELECT id_sport, name FROM SPORTS';

  db.query(query, (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération des sports:', err);
      return res.status(500).json({ error: 'Erreur lors de la récupération des sports' });
    }

    res.json(results);
  });
});

// Route pour récupérer un sport par son ID
app.get('/sports/:id', (req, res) => {
  const sportId = req.params.id;

  if (!sportId) {
    return res.status(400).json({ error: 'ID du sport requis' });
  }

  const query = 'SELECT * FROM SPORTS WHERE id_sport = ?';
  db.query(query, [sportId], (err, results) => {
    if (err) {
      console.error('Erreur lors de la récupération du sport:', err);
      return res.status(500).json({ error: 'Erreur lors de la récupération du sport' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'Sport non trouvé' });
    }

    res.json(results[0]);
  });
});


//------------------------------------------
// Route pour créer un profil (étape 1 sur 2)
app.post('/profil-1-2', upload.single('photo_profil'), (req, res) => {
  console.log("🚀 Requête reçue sur /profil-1-2 !");
  console.log("Body reçu:", req.body);
  console.log("Fichier reçu:", req.file);

  const { username, sports_pratiques } = req.body;

  if (!req.file) {
    console.log("❌ Aucune image reçue !");
  }
  if (!req.body.username || !req.body.sports_pratiques) {
    console.log("❌ Données manquantes :", req.body);
    return res.status(400).json({ error: 'Username et sports_pratiques sont requis' });
  }

  if (!username || !sports_pratiques) {
    return res.status(400).json({ error: 'Username et sports_pratiques sont requis' });
  }

  let parsedSportsPratiques;
  try {
    parsedSportsPratiques = JSON.parse(sports_pratiques);
  } catch (error) {
    return res.status(400).json({ error: 'sports_pratiques doit être un tableau JSON valide' });
  }

  let photo_profil = null;
  if (req.file) {
    photo_profil = `/uploads/${req.file.filename}`;
  }

  // Récupérer l'user_id à partir de l'username
  const getUserQuery = 'SELECT user_id FROM USERS WHERE username = ?';
  db.query(getUserQuery, [username], (err, userResults) => {
    if (err) {
      console.error('Erreur lors de la récupération de l\'user_id:', err);
      return res.status(500).json({ error: 'Erreur interne' });
    }

    if (userResults.length === 0) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    const user_id = userResults[0].user_id;

    const insertMediaQuery = `
      INSERT INTO MEDIAS (filepath, user_id) VALUES (?, ?)
    `;

    db.query(insertMediaQuery, [photo_profil, user_id], (err, mediaResults) => {
      if (err) {
        console.error('Erreur lors de l\'insertion du média:', err);
        return res.status(500).json({ error: 'Erreur lors de l\'insertion du média' });
      }

      const mediaId = mediaResults.insertId;

      const insertProfileQuery = `
        INSERT INTO PROFIL (username, photo_profil, sports_pratiqués) VALUES (?, ?, ?)
      `;

      db.query(insertProfileQuery, [username, mediaId, JSON.stringify(parsedSportsPratiques)], (err, profileResults) => {
        if (err) {
          console.error('Erreur lors de la création du profil:', err);
          return res.status(500).json({ error: 'Erreur lors de la création du profil' });
        }

        res.status(201).json({ message: 'Profil créé avec succès', profilId: profileResults.insertId });
      });
    });
  });
});

// Route pour créer un profil (étape 2 sur 2)
app.put('/profil-2-2/', (req, res) => {
  const { sports_suivis, username} = req.body;

  if (!username) {
    return res.status(400).json({ error: 'Username requis' });
  }

  const query = 'UPDATE PROFIL SET sports_suivis = ? WHERE username = ?';
  db.query(query, [JSON.stringify(sports_suivis), username], (err, results) => {
    if (err) {
      console.error('Erreur lors de la mise à jour du profil:', err);
      return res.status(500).json({ error: 'Erreur lors de la mise à jour du profil' });
    }

    res.status(200).json({ message: 'Profil mis à jour avec succès' });
  });
});