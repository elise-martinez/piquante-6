const bcrypt = require('bcrypt'); // package de chiffrement
const User = require('../models/User'); // modele user
const jwt = require('jsonwebtoken'); // token generator package
const emailValidator = require('email-validator');// email validator package
const passwordValidator = require('password-validator'); // password validation package

const passwordSchema = new passwordValidator();

passwordSchema
.is().min(8)                                    // nbr caractères min 8
.is().max(50)                                  // nbr caractères max 50
.has().uppercase()                              // lettres majuscule requises
.has().lowercase()                              // lettres minuscule requises
.has().digits()                                // au moins un chiffre est demandé
.has().not().symbols();                         // pas de symboles

// inscription du user
exports.signup = (req, res, next) => { 
  bcrypt.hash(req.body.password, 10)
    .then(hash => {
      const user = new User({ // créer un nouvel utilisateur
        email: req.body.email, // l'adresse mail
        password: hash // le mot de passe haché
      });
      user.save() // mongoose le stocke dans la bdd
        .then(() => res.status(201).json({ message: 'Utilisateur créé !' }))
        .catch(error => res.status(400).json({ error }));
    })
    .catch(error => res.status(500).json({ error }));
};

// connexion du user
exports.login = (req, res, next) => { 
  User.findOne({ email: req.body.email }) // on vérifie que l'adresse mail figure bien dan la bdd
    .then(user => {
      if (!user) {
        return res.status(401).json({ error: 'Utilisateur non trouvé !' });
      }
      bcrypt.compare(req.body.password, user.password) // comparaison les mots de passes
        .then(valid => {
          if (!valid) {
            return res.status(401).json({ error: 'Mot de passe incorrect !' });
          }
          res.status(200).json({
            userId: user._id,
            token: jwt.sign( // on génère un token de session pour le user connecté
              { userId: user._id },
              'RANDOM_TOKEN_SECRET',
              { expiresIn: '24h' }
            )
          });
        })
        .catch(error => res.status(500).json({ error }));
    })
    .catch(error => res.status(500).json({ error }));
};