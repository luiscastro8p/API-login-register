//import package
var mongodb = require('mongodb');
var ObjectID = mongodb.ObjectID;
var crypto = require('crypto');
var express = require('express');
var bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');



//password ultils
//create function to random salt

var genRandomString = function(length) {
    return crypto.randomBytes(Math.ceil(length / 2))
        .toString('hex') //convert to hexa format
        .slice(0, length);
};

var sha512 = function(password, salt) {
    var hash = crypto.createHmac('sha512', salt);
    hash.update(password);
    var value = hash.digest('hex');
    return {
        salt: salt,
        passwordHash: value
    };
};

function saltHashPassword(userPassword) {
    var salt = genRandomString(16);
    var passwordData = sha512(userPassword, salt);
    return passwordData;
}

function checkHashPassword(userPassword, salt) {
    var passwordData = sha512(userPassword, salt);
    return passwordData;
}


//create Express service
var app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));








//create MongoDB client
var MongoClient = mongodb.MongoClient;

//connection URL
var url = 'mongodb://localhost:27017'

MongoClient.connect(url, { useNewUrlParser: true }, function(err, client) {
    if (err)
        console.log('Unable to connect to the mongo server error', err);
    else {


        app.get('/api', (req, res) => {
            res.json({
                message: 'Welcome to the API'
            });
        });

        app.post('/api/posts', verifyToken, (req, res) => {
            jwt.verify(req.token, 'secretkey', (err, authData) => {
                if (err) {
                    res.sendStatus(403);
                } else {
                    res.json({
                        message: 'Post created...',
                        authData
                    });
                }
            });
        });

        app.post('/api/login', (req, res) => {
            // Mock user
            const user = {
                id: 1,
                username: 'brad',
                email: 'brad@gmail.com'
            }

            jwt.sign({ user }, 'secretkey', { expiresIn: '30s' }, (err, token) => {
                res.json({
                    token
                });
            });
        });

        // FORMAT OF TOKEN
        // Authorization: Bearer <access_token>

        // Verify Token
        function verifyToken(req, res, next) {
            // Get auth header value
            const bearerHeader = req.headers['authorization'];
            // Check if bearer is undefined
            if (typeof bearerHeader !== 'undefined') {
                // Split at the space
                const bearer = bearerHeader.split(' ');
                // Get token from array
                const bearerToken = bearer[1];
                // Set the token
                req.token = bearerToken;
                // Next middleware
                next();
            } else {
                // Forbidden
                res.sendStatus(403);
            }

        }



        //registrer
        app.post('/register', (request, response, next) => {
            var post_data = request.body;

            var plaint_password = post_data.password;
            var Hash_data = saltHashPassword(plaint_password);

            var password = Hash_data.passwordHash; //save password hash
            var salt = Hash_data.salt; // save salt 

            var name = post_data.name;
            var email = post_data.email;

            var insertJson = {
                'email': email,
                'password': password,
                'salt': salt,
                'name': name
            };
            var db = client.db('nombresenclave');


            //check exists email 
            db.collection('user')
                .find({ 'email': email }).count(function(err, number) {
                    if (number != 0) {
                        response.json('email already exists');
                        console.log('Email already exists');
                    } else {
                        //insert data
                        db.collection('user')
                            .insertOne(insertJson, function(error, res) {
                                response.json('Registration success');
                                console.log('Registration success');
                            })
                    }


                })

        });




        app.post('/login', (request, response, next) => {
            var post_data = request.body;
            var userPassword = post_data.password;
            var email = post_data.email;
            var db = client.db('nombresenclave');

            //check exists email 
            db.collection('user')
                .find({ 'email': email }).count(function(err, number) {


                    if (number == 0) {
                        response.json('Email NOT exists');
                        console.log('Email NOT exists');


                    } else {
                        //insert data
                        db.collection('user')
                            .findOne({ 'email': email }, function(err, user) {

                                jwt.sign({ user }, 'secretkey', (err, token) => {
                                    res.json({
                                        token
                                    });

                                });

                                var salt = user.salt;
                                var Hashed_password = checkHashPassword(userPassword, salt).passwordHash; //hash pasword with salt
                                var encrypted_password = user.password; //get password from user
                                if (Hashed_password == encrypted_password) {
                                    response.json('login success');
                                    console.log('login success');
                                    //token

                                } else {
                                    response.json('Wrong password');
                                    console.log('Wrong password');
                                }


                            })
                    }

                })
        });

        //start web server
        app.listen(3000, () => {
            console.log('Conected to Mongo server, WebService running on port 3000');
        })
    }

});