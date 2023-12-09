const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const connection = require('./db.js');
const response = require('./response.js');
const swaggerJsDoc = require('swagger-jsdoc');
const swaggerUI = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');
const multer = require('multer');
const path = require('path');
const passport = require('passport');
const jwt = require('jsonwebtoken')
const upload = multer({ dest: 'uploads/' });
const axios = require('axios');
app.use(passport.initialize());
require('./passport')(passport);

const swaggerOptions = {
    swaggerDefinition: {
        info: {
            title: 'web lab 6 API',
            description: 'O_o',
            contact: {
                name: "developer"
            },
            servers: ["http://localhost:8000"]
        }
    },
    // ['.routes/*.js']
    apis: ["server.js"]
};

const setTokenHeader = (req, res, next) => {
    if (req.cookies.Authorization) {
        const token = req.cookies.Authorization;
        res.setHeader('Authorization', `Bearer ${token}`);
    } else {
        response.status(401, `Cannot get token!`, res);
    }
    next();
}

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerDocs));
app.use('/photos', express.static(path.join(__dirname, 'photos')));

app.use(cookieParser());
app.use(express.json());


// routes
/**
 * @swagger
 * /hello:
 *  get:
 *     description: hello
 *     responses:
 *      '200':
 *          description: success
 */
app.get('/hello', setTokenHeader, passport.authenticate('jwt', {session: false}), function (req, res) {
    console.log(req.user);
    res.status(200).send(`hello, ${req.user.username}!`);
});


/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get all users
 *     description: Retrieve a list of all users from the database.
 *     tags:
 *       - Users
 *     responses:
 *       '200':
 *         description: Successful retrieval of users
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   userId:
 *                     type: integer
 *                     description: The unique identifier of the user.
 *                   username:
 *                     type: string
 *                     description: The username of the user.
 *       '500':
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message indicating a server error.
 */
// ПЕРЕГЛЯНУТИ УСІХ ЮЗЕРІВ
app.get('/users', setTokenHeader, passport.authenticate('jwt', {session: false}), function (req, res) {
    connection.query('SELECT * FROM users', function (err, results, fields) {
      if (err) {
        console.error('query error: ', err);
        res.status(500).json({ message: 'query error' });
      } else {
        response.status(200, results, res);
      }
    });
});

/**
* @swagger
* /register:
*   post:
*     summary: Create a new user
*     description: Create a new user with the specified username.
*     tags:
*       - Users
*     parameters:
*       - in: query
*         name: username
*         schema:
*           type: string
*         required: true
*         description: The username of the new user.
*     requestBody:
*       content:
*         application/json:
*           schema:
*             type: object
*             properties:
*               username:
*                 type: string
*                 description: The username of the new user.
*             required:
*               - username
*           example:
*             username: john_doe
*     responses:
*       '201':
*         description: User created successfully
*         content:
*           application/json:
*             schema:
*               type: object
*               properties:
*                 message:
*                   type: string
*                   description: A success message.
*                 userId:
*                   type: integer
*                   description: The ID of the newly created user.
*       '400':
*         description: Bad request
*         content:
*           application/json:
*             schema:
*               type: object
*               properties:
*                 message:
*                   type: string
*                   description: An error message.
*       '500':
*         description: Internal server error
*         content:
*           application/json:
*             schema:
*               type: object
*               properties:
*                 message:
*                   type: string
*                   description: An error message indicating a server error.
*/
// ЗАРЕЄСТРУВАТИСЬ
app.post('/register', function (req, res) {
    const username = req.query.username;

    connection.query('SELECT * FROM users WHERE username = ?', [username], function (error, results, fields) {
        if (error) {
            console.error('query error:', error);
            res.status(500).json({ message: 'server error' });
            return;
        }
        if (results.length === 0) {
            connection.query('INSERT INTO users (username) VALUES (?)', [username], function (insertError, insertResults, insertFields) {
                if (insertError) {
                    console.error('query error:', insertError);
                    res.status(500).json({ message: 'server error' });
                    return;
                }
                res.status(201).json({ message: `user '${username}' has been added`, userId: insertResults.insertId });
            });
        } else {
            res.status(400).json({ message: 'user with the same username already exists!' });
        }
    });
});

/**
 * @swagger
 * /login:
 *   get:
 *     summary: Authenticate user and generate JWT
 *     description: |
 *       Authenticate a user using local strategy (username and password) and generate a JWT (JSON Web Token).
 *     tags:
 *       - Users
 *     parameters:
 *       - in: query
 *         name: username
 *         schema:
 *           type: string
 *         required: true
 *         description: The username of the user.
 *     responses:
 *       '200':
 *         description: Authentication successful, JWT generated
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   description: The generated JSON Web Token.
 *       '401':
 *         description: Authentication failed
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message indicating authentication failure.
 *       '500':
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message indicating a server error.
 */
// УВІЙТИ
app.get('/login', (req, res, next) => {
    const username = req.query.username;

    connection.query('SELECT id FROM users WHERE username = ?', [username], (error, results) => {
    if (error) {
      console.error('Query error:', error);
      return res.status(500).json({ message: 'Internal server error' });
    }

    if (results.length === 0) {
      return res.status(401).json({ message: 'Authentication failed. User not found.' });
    }

    const userId = results[0].id;

    const initialtoken = jwt.sign({ sub: userId }, 'jwt-key', { expiresIn: 120 * 120 });
    console.log(initialtoken);
    res.cookie('Authorization', `${initialtoken}`);
    return res.json({ initialtoken });
  });
});

/**
 * @swagger
 * /take/{deviceID}:
 *   get:
 *     summary: Update device ownership
 *     description: Update the ownership of a device based on the provided device ID.
 *     tags:
 *       - Users
 *     parameters:
 *       - in: path
 *         name: deviceID
 *         required: true
 *         description: The ID of the device.
 *         schema:
 *           type: integer
 *     responses:
 *       '200':
 *         description: Device ownership updated successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Device ownership updated successfully
 *       '401':
 *         description: Unauthorized - Token missing or invalid.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Authentication failed. Token missing or invalid.
 *       '500':
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Internal server error
 */
// ВЗЯТИ ПРИСТРІЙ НА ВИКОРИСТАННЯ
app.get('/take/:deviceID', setTokenHeader, passport.authenticate('jwt', { session: false }), function (req, res) {
    const userID = req.user.id;
    const deviceID = req.params.deviceID;

    const checkDeviceQuery = `
        SELECT *
        FROM devices
        WHERE id = ?;
    `;

    connection.query(checkDeviceQuery, [deviceID], (checkError, checkResults) => {
        if (checkError) {
            console.error('query error:', checkError);
            return res.status(500).json({ message: 'internal server error' });
        }
        
        if (!checkResults[0])
        {
            return res.status(404).json({ message: 'the device with this ID hasn`t been found' });
        }

        if (!checkResults[0].device_name || checkResults[0].owner) {
            return res.status(403).json({ message: 'the device is already in use or not found' });
        }

        const updateOwnershipQuery = `
            UPDATE devices
            SET owner_id = ?,
                status = 'in using',
                owner = ?
            WHERE id = ?;
        `;

        const updateValues = [userID, req.user.username, deviceID];

        connection.query(updateOwnershipQuery, updateValues, (updateError, updateResults, updateFields) => {
            if (updateError) {
                console.error('query error:', updateError);
                return res.status(500).json({ message: 'internal server error' });
            }

            if (updateResults.affectedRows === 0) {
                return res.status(403).json({ message: 'the device is already in use or not found' });
            }

            return res.status(200).json({ message: 'you successfully became a new owner of this device!' });
        });
    });
});

/**
 * @swagger
 * /mydevices:
 *   get:
 *     summary: Get devices owned by the authenticated user
 *     description: Retrieve a list of devices owned by the authenticated user.
 *     tags:
 *       - Users
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       '200':
 *         description: Successful retrieval of user's devices
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                     description: The unique identifier of the device.
 *                   device_name:
 *                     type: string
 *                     description: The name of the device.
 *                   description:
 *                     type: string
 *                     description: A description of the device.
 *                   serial_number:
 *                     type: string
 *                     description: The serial number of the device.
 *                   manufacturer:
 *                     type: string
 *                     description: The manufacturer of the device.
 *                 required:
 *                   - id
 *                   - device_name
 *                   - description
 *                   - serial_number
 *                   - manufacturer
 *       '401':
 *         description: Unauthorized - Token missing or invalid.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Authentication failed. Token missing or invalid.
 *       '500':
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Internal server error.
 */
// ПЕРЕГЛЯНУТИ ДЕВАЙСИ У ВИКОРИСТАННІ
app.get('/mydevices', setTokenHeader, passport.authenticate('jwt', { session: false }), function (req, res) {
    const userID = req.user.id;

    const sqlQuery = `
        SELECT * FROM devices
        WHERE owner_id = ?;
    `;

    connection.query(sqlQuery, [userID], (error, results, fields) => {
        if (error) {
            console.error('query error:', error);
            return res.status(500).json({ message: 'internal server error' });
        }

        return res.status(200).json(results);
    });
});

/**
 * @swagger
 * /takeoff/{deviceID}:
 *   get:
 *     summary: Release a device
 *     description: Release a device from user ownership.
 *     tags:
 *      - Users
 *     parameters:
 *       - in: path
 *         name: deviceID
 *         required: true
 *         description: The ID of the device to be released.
 *         schema:
 *           type: integer
 *     responses:
 *       '200':
 *         description: Device released successfully.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Device released successfully.
 *       '401':
 *         description: Unauthorized - Token missing or invalid.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Authentication failed. Token missing or invalid.
 *       '404':
 *         description: Device not found or not owned by the user.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Device not found or not owned by the user.
 *       '500':
 *         description: Internal server error.
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Internal server error.
 */
// ЗНЯТИ ДЕВАЙС З ВИКОРИСТАННЯ
app.get('/takeoff/:deviceID', setTokenHeader, passport.authenticate('jwt', { session: false }), function (req, res) {
    const userID = req.user.id;
    const deviceID = req.params.deviceID;

    const sqlQuery = `
     UPDATE devices
     SET status = 'free', owner = NULL, owner_id = NULL
     WHERE owner_id = ? AND id = ?;
     `;

    const values = [userID, deviceID];

    connection.query(sqlQuery, values, (error, results, fields) => {
        if (error) {
            console.error('Query error:', error);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.affectedRows === 0) {
            return res.status(404).json({ message: 'Device not found or not owned by the user' });
        }

        return res.status(200).json({ message: 'Device released successfully' });
    });
});


/**
 * @swagger
 * /devices:
 *   get:
 *     summary: Get all devices
 *     description: Retrieve a list of all devices from the database.
 *     tags:
 *       - Devices
 *     responses:
 *       '200':
 *         description: Successful retrieval of devices
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   deviceId:
 *                     type: integer
 *                     description: The unique identifier of the device.
 *                   device_name:
 *                     type: string
 *                     description: The name of the device.
 *                   description:
 *                     type: string
 *                     description: A description of the device.
 *                   serial_number:
 *                     type: string
 *                     description: The serial number of the device.
 *                   manufacturer:
 *                     type: string
 *                     description: The manufacturer of the device.
 *                 required:
 *                   - deviceId
 *                   - device_name
 *                   - description
 *                   - serial_number
 *                   - manufacturer
 *       '500':
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message indicating a server error.
 */
// ПЕРЕГЛЯНУТИ УСІ ДЕВАЙСИ
app.get('/devices', function (req, res) {
    connection.query('SELECT * FROM devices', function (err, results, fields) {
        if (err) {
            console.error('query error: ', err);
            res.status(500).json({ message: 'query error' });
        } else {
            response.status(200, results, res);
        }
    });
})

/**
 * @swagger
 * /devices:
 *   post:
 *     summary: Add a new device
 *     description: Add a new device with the specified details.
 *     tags:
 *       - Devices
 *     parameters:
 *       - in: query
 *         name: device_name
 *         schema:
 *           type: string
 *         required: true
 *         description: The name of the device.
 *       - in: query
 *         name: description
 *         schema:
 *           type: string
 *         required: true
 *         description: A description of the device.
 *       - in: query
 *         name: serial_number
 *         schema:
 *           type: string
 *         required: true
 *         description: The serial number of the device.
 *       - in: query
 *         name: manufacturer
 *         schema:
 *           type: string
 *         required: true
 *         description: The manufacturer of the device.
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               device_name:
 *                 type: string
 *                 description: The name of the device.
 *               description:
 *                 type: string
 *                 description: A description of the device.
 *               serial_number:
 *                 type: string
 *                 description: The serial number of the device.
 *               manufacturer:
 *                 type: string
 *                 description: The manufacturer of the device.
 *             required:
 *               - device_name
 *               - description
 *               - serial_number
 *               - manufacturer
 *           example:
 *             device_name: ExampleDevice
 *             description: An example device description.
 *             serial_number: SN123456
 *             manufacturer: ExampleManufacturer
 *     responses:
 *       '201':
 *         description: Device added successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: A success message.
 *                 deviceId:
 *                   type: integer
 *                   description: The ID of the newly created device.
 *       '400':
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message.
 *       '500':
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message indicating a server error.
 */
// ДОДАТИ ДЕВАЙС
app.post('/devices', function (req, res) {
    const device_name = req.query.device_name;
    const description = req.query.description;
    const serial_number = req.query.serial_number;
    const manufacturer = req.query.manufacturer;

    if (!device_name || !description || !serial_number || !manufacturer) {
        res.status(400).json({ message: 'All fields (device_name, description, serial_number, manufacturer) are required in the request parameters' });
        return;
    }
    connection.query('SELECT * FROM devices WHERE serial_number = ?', [serial_number], function (selectError, selectResults) {
        if (selectError) {
            console.error('query error:', selectError);
            res.status(500).json({ message: 'Error checking for existing device in the database' });
        } else {
            if (selectResults.length > 0) {
                res.status(400).json({ message: 'Device with the same serial number already exists' });
            } else {
                connection.query('INSERT INTO devices (device_name, description, serial_number, manufacturer) VALUES (?, ?, ?, ?)',
                    [device_name, description, serial_number, manufacturer],
                    function (insertError, results) {
                        if (insertError) {
                            console.error('query error:', insertError);
                            res.status(500).json({ message: 'Error adding device to the database' });
                        } else {
                            res.status(201).json({ message: 'Device added successfully', deviceId: results.insertId });
                        }
                    }
                );
            }
        }
    });
});

/**
 * @swagger
 * /devices/{deviceID}:
 *   get:
 *     summary: Get device by ID
 *     description: Retrieve information about a device based on its ID.
 *     tags:
 *       - Devices
 *     parameters:
 *       - in: path
 *         name: deviceID
 *         schema:
 *           type: integer
 *         required: true
 *         description: The ID of the device to retrieve.
 *     responses:
 *       '200':
 *         description: Successful retrieval of device
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 deviceId:
 *                   type: integer
 *                   description: The unique identifier of the device.
 *                 device_name:
 *                   type: string
 *                   description: The name of the device.
 *                 description:
 *                   type: string
 *                   description: A description of the device.
 *                 serial_number:
 *                   type: string
 *                   description: The serial number of the device.
 *                 manufacturer:
 *                   type: string
 *                   description: The manufacturer of the device.
 *               required:
 *                 - deviceId
 *                 - device_name
 *                 - description
 *                 - serial_number
 *                 - manufacturer
 *       '404':
 *         description: Device not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message indicating that the device with the specified ID was not found.
 *       '500':
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message indicating a server error.
 */
// ПЕРЕГЛЯНУТИ ДЕВАЙС ПО ID
app.get('/devices/:deviceID', function (req, res) {
    const deviceID = req.params.deviceID;

    connection.query('SELECT * FROM devices WHERE id = ?', [deviceID], function (err, results, fields) {
        if (err) {
            console.error('query error: ', err);
            res.status(500).json({ message: 'query error' });
        } else {
            if (results.length > 0) {
                res.status(200).json(results[0]);
            } else {
                res.status(404).json({ message: 'Device not found' });
            }
        }
    });
});

/**
 * @swagger
 * /devices/{deviceID}:
 *   put:
 *     summary: Update device by ID
 *     description: Update information about a device based on its ID.
 *     tags:
 *       - Devices
 *     parameters:
 *       - in: path
 *         name: deviceID
 *         schema:
 *           type: integer
 *         required: true
 *         description: The ID of the device to update.
 *       - in: query
 *         name: device_name
 *         schema:
 *           type: string
 *         required: true
 *         description: The updated name of the device.
 *       - in: query
 *         name: description
 *         schema:
 *           type: string
 *         required: true
 *         description: The updated description of the device.
 *       - in: query
 *         name: serial_number
 *         schema:
 *           type: string
 *         required: true
 *         description: The updated serial number of the device.
 *       - in: query
 *         name: manufacturer
 *         schema:
 *           type: string
 *         required: true
 *         description: The updated manufacturer of the device.
 *     responses:
 *       '200':
 *         description: Device updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: A success message.
 *       '404':
 *         description: Device not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message indicating that the device with the specified ID was not found.
 *       '500':
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message indicating a server error.
 */
// РЕДАГУВАТИ ДЕВАЙС
app.put('/devices/:deviceID', function (req, res) {
    const deviceID = req.params.deviceID;
    const updatedDevice = {
        device_name: req.query.device_name,
        description: req.query.description,
        serial_number: req.query.serial_number,
        manufacturer: req.query.manufacturer,
    };

    if (!updatedDevice.device_name || !updatedDevice.description || !updatedDevice.serial_number || !updatedDevice.manufacturer) {
        res.status(400).json({ message: 'All fields (device_name, description, serial_number, manufacturer) are required in the request parameters' });
        return;
    }

    connection.query('SELECT * FROM devices WHERE serial_number = ? AND id <> ?', [updatedDevice.serial_number, deviceID], function (selectErr, selectResults, selectFields) {
        if (selectErr) {
            console.error('query error: ', selectErr);
            res.status(500).json({ message: 'Error checking device existence in the database' });
        } else {
            if (selectResults.length > 0) {
                res.status(409).json({ message: 'Device with the same serial number already exists' });
            } else {
                connection.query('UPDATE devices SET ? WHERE id = ?', [updatedDevice, deviceID], function (updateErr, updateResults, updateFields) {
                    if (updateErr) {
                        console.error('query error: ', updateErr);
                        res.status(500).json({ message: 'Error updating device in the database' });
                    } else {
                        if (updateResults.affectedRows > 0) {
                            res.status(200).json({ message: 'Device updated successfully' });
                        } else {
                            res.status(404).json({ message: 'Device not found' });
                        }
                    }
                });
            }
        }
    });
});

/**
 * @swagger
 * /devices/{deviceID}:
 *   delete:
 *     summary: Delete device by ID
 *     description: Delete a device based on its ID.
 *     tags:
 *       - Devices
 *     parameters:
 *       - in: path
 *         name: deviceID
 *         schema:
 *           type: integer
 *         required: true
 *         description: The ID of the device to delete.
 *     responses:
 *       '200':
 *         description: Device deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: A success message.
 *       '404':
 *         description: Device not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message indicating that the device with the specified ID was not found.
 *       '500':
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message indicating a server error.
 */
// ВИДАЛИТИ ДЕВАЙС
app.delete('/devices/:deviceID', function (req, res) {
    const deviceID = req.params.deviceID;
    connection.query('DELETE FROM devices WHERE id = ?', [deviceID], function (err, results, fields) {
        if (err) {
            console.error('query error: ', err);
            res.status(500).json({ message: 'Error deleting device from the database' });
        } else {
            if (results.affectedRows > 0) {
                res.status(200).json({ message: 'Device deleted successfully' });
            } else {
                res.status(404).json({ message: 'Device not found' });
            }
        }
    });
});

/**
 * @swagger
 * /devices/{deviceID}/photoadd:
 *   post:
 *     summary: Upload a photo for a device
 *     description: Upload a photo and associate it with a specific device.
 *     tags:
 *       - Devices
 *     parameters:
 *       - in: path
 *         name: deviceID
 *         schema:
 *           type: integer
 *         required: true
 *         description: The ID of the device to associate the photo with.
 *       - in: query
 *         name: photoName
 *         schema:
 *           type: string
 *         required: true
 *         description: The desired name for the uploaded photo.
 *     requestBody:
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               photo:
 *                 type: string
 *                 format: binary
 *     responses:
 *       '200':
 *         description: Photo uploaded successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: A success message.
 *       '500':
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message indicating a server error.
 */
// ДОДАТИ ФОТОГРАФІЮ
app.post('/devices/:deviceID/photoadd', upload.single('photo'), function (req, res) {
    const deviceID = req.params.deviceID;
    const photoName = req.query.photoName;

    connection.query('INSERT INTO photos (device_id, filename) VALUES (?, ?)', [deviceID, photoName], function (err, results, fields) {
        if (err) {
            console.error('query error: ', err);
            res.status(500).json({ message: 'Error saving photo to the database' });
        } else {
            res.status(200).json({ message: 'Photo uploaded and associated with the device successfully' });
        }
    });
});

/**
 * @swagger
 * /device/{deviceID}/photo:
 *   get:
 *     summary: Get device photo by ID
 *     description: Retrieve the photo of a device by its ID.
 *     tags:
 *       - Devices
 *     parameters:
 *       - in: path
 *         name: deviceID
 *         required: true
 *         description: The ID of the device.
 *         schema:
 *           type: integer
 *     responses:
 *       '200':
 *         description: Successful operation
 *         content:
 *           image/*:
 *             schema:
 *               type: string
 *               format: binary
 *       '404':
 *         description: Device not found or no photo available
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message.
 *       '500':
 *         description: Internal server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: An error message indicating a server error.
 */
// ПЕЕРЕГЛЯНУТИ ФОТОГРАФІЮ
app.get('/device/:deviceID/photo', (req, res) => {
    const deviceID = req.params.deviceID;

    // Отримати назву фото з бази даних за ID пристрою
    connection.query('SELECT filename FROM photos WHERE device_id = ?', [deviceID], (error, results) => {
        if (error) {
            console.error('Query error:', error);
            res.status(500).send('Internal server error');
        } else {
            // Перевірити, чи є результати запиту
            if (results.length === 0) {
                res.status(404).send('Photo not found for the specified device ID');
            } else {
                // Вивести HTML сторінку зі зображенням, використовуючи отриману назву фото
                res.send(`
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Device Photo</title>
                        <meta charset="utf-8">
                    </head>
                    <body>
                        <img src="/photos/${results[0].filename}.jpg" alt="Device Photo">
                    </body>
                    </html>
                `);
            }
        }
    });
});


app.listen(8000, () => {
    console.log('Сервер запущено на порту 8000');
});