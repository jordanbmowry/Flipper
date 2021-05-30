// required npm packages
const express = require('express');
const path = require('path');
const redis = require('redis');
const bcrypt = require('bcrypt');
const session = require('express-session');
const RedisStore = require('connect-redis')(session);

const app = express();
const client = redis.createClient();

app.use(express.urlencoded({ extended: true }));
app.use(
	session({
		store: new RedisStore({ client: client }),
		resave: true,
		saveUninitialized: true,
		cookie: {
			maxAge: 36000000, //10 hours, in milliseconds
			httpOnly: false,
			secure: false,
		},
		secret: 'keyboard dog',
	})
);
app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));

app.get('/', (req, res) => res.render('index'));

// handling POST requests
app.post('/', (req, res) => {
	const { username, password } = req.body;

	const saveSessionAndRenderDashboard = (userid) => {
		req.session.userid = userid;
		req.session.save();
		res.render('dashboard');
	};

	if (!username || !password) {
		res.render('error', {
			message: 'Please set both username and password',
		});
		return;
	}

	console.log(req.body, username, password);

	client.hget('users', username, (err, userid) => {
		if (!userid) {
			//user does not exist, signup procedure
			client.incr('userid', async (err, userid) => {
				client.hset('users', username, userid);

				const saltRounds = 10;
				const hash = await bcrypt.hash(password, saltRounds);

				client.hset(`user:${userid}`, 'hash', hash, 'username', username);

				saveSessionAndRenderDashboard(userid);
			});
		} else {
			//user exists, login procedure
			client.hget(`user:${userid}`, 'hash', async (err, hash) => {
				const result = await bcrypt.compare(password, hash);
				if (result) {
					//password OK
					saveSessionAndRenderDashboard(userid);
				} else {
					//incorrect password
					res.render('error', {
						message: 'Incorrect password',
					});
					return;
				}
			});
		}
	});
});

app.listen(3000, () => {
	console.log('Server ready');
});
