var createError = require('http-errors');
var express = require('express');
var path = require('path');
var multer  = require('multer');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var csrf = require('csurf');
var passport = require('passport');
var logger = require('morgan');
var passport = require('passport');
var WebAuthnStrategy = require('passport-fido2-webauthn');
var SessionChallengeStore = require('passport-fido2-webauthn').SessionChallengeStore;
var base64url = require('base64url');
var uuid = require('uuid').v4;
var db = require('./db');
var store = new SessionChallengeStore();
const port = 3000;
var SQLiteStore = require('connect-sqlite3')(session);

// var authRouter = require('./routes/auth');
passport.use(new WebAuthnStrategy({ store: store }, function verify(id, userHandle, cb) {
  db.get('SELECT * FROM public_key_credentials WHERE external_id = ?', [ id ], function(err, row) {
    if (err) { return cb(err); }
    if (!row) { return cb(null, false, { message: 'Invalid key. '}); }
    var publicKey = row.public_key;
    db.get('SELECT * FROM users WHERE rowid = ?', [ row.user_id ], function(err, row) {
      if (err) { return cb(err); }
      if (!row) { return cb(null, false, { message: 'Invalid key. '}); }
      if (Buffer.compare(row.handle, userHandle) != 0) {
        return cb(null, false, { message: 'Invalid key. '});
      }
      return cb(null, row, publicKey);
    });
  });
}, function register(user, id, publicKey, cb) {
  db.run('INSERT INTO users (username, name, handle) VALUES (?, ?, ?)', [
    user.name,
    user.displayName,
    user.id
  ], function(err) {
    if (err) { return cb(err); }
    var newUser = {
      id: this.lastID,
      username: user.name,
      name: user.displayName
    };
    db.run('INSERT INTO public_key_credentials (user_id, external_id, public_key) VALUES (?, ?, ?)', [
      newUser.id,
      id,
      publicKey
    ], function(err) {
      if (err) { return cb(err); }
      return cb(null, newUser);
    });
  });
}));

passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username, name: user.name });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.locals.pluralize = require('pluralize');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(multer().none());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'keyboard cat',
  resave: false, // don't save session if unmodified
  saveUninitialized: false, // don't create session until something stored
  store: new SQLiteStore({ db: 'sessions.db', dir: './var/db' })
}));
//app.use(csrf());
app.use(passport.authenticate('session'));
app.use(function(req, res, next) {
  var msgs = req.session.messages || [];
  res.locals.messages = msgs;
  res.locals.hasMessages = !! msgs.length;
  req.session.messages = [];
  next();
});
app.use(function(req, res, next) {
  //res.locals.csrfToken = req.csrfToken();
  res.locals.csrfToken = 'TODO';
  next();
});



var ensureLogIn = require('connect-ensure-login').ensureLoggedIn;
var ensureLoggedIn = ensureLogIn();

function fetchTodos(req, res, next) {
  db.all('SELECT * FROM todos WHERE owner_id = ?', [
    req.user.id
  ], function(err, rows) {
    if (err) { return next(err); }
    
    var todos = rows.map(function(row) {
      return {
        id: row.id,
        title: row.title,
        completed: row.completed == 1 ? true : false,
        url: '/' + row.id
      }
    });
    res.locals.todos = todos;
    res.locals.activeCount = todos.filter(function(todo) { return !todo.completed; }).length;
    res.locals.completedCount = todos.length - res.locals.activeCount;
    next();
  });
}

app.get('/', function(req, res, next) {
  if (!req.user) { return res.render('home'); }
  next();
}, fetchTodos, function(req, res, next) {
  res.locals.filter = null;
  res.render('index', { user: req.user });
});

app.get('/active', ensureLoggedIn, fetchTodos, function(req, res, next) {
  res.locals.todos = res.locals.todos.filter(function(todo) { return !todo.completed; });
  res.locals.filter = 'active';
  res.render('index', { user: req.user });
});

app.get('/completed', ensureLoggedIn, fetchTodos, function(req, res, next) {
  res.locals.todos = res.locals.todos.filter(function(todo) { return todo.completed; });
  res.locals.filter = 'completed';
  res.render('index', { user: req.user });
});

app.post('/', ensureLoggedIn, function(req, res, next) {
  req.body.title = req.body.title.trim();
  next();
}, function(req, res, next) {
  if (req.body.title !== '') { return next(); }
  return res.redirect('/' + (req.body.filter || ''));
}, function(req, res, next) {
  db.run('INSERT INTO todos (owner_id, title, completed) VALUES (?, ?, ?)', [
    req.user.id,
    req.body.title,
    req.body.completed == true ? 1 : null
  ], function(err) {
    if (err) { return next(err); }
    return res.redirect('/' + (req.body.filter || ''));
  });
});

app.post('/:id(\\d+)', ensureLoggedIn, function(req, res, next) {
  req.body.title = req.body.title.trim();
  next();
}, function(req, res, next) {
  if (req.body.title !== '') { return next(); }
  db.run('DELETE FROM todos WHERE id = ? AND owner_id = ?', [
    req.params.id,
    req.user.id
  ], function(err) {
    if (err) { return next(err); }
    return res.redirect('/' + (req.body.filter || ''));
  });
}, function(req, res, next) {
  db.run('UPDATE todos SET title = ?, completed = ? WHERE id = ? AND owner_id = ?', [
    req.body.title,
    req.body.completed !== undefined ? 1 : null,
    req.params.id,
    req.user.id
  ], function(err) {
    if (err) { return next(err); }
    return res.redirect('/' + (req.body.filter || ''));
  });
});

app.post('/:id(\\d+)/delete', ensureLoggedIn, function(req, res, next) {
  db.run('DELETE FROM todos WHERE id = ? AND owner_id = ?', [
    req.params.id,
    req.user.id
  ], function(err) {
    if (err) { return next(err); }
    return res.redirect('/' + (req.body.filter || ''));
  });
});

app.post('/toggle-all', ensureLoggedIn, function(req, res, next) {
  db.run('UPDATE todos SET completed = ? WHERE owner_id = ?', [
    req.body.completed !== undefined ? 1 : null,
    req.user.id
  ], function(err) {
    if (err) { return next(err); }
    return res.redirect('/' + (req.body.filter || ''));
  });
});

app.post('/clear-completed', ensureLoggedIn, function(req, res, next) {
  db.run('DELETE FROM todos WHERE owner_id = ? AND completed = ?', [
    req.user.id,
    1
  ], function(err) {
    if (err) { return next(err); }
    return res.redirect('/' + (req.body.filter || ''));
  });
});

app.get('/login', function(req, res, next) {
  res.render('login');
});

app.post('/login/public-key', passport.authenticate('webauthn', {
  failureMessage: true,
  failWithError: true
}), function(req, res, next) {
  res.json({ ok: true, location: '/' });
}, function(err, req, res, next) {
  var cxx = Math.floor(err.status / 100);
  if (cxx != 4) { return next(err); }
  res.json({ ok: false, location: '/login' });
});

app.post('/login/public-key/challenge', function(req, res, next) {
  store.challenge(req, function(err, challenge) {
    if (err) { return next(err); }
    res.json({ challenge: base64url.encode(challenge) });
  });
});

app.post('/logout', function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

app.get('/signup', function(req, res, next) {
  res.render('signup');
});

app.post('/signup/public-key/challenge', function(req, res, next) {
  var handle = Buffer.alloc(16);
  handle = uuid({}, handle);
  var user = {
    id: handle,
    name: req.body.username,
    displayName: req.body.name
  };
  store.challenge(req, { user: user }, function(err, challenge) {
    if (err) { return next(err); }
    user.id = base64url.encode(user.id);
    res.json({ user: user, challenge: base64url.encode(challenge) });
  });
});



// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

app.listen(port, (err)=>{
  if(err) throw err;
  console.log(`Connection Established!! http://localhost:${port}`);
})