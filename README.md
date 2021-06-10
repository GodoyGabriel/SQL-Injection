[![Build Status](https://secure.travis-ci.org/ghafran/sql-injection.png)](http://travis-ci.org/ghafran/sql-injection)
[![NSP Status](https://nodesecurity.io/orgs/ghafran/projects/c6cb2b07-e84b-4985-84ca-ea057c88cadb/badge)](https://nodesecurity.io/orgs/ghafran/projects/c6cb2b07-e84b-4985-84ca-ea057c88cadb)

sql-injection
=============

This express module detects sql injection attacks and stops them by sending 403 as response.
The module checks the query string, route params, and body for any sql injection related content.

```js
var app = express();
var sqlinjection = require('./src/sql-injection');
app.use(sqlinjection);
```

## Usage