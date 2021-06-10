function hasSql(value) {
  if (value === null || value === undefined) {
    return false;
  }
  // sql regex reference: http://www.symantec.com/connect/articles/detection-sql-injection-and-cross-site-scripting-attacks
  let sql_meta = new RegExp("(%27)|(')|(--)|(%23)|(#)", "i");
  if (sql_meta.test(value)) {
    return true;
  }
  let sql_meta2 = new RegExp(
    "((%3D)|(=))[^\n]*((%27)|(')|(--)|(%3B)|(;))",
    "i"
  );
  if (sql_meta2.test(value)) {
    return true;
  }
  let sql_typical = new RegExp(
    "w*((%27)|('))((%6F)|o|(%4F))((%72)|r|(%52))",
    "i"
  );
  if (sql_typical.test(value)) {
    return true;
  }
  let sql_union = new RegExp("((%27)|('))union", "i");
  if (sql_union.test(value)) {
    return true;
  }
  return false;
}

function middleware(req, res, next) {
  let containsSql = false;
  if (req.originalUrl !== null && req.originalUrl !== undefined) {
    if (hasSql(req.originalUrl) === true) {
      containsSql = true;
    }
  }
  if (!containsSql) {
    if (req.params.length > 0 || req.query.length > 0) {
      const values = Object.assign(req.params, req.query);
      if (typeof values !== "string") {
        body = JSON.stringify(values);
      }
      if (hasSql(body)) {
        containsSql = true;
      }
      if (containsSql) {
        console.warn("SQL Detected in Request, Rejected.");
        res.status(403).json({
          error: "SQL Detected in Request, Rejected.",
        });
      } else {
        return next();
      }
    } else {
      return next();
    }
  } else {
    console.warn("SQL Detected in Request, Rejected.");
    res.status(403).json({
      error: "SQL Detected in Request, Rejected.",
    });
  }
}

module.exports = middleware;
